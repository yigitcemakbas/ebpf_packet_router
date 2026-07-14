package pfcp

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gtp-router/control/maps"
)

// Config carries everything PFCP itself does not tell the router. PFCP conveys
// TEIDs, UE IPs, and the gNB's N3 tunnel endpoint, but never L2 addressing or
// which host interface to egress on, so those (and the static-NAT pool the lab
// topology needs to make UE traffic routable) are supplied out-of-band here,
// exactly as tools/lab_provision.sh passes them to `add-teid`/`add-nat`.
type Config struct {
	Listen  string // UDP address to bind PFCP/N4 on, e.g. "10.201.0.1:8805"
	NodeIP  net.IP // our Node ID / F-SEID IPv4 (control-plane identity)
	N3IP    net.IP // UP IPv4 advertised in the uplink F-TEID (gNB sends here)

	// Uplink egress (toward N6/internet): where decapsulated UE packets go.
	ULIface string
	ULDMac  [6]byte
	ULSMac  [6]byte

	// Downlink egress (toward the gNB): where re-encapsulated packets go.
	DLIface string
	DLDMac  [6]byte
	DLSMac  [6]byte

	// Static-NAT egress pool. Each session's UE is NATed to NATBase + n. These
	// addresses must already be reachable/ARP-answerable on the uplink egress
	// (tools/lab.sh adds them as /32 secondaries on veth-inet0).
	NATBase net.IP
}

// session is the per-PFCP-session state we keep to correlate the uplink PDR
// (which allocates our F-TEID) with the downlink FAR (whose outer header, i.e.
// the gNB TEID, often only arrives in a later Session Modification), and to
// tear both map rules down on Session Deletion.
type session struct {
	localSEID  uint64
	remoteSEID uint64
	remoteAddr *net.UDPAddr

	ueIP        net.IP
	natIP       net.IP
	uplinkTEID  uint32 // allocated by us; matched in teid_map
	teidInstalled bool
	natInstalled  bool
}

// Server is a minimal UPF-side PFCP endpoint.
type Server struct {
	cfg  Config
	conn *net.UDPConn

	mu         sync.Mutex
	sessions   map[uint64]*session // keyed by our local SEID
	nextSEID   uint64
	nextTEID   uint32
	natCounter int
	recovery   uint32 // our recovery timestamp (NTP seconds), fixed at startup
	ulIfindex  uint32
	dlIfindex  uint32
}

// ntpEpochOffset converts Unix seconds to NTP (1900) epoch seconds.
const ntpEpochOffset = 2208988800

// Serve binds the PFCP socket and processes messages until the process exits.
func Serve(cfg Config) error {
	ulIf, err := net.InterfaceByName(cfg.ULIface)
	if err != nil {
		return fmt.Errorf("uplink egress %q: %w", cfg.ULIface, err)
	}
	dlIf, err := net.InterfaceByName(cfg.DLIface)
	if err != nil {
		return fmt.Errorf("downlink egress %q: %w", cfg.DLIface, err)
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", cfg.Listen, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("bind %q: %w", cfg.Listen, err)
	}
	defer conn.Close()

	s := &Server{
		cfg:       cfg,
		conn:      conn,
		sessions:  make(map[uint64]*session),
		nextSEID:  1,
		nextTEID:  0x00010000,
		recovery:  uint32(time.Now().Unix() + ntpEpochOffset),
		ulIfindex: uint32(ulIf.Index),
		dlIfindex: uint32(dlIf.Index),
	}

	// Pre-provision both egress ifindexes in the devmap so the very first
	// redirect after a session install cannot be dropped for a missing entry.
	if err := maps.EnsureTxPort(s.ulIfindex); err != nil {
		return fmt.Errorf("tx_port uplink: %w", err)
	}
	if err := maps.EnsureTxPort(s.dlIfindex); err != nil {
		return fmt.Errorf("tx_port downlink: %w", err)
	}

	log.Printf("pfcp: listening on %s (node-id %s, N3 %s), UL egress %s, DL egress %s",
		cfg.Listen, cfg.NodeIP, cfg.N3IP, cfg.ULIface, cfg.DLIface)

	buf := make([]byte, 65535)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("pfcp: read error: %v", err)
			continue
		}
		msg, err := parseMessage(buf[:n])
		if err != nil {
			log.Printf("pfcp: parse error from %s: %v", src, err)
			continue
		}
		s.dispatch(msg, src)
	}
}

func (s *Server) dispatch(msg *message, src *net.UDPAddr) {
	switch msg.Type {
	case msgHeartbeatRequest:
		s.handleHeartbeat(msg, src)
	case msgAssociationSetupRequest:
		s.handleAssociationSetup(msg, src)
	case msgAssociationReleaseRequest:
		s.reply(src, buildMessage(msgAssociationReleaseResponse, false, 0, msg.Seq,
			encodeNodeIDv4(s.cfg.NodeIP), encodeCause(causeRequestAccepted)))
	case msgSessionEstablishmentRequest:
		s.handleSessionEstablishment(msg, src)
	case msgSessionModificationRequest:
		s.handleSessionModification(msg, src)
	case msgSessionDeletionRequest:
		s.handleSessionDeletion(msg, src)
	default:
		log.Printf("pfcp: ignoring unhandled message type %d from %s", msg.Type, src)
	}
}

func (s *Server) reply(dst *net.UDPAddr, b []byte) {
	if _, err := s.conn.WriteToUDP(b, dst); err != nil {
		log.Printf("pfcp: write to %s failed: %v", dst, err)
	}
}

func (s *Server) handleHeartbeat(msg *message, src *net.UDPAddr) {
	s.reply(src, buildMessage(msgHeartbeatResponse, false, 0, msg.Seq,
		encodeRecoveryTimeStamp(s.recovery)))
}

func (s *Server) handleAssociationSetup(msg *message, src *net.UDPAddr) {
	log.Printf("pfcp: association setup from %s", src)
	s.reply(src, buildMessage(msgAssociationSetupResponse, false, 0, msg.Seq,
		encodeNodeIDv4(s.cfg.NodeIP),
		encodeCause(causeRequestAccepted),
		encodeRecoveryTimeStamp(s.recovery),
		encodeUPFunctionFeatures(),
	))
}

// allocation helpers (caller holds s.mu).
func (s *Server) allocSEID() uint64 { v := s.nextSEID; s.nextSEID++; return v }
func (s *Server) allocTEID() uint32 { v := s.nextTEID; s.nextTEID++; return v }
func (s *Server) allocNATIP() net.IP {
	ip := s.cfg.NATBase.To4()
	out := net.IP{ip[0], ip[1], ip[2], byte(int(ip[3]) + s.natCounter)}
	s.natCounter++
	return out
}

// handleSessionEstablishment parses the Create PDR(s)/FAR(s), allocates our
// uplink F-TEID + a NAT egress IP, installs the uplink decap rule now, installs
// the downlink encap rule too if the FAR already carries the gNB tunnel, and
// answers with our F-SEID and the Created PDR (the allocated F-TEID).
func (s *Server) handleSessionEstablishment(msg *message, src *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess := &session{remoteAddr: src}

	// SMF's F-SEID (its session id + control IP): we address later replies to
	// its SEID.
	if fseid := findIE(msg.IEs, ieFSEID); fseid != nil && len(fseid.Value) >= 9 {
		sess.remoteSEID = beUint64(fseid.Value[1:9])
	}

	// Walk Create PDRs to find the uplink one (Source Interface = access) whose
	// F-TEID we must allocate, and to pick up the UE IP.
	var chosenPDRID uint16
	haveUplink := false
	for _, pdr := range findAllIE(msg.IEs, ieCreatePDR) {
		pdi := findIE(pdr.Children, iePDI)
		if pdi == nil {
			continue
		}
		srcIf := ifaceOf(pdi)
		if ue := findIE(pdi.Children, ieUEIPAddress); ue != nil {
			if ip := parseUEIPAddress(ue.Value); ip != nil {
				sess.ueIP = ip
			}
		}
		if srcIf == ifaceAccess {
			// Uplink detection rule. Its F-TEID is normally CHOOSE (UPF
			// allocates); allocate regardless and echo it back in Created PDR.
			if id := findIE(pdr.Children, iePDRID); id != nil && len(id.Value) >= 2 {
				chosenPDRID = beUint16(id.Value)
			}
			sess.uplinkTEID = s.allocTEID()
			haveUplink = true
		}
	}

	if !haveUplink {
		log.Printf("pfcp: establishment from %s had no uplink (access) PDR; rejecting", src)
		s.reply(src, buildMessage(msgSessionEstablishmentResponse, true, sess.remoteSEID, msg.Seq,
			encodeNodeIDv4(s.cfg.NodeIP), encodeCause(causeRequestRejected)))
		return
	}

	sess.natIP = s.allocNATIP()
	sess.localSEID = s.allocSEID()

	// Install the uplink decap+NAT rule now (teid_map[uplinkTEID]).
	if err := s.installUplink(sess); err != nil {
		log.Printf("pfcp: uplink install failed for SEID %d: %v", sess.localSEID, err)
		s.reply(src, buildMessage(msgSessionEstablishmentResponse, true, sess.remoteSEID, msg.Seq,
			encodeNodeIDv4(s.cfg.NodeIP), encodeCause(causeRequestRejected)))
		return
	}

	// If a Create FAR already carries the downlink tunnel (gNB TEID+IP), install
	// the downlink encap rule too. Often it does not yet, and arrives later in a
	// Session Modification once the gNB has signalled its TEID.
	if ohc, ok := downlinkOHC(msg.IEs); ok && sess.ueIP != nil {
		if err := s.installDownlink(sess, ohc); err != nil {
			log.Printf("pfcp: downlink install (establishment) failed for SEID %d: %v", sess.localSEID, err)
		}
	}

	s.sessions[sess.localSEID] = sess
	log.Printf("pfcp: session established SEID=%d UE=%v NAT=%v ulTEID=0x%08X",
		sess.localSEID, sess.ueIP, sess.natIP, sess.uplinkTEID)

	// Respond: our F-SEID + a Created PDR echoing the allocated uplink F-TEID.
	createdPDR := encodeGrouped(ieCreatedPDR,
		encodePDRID(chosenPDRID),
		encodeFTEIDv4(sess.uplinkTEID, s.cfg.N3IP),
	)
	s.reply(src, buildMessage(msgSessionEstablishmentResponse, true, sess.remoteSEID, msg.Seq,
		encodeNodeIDv4(s.cfg.NodeIP),
		encodeCause(causeRequestAccepted),
		encodeFSEIDv4(sess.localSEID, s.cfg.NodeIP),
		createdPDR,
	))
}

// handleSessionModification applies an Update FAR carrying the downlink tunnel
// (the common case: the gNB TEID becomes known after establishment).
func (s *Server) handleSessionModification(msg *message, src *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess := s.sessions[msg.SEID]
	if sess == nil {
		log.Printf("pfcp: modification for unknown SEID %d", msg.SEID)
		s.reply(src, buildMessage(msgSessionModificationResponse, true, 0, msg.Seq,
			encodeCause(causeRequestRejected)))
		return
	}
	sess.remoteAddr = src

	// A modification may (re)carry the UE IP and the downlink outer header.
	if ohc, ok := downlinkOHC(msg.IEs); ok {
		if sess.ueIP == nil {
			if ue := findUEIP(msg.IEs); ue != nil {
				sess.ueIP = ue
			}
		}
		if sess.ueIP != nil {
			if err := s.installDownlink(sess, ohc); err != nil {
				log.Printf("pfcp: downlink install (modification) failed SEID %d: %v", msg.SEID, err)
			} else {
				log.Printf("pfcp: session %d downlink installed: NAT %v -> UE %v teid=0x%08X gNB=%v",
					msg.SEID, sess.natIP, sess.ueIP, ohc.TEID, ohc.IPv4)
			}
		}
	}

	s.reply(src, buildMessage(msgSessionModificationResponse, true, sess.remoteSEID, msg.Seq,
		encodeCause(causeRequestAccepted)))
}

func (s *Server) handleSessionDeletion(msg *message, src *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess := s.sessions[msg.SEID]
	if sess == nil {
		s.reply(src, buildMessage(msgSessionDeletionResponse, true, 0, msg.Seq,
			encodeCause(causeRequestRejected)))
		return
	}
	s.removeRules(sess)
	delete(s.sessions, msg.SEID)
	log.Printf("pfcp: session deleted SEID=%d", msg.SEID)
	s.reply(src, buildMessage(msgSessionDeletionResponse, true, sess.remoteSEID, msg.Seq,
		encodeCause(causeRequestAccepted)))
}

// --- rule installation (reuses the exact maps path the CLI uses) ----------

func (s *Server) installUplink(sess *session) error {
	rule := &maps.FwdRule{
		Action:     maps.ActionDecapFwd,
		OutIfindex: s.ulIfindex,
		DMac:       s.cfg.ULDMac,
		SMac:       s.cfg.ULSMac,
	}
	natHost, err := maps.IPToUint32(sess.natIP)
	if err != nil {
		return err
	}
	rule.NatIP = natHost
	if err := maps.ValidateRule(rule); err != nil {
		return err
	}
	tm, err := maps.OpenTeidMap()
	if err != nil {
		return err
	}
	defer tm.Close()
	if err := tm.Put(sess.uplinkTEID, rule); err != nil {
		return err
	}
	if err := maps.EnsureTxPort(s.ulIfindex); err != nil {
		return err
	}
	sess.teidInstalled = true
	return nil
}

func (s *Server) installDownlink(sess *session, ohc decodedOHC) error {
	if ohc.IPv4 == nil {
		return fmt.Errorf("downlink outer header has no gNB IPv4")
	}
	rule := &maps.FwdRule{
		Action:     maps.ActionEncapFwd,
		OutIfindex: s.dlIfindex,
		DMac:       s.cfg.DLDMac,
		SMac:       s.cfg.DLSMac,
		TeidOut:    ohc.TEID,
	}
	// nat_map value convention (see control/cmd/add_nat.go): NatIP stores the UE
	// IP to restore as the inner destination.
	ueHost, err := maps.IPToUint32(sess.ueIP)
	if err != nil {
		return err
	}
	rule.NatIP = ueHost
	if rule.SrcIP, err = maps.IPToUint32(s.cfg.N3IP); err != nil {
		return err
	}
	if rule.DstIP, err = maps.IPToUint32(ohc.IPv4); err != nil {
		return err
	}
	if err := maps.ValidateRule(rule); err != nil {
		return err
	}
	nm, err := maps.OpenNatMap()
	if err != nil {
		return err
	}
	defer nm.Close()
	if err := nm.Put(sess.natIP, rule); err != nil {
		return err
	}
	if err := maps.EnsureTxPort(s.dlIfindex); err != nil {
		return err
	}
	sess.natInstalled = true
	return nil
}

func (s *Server) removeRules(sess *session) {
	if sess.teidInstalled {
		if tm, err := maps.OpenTeidMap(); err == nil {
			_ = tm.Delete(sess.uplinkTEID)
			tm.Close()
		}
	}
	if sess.natInstalled && sess.natIP != nil {
		if nm, err := maps.OpenNatMap(); err == nil {
			_ = nm.Delete(sess.natIP)
			nm.Close()
		}
	}
}

// --- small IE helpers used by the handlers --------------------------------

// ifaceOf returns the Source/Destination Interface value inside a PDI/FAR, or a
// sentinel 0xff when absent.
func ifaceOf(container *ie) uint8 {
	if si := findIE(container.Children, ieSourceInterface); si != nil {
		return firstByte(si.Value)
	}
	if di := findIE(container.Children, ieDestinationIface); di != nil {
		return firstByte(di.Value)
	}
	return 0xff
}

// downlinkOHC extracts the Outer Header Creation from a Create FAR or Update FAR
// whose Apply Action forwards toward the access (gNB) side.
func downlinkOHC(ies []ie) (decodedOHC, bool) {
	for _, t := range []uint16{ieCreateFAR, ieUpdateFAR} {
		for _, far := range findAllIE(ies, t) {
			if aa := findIE(far.Children, ieApplyAction); aa != nil && !applyActionForwards(aa.Value) {
				continue
			}
			fp := findIE(far.Children, ieForwardingParams)
			if fp == nil {
				fp = findIE(far.Children, ieUpdateForwardingPrm)
			}
			if fp == nil {
				continue
			}
			ohcIE := findIE(fp.Children, ieOuterHeaderCreation)
			if ohcIE == nil {
				continue
			}
			ohc, err := parseOuterHeaderCreation(ohcIE.Value)
			if err == nil && ohc.GTPU {
				return ohc, true
			}
		}
	}
	return decodedOHC{}, false
}

// findUEIP searches all Create PDRs' PDIs for a UE IP Address IE.
func findUEIP(ies []ie) net.IP {
	for _, pdr := range findAllIE(ies, ieCreatePDR) {
		if pdi := findIE(pdr.Children, iePDI); pdi != nil {
			if ue := findIE(pdi.Children, ieUEIPAddress); ue != nil {
				if ip := parseUEIPAddress(ue.Value); ip != nil {
					return ip
				}
			}
		}
	}
	return nil
}

func beUint16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
func beUint64(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v
}
