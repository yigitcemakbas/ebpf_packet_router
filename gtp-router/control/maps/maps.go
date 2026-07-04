package maps

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

const (
	PinDir          = "/sys/fs/bpf/gtp_router"
	PinTeidMap      = PinDir + "/teid_map"
	PinUeipMap      = PinDir + "/ueip_map"
	PinNatMap       = PinDir + "/nat_map"
	PinStatsMap     = PinDir + "/stats_map"
	PinTxPort       = PinDir + "/tx_port"
	PinProg         = PinDir + "/xdp_prog"
	PinProgDownlink = PinDir + "/xdp_prog_dl"
)

type TeidMap struct{ m *ebpf.Map }

func OpenTeidMap() (*TeidMap, error) {
	m, err := ebpf.LoadPinnedMap(PinTeidMap, nil)
	if err != nil {
		return nil, fmt.Errorf("open teid_map: %w", err)
	}
	return &TeidMap{m: m}, nil
}

func NewTeidMap(m *ebpf.Map) *TeidMap { return &TeidMap{m: m} }
func (t *TeidMap) Close()             { t.m.Close() }

func (t *TeidMap) Put(teid uint32, rule *FwdRule) error {
	if err := t.m.Put(teid, rule); err != nil {
		return fmt.Errorf("teid_map put 0x%08X: %w", teid, err)
	}
	return nil
}

func (t *TeidMap) Delete(teid uint32) error {
	err := t.m.Delete(teid)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("teid_map delete 0x%08X: %w", teid, err)
	}
	return nil
}

func (t *TeidMap) Get(teid uint32) (*FwdRule, error) {
	var rule FwdRule
	err := t.m.Lookup(teid, &rule)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("teid_map lookup 0x%08X: %w", teid, err)
	}
	return &rule, nil
}

func (t *TeidMap) List() (map[uint32]*FwdRule, error) {
	out := make(map[uint32]*FwdRule)
	var key uint32
	var rule FwdRule
	iter := t.m.Iterate()
	for iter.Next(&key, &rule) {
		r := rule
		out[key] = &r
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("teid_map iterate: %w", err)
	}
	return out, nil
}

type UeipMap struct{ m *ebpf.Map }

func OpenUeipMap() (*UeipMap, error) {
	m, err := ebpf.LoadPinnedMap(PinUeipMap, nil)
	if err != nil {
		return nil, fmt.Errorf("open ueip_map: %w", err)
	}
	return &UeipMap{m: m}, nil
}

func NewUeipMap(m *ebpf.Map) *UeipMap { return &UeipMap{m: m} }
func (u *UeipMap) Close()             { u.m.Close() }

func ipKey(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("%s is not an IPv4 address", ip)
	}
	return binary.BigEndian.Uint32(ip4), nil
}

func (u *UeipMap) Put(ueip net.IP, rule *FwdRule) error {
	key, err := ipKey(ueip)
	if err != nil {
		return err
	}
	if err := u.m.Put(key, rule); err != nil {
		return fmt.Errorf("ueip_map put %s: %w", ueip, err)
	}
	return nil
}

func (u *UeipMap) Delete(ueip net.IP) error {
	key, err := ipKey(ueip)
	if err != nil {
		return err
	}
	err = u.m.Delete(key)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("ueip_map delete %s: %w", ueip, err)
	}
	return nil
}

func (u *UeipMap) Get(ueip net.IP) (*FwdRule, error) {
	key, err := ipKey(ueip)
	if err != nil {
		return nil, err
	}
	var rule FwdRule
	err = u.m.Lookup(key, &rule)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ueip_map lookup %s: %w", ueip, err)
	}
	return &rule, nil
}

func (u *UeipMap) List() (map[uint32]*FwdRule, error) {
	out := make(map[uint32]*FwdRule)
	var key uint32
	var rule FwdRule
	iter := u.m.Iterate()
	for iter.Next(&key, &rule) {
		r := rule
		out[key] = &r
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("ueip_map iterate: %w", err)
	}
	return out, nil
}

type NatMap struct{ m *ebpf.Map }

func OpenNatMap() (*NatMap, error) {
	m, err := ebpf.LoadPinnedMap(PinNatMap, nil)
	if err != nil {
		return nil, fmt.Errorf("open nat_map: %w", err)
	}
	return &NatMap{m: m}, nil
}

func NewNatMap(m *ebpf.Map) *NatMap { return &NatMap{m: m} }
func (n *NatMap) Close()            { n.m.Close() }

func (n *NatMap) Put(natIP net.IP, rule *FwdRule) error {
	key, err := ipKey(natIP)
	if err != nil {
		return err
	}
	if err := n.m.Put(key, rule); err != nil {
		return fmt.Errorf("nat_map put %s: %w", natIP, err)
	}
	return nil
}

func (n *NatMap) Delete(natIP net.IP) error {
	key, err := ipKey(natIP)
	if err != nil {
		return err
	}
	err = n.m.Delete(key)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("nat_map delete %s: %w", natIP, err)
	}
	return nil
}

func (n *NatMap) Get(natIP net.IP) (*FwdRule, error) {
	key, err := ipKey(natIP)
	if err != nil {
		return nil, err
	}
	var rule FwdRule
	err = n.m.Lookup(key, &rule)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("nat_map lookup %s: %w", natIP, err)
	}
	return &rule, nil
}

func (n *NatMap) List() (map[uint32]*FwdRule, error) {
	out := make(map[uint32]*FwdRule)
	var key uint32
	var rule FwdRule
	iter := n.m.Iterate()
	for iter.Next(&key, &rule) {
		r := rule
		out[key] = &r
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("nat_map iterate: %w", err)
	}
	return out, nil
}

// TxPortMap wraps the BPF_MAP_TYPE_DEVMAP that bpf_redirect_map() targets.
// It is keyed by egress ifindex and stores the same ifindex as the value.
// Every out_ifindex a forwarding rule uses must have an entry here, or the
// in-kernel redirect aborts (drops) that frame.
type TxPortMap struct{ m *ebpf.Map }

func OpenTxPortMap() (*TxPortMap, error) {
	m, err := ebpf.LoadPinnedMap(PinTxPort, nil)
	if err != nil {
		return nil, fmt.Errorf("open tx_port: %w", err)
	}
	return &TxPortMap{m: m}, nil
}

func NewTxPortMap(m *ebpf.Map) *TxPortMap { return &TxPortMap{m: m} }
func (t *TxPortMap) Close()               { t.m.Close() }

// Ensure makes tx_port[ifindex] = ifindex so bpf_redirect_map() can send
// frames out that interface. Idempotent; safe to call on every rule write.
func (t *TxPortMap) Ensure(ifindex uint32) error {
	if err := t.m.Put(ifindex, ifindex); err != nil {
		return fmt.Errorf("tx_port put ifindex %d: %w", ifindex, err)
	}
	return nil
}

// EnsureTxPort opens the pinned devmap and provisions one ifindex, then
// closes it. Convenience for the rule-adding CLI commands, which otherwise
// do not hold the map open. A zero ifindex (no egress set) is a no-op.
func EnsureTxPort(ifindex uint32) error {
	if ifindex == 0 {
		return nil
	}
	t, err := OpenTxPortMap()
	if err != nil {
		return err
	}
	defer t.Close()
	return t.Ensure(ifindex)
}