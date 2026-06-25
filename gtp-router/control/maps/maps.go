package maps

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

const (
	PinDir      = "/sys/fs/bpf/gtp_router"
	PinTeidMap  = PinDir + "/teid_map"
	PinUeipMap  = PinDir + "/ueip_map"
	PinStatsMap = PinDir + "/stats_map"
	PinProg     = PinDir + "/xdp_prog"
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