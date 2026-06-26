package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go GtpXdp ../../ebpf/gtp_xdp.c -- -I../../include
