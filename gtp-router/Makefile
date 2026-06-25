ARCH      := $(shell uname -m)
# libbpf expects arm64, not aarch64 — remap for ARM64 hosts
BPF_ARCH  := $(shell uname -m | sed 's/aarch64/arm64/')
KERN_HDRS := /usr/include/$(ARCH)-linux-gnu

OUT_DIR  := build
BPF_SRC  := ebpf/gtp_xdp.c
BPF_OBJ  := $(OUT_DIR)/gtp_xdp.o
GTP_CTRL := $(OUT_DIR)/gtp-ctrl

GENERATED := control/loader/gtpxdp_bpfel.go \
             control/loader/gtpxdp_bpfel.o

BPF_CFLAGS := \
    -O2 -g \
    -target bpf \
    -D__TARGET_ARCH_$(BPF_ARCH) \
    -I./include \
    -I$(KERN_HDRS) \
    -Wall \
    -Wno-unused-value \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types

IF       ?= eth0
XDP_MODE ?= native

.PHONY: all ebpf generate build load unload info clean

# Full build: C → bpf2go → Go binary
all: ebpf generate build

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# Step 1: compile the BPF C program to a BPF ELF object
ebpf: $(OUT_DIR) $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) include/gtp_router.h
	clang $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "BPF object: $(BPF_OBJ)"

# Step 2: run bpf2go — embeds the .o into Go source and generates typed structs
generate: $(BPF_OBJ)
	cd control && go generate ./...
	@echo "Generated: $(GENERATED)"

# Step 3: compile the Go binary (includes the embedded .o via go:embed)
build: $(GENERATED)
	cd control && go build -o ../$(GTP_CTRL) .
	@echo "Binary: $(GTP_CTRL)"

# Manual attach via iproute2 (useful for testing without the Go binary)
load: $(BPF_OBJ)
	ip link set dev $(IF) xdp obj $(BPF_OBJ) sec xdp
	@echo "XDP attached to $(IF)"

unload:
	ip link set dev $(IF) xdp off
	@echo "XDP detached from $(IF)"

info:
	bpftool prog show
	bpftool map show

clean:
	rm -rf $(OUT_DIR) $(GENERATED)