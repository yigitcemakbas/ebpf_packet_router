ARCH		:= $(shell uname -m)
KERN_HDRS	:= /usr/include/$(ARCH)-linux-gnu

OUT_DIR		:= build
BPF_SRC		:= ebpf/gtp_xdp.c
BPF_OBJ		:= $(OUT_DIR)/gtp_xdp.o

BPF_CFLAGS:=\
	-O2 -g \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I ./include \
	-I$(KERN_HDRS) \
	-Wall -Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types

IF		?=eth0
XDP_MODE 	?= native 

.PHONY: all ebpf skel load unload clean
all:ebpf

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# compile the bpf object

ebpf:$(OUT_DIR) $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) include/gtp_router.h
	clang $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "BPF object: $(BPF_OBJ)"
	@llvm-objdump -h $(BPF_OBJ) | grep -E "^[[:space:]]+[0-9]|Name"

# generate bpf2go skeleton for control plane
skel: $(BPF_OBJ)
	bpftool gen skeleton $(BPF_O) name gtp_xdp>$(OUT_DIR)/gtp_xdp.skel.h
	@echo "Skeleton header: $(OUT_DIR)/gtp_xdp.skel.h"

# load via iproute2 (for manual testing without go loader)
load:$(BPF_OBJ)
	ip link set dev $(IF) xdp$(if $(filter offload, $(XDP_MODE)),offload,\
		$(if $(filter generic, $(XDP_MODE)), generic,)) \
		obj $(BPF_OBJ) sec xdp
	@echo "XDP program attached to $(IF) (mode: $(XDP_MODE))"

unload:
	ip link set dev $(IF) xdp off
	@echo "XDP program detached from $(IF)"

#inspect loaded program
info:
	bpftool prog show
	bpftool map show

clean:
	rm -rf $(OUT_DIR)
	@echo "cleaned"

