project_root=../..
uname=$(shell uname -r)
kernel_src=$(shell rpm -qa kernel-devel | head -1 | sed 's/kernel-devel-//g' | awk '{print "/usr/src/kernels/"$$1""}')

all: build copy

build:
	clang \
      -D__KERNEL__ \
      -D__ASM_SYSREG_H \
      -Wno-address-of-packed-member \
      -O2 -emit-llvm -c socket.c \
      -I $(project_root)/common/bpf \
      -I $(kernel_src)/arch/x86/include \
      -I $(kernel_src)/arch/x86/include/generated \
      -I $(kernel_src)/include \
      -o - | \
      llc -march=bpf -filetype=obj -o socket.o

copy:
	go run $(project_root)/scripts/bin_data.go -pkg socket socket.o socket.o > bin_data.go
	mv bin_data.go ..

.PHONY: all build copy
