project_root=../..
uname=$(shell uname -r)

all: build copy

build:
	clang \
      -D__KERNEL__ \
      -D__ASM_SYSREG_H \
      -Wno-address-of-packed-member \
      -O2 -emit-llvm -c exec.c \
      -I $(project_root)/common/bpf \
      -I /lib/modules/$(uname)/source/include \
      -I /lib/modules/$(uname)/source/arch/x86/include \
      -I /lib/modules/$(uname)/build/include \
      -I /lib/modules/$(uname)/build/arch/x86/include/generated \
      -o - | \
      llc -march=bpf -filetype=obj -o exec.o

copy:
	go run $(project_root)/scripts/bin_data.go -pkg exec exec.o exec.o > bin_data.go
	mv bin_data.go ..
