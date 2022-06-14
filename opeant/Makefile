obj-m += openat_bpf.o

all:
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -c openat.bpf.c -I/home/vagrant/vmLinux -I/lib/modules/$(shell uname -r)/build/include/ -I/home/vagrant/libbpf/src

