rm openat openat.bpf.o openat.o openat.skel.h
clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c openat.bpf.c -o openat.bpf.o -I/home/vagrant/libbpf/src/include
./bpftool gen skeleton openat.bpf.o > openat.skel.h	
clang -g -O2 -Wall -I . -c openat.c -o openat.o -I . -I/home/vagrant/libbpf/src/include
clang -Wall -O2 -g openat.o /home/vagrant/libbpf/src/lib/libbpf.a -lelf -lz -o openat
ls
