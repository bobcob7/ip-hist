INTERFACE=enp0s31f6

build: ip-hist.o ip-hist

install: ip-hist.o
	ip link set dev ${INTERFACE} xdp obj ip-hist.o

run: ip-hist
	./ip-hist

clean:
	ip link set dev ${INTERFACE} xdp none
	rm -f ip-hist* /sys/fs/bpf/tc/globals/packet_count

ip-hist:
	go build ./cmd/ip-hist

ip-hist.bc: xdp-module/main.c
	clang -O2 -Wall -g -emit-llvm -target bpf -c xdp-module/main.c -o ip-hist.bc

ip-hist.o: ip-hist.bc
	llc ip-hist.bc -march=bpf -mattr=dwarfris -filetype=obj -o ip-hist.o

diss: xdp-module/main.c
	clang -O2 -S -v -Wall -I /usr/include/iproute2 -I /usr/include/x86_64-linux-gnu -target bpf -c xdp-module/main.c -o ip-hist.S