# IP Histogram

This is a sort of PoC for BPF and XDP filters.
My goal is to create live histograms for various network statistics.

# Requirements
This requires limited kernel development toolchain.
You will require:
- Clang
- LLVM
- Kernel headers
- iproute2 headers
- Lib C 32-bit headers
On ubuntu, these can usually be gotten with
`apt install -y clang llvm linux-header-$(uname -r) libc6-dev-i386

# Installation
This project contains 2 main components.
The XDP module that is attached to an interface
and the userspace application that reads in the statistics.
Both can be built with:
```
make build
```

The XDP module installation and userspace application execution needs to be performed
by a priviledged user.

The XDP module can be installed with:
```
sudo make install
```

To view the statistics, start the userspace application with:
```
sudo make run
```
