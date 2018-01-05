#!/bin/bash

set -euo pipefail

echo_stderr ()
{
    echo "$@" >&2
}

echo_stderr "###################################################################################"
echo_stderr "# FYI: You need to run this with CAP_SYS_ADMIN and the give access to the debugfs."
echo_stderr "# docker run -it --rm --cap-add=SYS_ADMIN -v /sys/kernel/debug:/sys/kernel/debug akroh/go-ebpf:execsnoop"
echo_stderr "###################################################################################"

exec "$@"
