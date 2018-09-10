// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include <linux/kconfig.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <uapi/linux/ptrace.h>

#include "bpf_helpers.h"

/*
 * This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor. BPF_MAP_TYPE_PERF_EVENT_ARRAY
 * was introduced in kernel 4.3.
 */
struct bpf_map_def SEC("maps/socket_events") socket_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

/*
 * inet_sock_set_state tracepoint format.
 *
 * Format: cat /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format
 * Code: https://github.com/torvalds/linux/blob/v4.16/include/trace/events/sock.h#L123-L135
 */
struct inet_sock_set_state_ctx {
    u64 unused; // First 8 bytes are not accessible by BPF code.
    void *skaddr;
    u32 oldstate;
    u32 newstate;
    u16 sport;
    u16 dport;
    u16 family;
    u8 protocol;
    char saddr[4];
    char daddr[4];
    char saddr_v6[16];
    char daddr_v6[16];
};

/*
 * socket_state_data_t is the struct that is delivered to userspace.
 */
struct socket_state_data_t {
    u64 ktime_ns;
    u64 id;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 uid;
    u32 gid;
    char saddr[16];
    char daddr[16];
    u16 sport;
    u16 dport;
    u32 oldstate;
    u32 newstate;
    u16 family;
    u8 protocol;
    char pad[5];
};

// trace_inet_sock_set_state is attached to the tracepoint.
//
// https://github.com/torvalds/linux/blob/v4.16/include/trace/events/sock.h#L117
SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct inet_sock_set_state_ctx *ctx)
{
    u32 cpu = bpf_get_smp_processor_id();

    // NOTE: PID and comm are NOT valid for all states.
    struct socket_state_data_t evt = {
        .ktime_ns = bpf_ktime_get_ns(),
        .id = (u64)ctx->skaddr,
        .pid = bpf_get_current_pid_tgid() >> 32,
        .comm = {0},
        .uid = bpf_get_current_uid_gid() >> 32,
        .gid = bpf_get_current_uid_gid(),
        .saddr = {0},
        .daddr = {0},
        .sport = ctx->sport,
        .dport = ctx->dport,
        .oldstate = ctx->oldstate,
        .newstate = ctx->newstate,
        .family = ctx->family,
        .protocol = ctx->protocol,
        .pad = {0},
    };

    if (evt.protocol == AF_INET6) {
        bpf_probe_read(&evt.saddr, 16, ctx->saddr_v6);
        bpf_probe_read(&evt.daddr, 16, ctx->daddr_v6);
    } else {
        bpf_probe_read(&evt.saddr, 4, ctx->saddr);
        bpf_probe_read(&evt.daddr, 4, ctx->daddr);
    }
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm)); // 4.2
    bpf_perf_event_output(ctx, &socket_events, cpu, &evt, sizeof(evt));

    return 0;
}

// Code is licensed under Apache 2.0 which is GPL compatible.
char _license[] SEC("license") = "GPL";

// This number will be interpreted by the elf loader to set the current
// running kernel version.
__u32 _version SEC("version") = 0xFFFFFFFE;
