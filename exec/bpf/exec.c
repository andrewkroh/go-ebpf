/*
 * Copyright 2017 Elasticsearch Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/kconfig.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <uapi/linux/ptrace.h>

#include "bpf_helpers.h"

#define ARG_LEN 256

struct execve_data_t {
    u32 pid;
    u32 uid;
    u32 gid;
    u32 _pad;
    char comm[TASK_COMM_LEN];
};

struct execve_arg_t {
    u32 pid;
    u32 _pad;
    char arg[ARG_LEN];
};

struct execve_rtn_t {
    u32 pid;
    u32 rtn_code;
};

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct bpf_map_def SEC("maps/execve_events") execve_events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
};

int copy_arg(const char *const *src, char *dst) {
    char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), (void*)src);
    if (argp) {
        bpf_probe_read(dst, ARG_LEN, argp);
        return 1;
    }
    return 0;
}

int send_arg(
    struct pt_regs *ctx,
    int cpu,
    int *i,
    const char *const *argv,
    struct execve_arg_t *arg_data)
{
    if (!copy_arg(&argv[*i], arg_data->arg)) { return 0; }
    bpf_perf_event_output(ctx, &execve_events, cpu, arg_data, sizeof(*arg_data));
    (*i)++;
    return 1;
}

SEC("kprobe/SyS_execve")
int kprobe__sys_exeve(struct pt_regs *ctx)
{
    u32 cpu = bpf_get_smp_processor_id();

    // Read general execve attributes.
    struct execve_data_t execve_data = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .uid = bpf_get_current_uid_gid() >> 32,
        .gid = bpf_get_current_uid_gid(),
    };
    bpf_get_current_comm(&execve_data.comm, sizeof(execve_data.comm));
    bpf_perf_event_output(ctx, &execve_events, cpu, &execve_data, sizeof(execve_data));

    // Read execve arguments.
    struct execve_arg_t arg_data = {
        .pid = execve_data.pid,
    };

    // Read filename to executable.
    bpf_probe_read(arg_data.arg, sizeof(arg_data.arg), (void *)PT_REGS_PARM1(ctx));
    bpf_perf_event_output(ctx, &execve_events, cpu, &arg_data, sizeof(arg_data));

    // Read args.
    const char __user *const __user *argv = (void *)PT_REGS_PARM2(ctx);

    // No for loops in restricted C used by eBPF.
    int i = 0;
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }

    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }
    if (!send_arg(ctx, cpu, &i, argv, &arg_data)) { return 0; }

    // Truncated arguments.
    char ellipse[] = "...";
    bpf_probe_read(arg_data.arg, sizeof(arg_data.arg), (void*)ellipse);
    bpf_perf_event_output(ctx, &execve_events, cpu, &arg_data, sizeof(arg_data));

    return 0;
}

SEC("kretprobe/SyS_execve")
int kretprobe__sys_exeve(struct pt_regs *ctx)
{
    struct execve_rtn_t rtn_data = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .rtn_code = PT_REGS_RC(ctx),
    };

    u32 cpu = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &execve_events, cpu, &rtn_data, sizeof(rtn_data));

    return 0;
}

// Code is licensed under Apache 2.0 which is GPL compatible.
char _license[] SEC("license") = "GPL";

// This number will be interpreted by the elf loader to set the current
// running kernel version.
__u32 _version SEC("version") = 0xFFFFFFFE;
