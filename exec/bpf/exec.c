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
#include <uapi/linux/ptrace.h>

#include "bpf_helpers.h"

#define ARG_LEN 256

struct execve_data_t {
    u64 ktime_ns;
    u64 real_start_time_ns;
    u32 pid;
    u32 uid;
    u32 gid;
    u32 ppid;
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

struct exit_data_t {
    u64 ktime_ns;
    u32 pid;
    u32 _pad;
};

/*
 * This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor. BPF_MAP_TYPE_PERF_EVENT_ARRAY
 * was introduced in kernel 4.3.
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

/*
 * get_ppid returns the process ID of the parent process (PPID). Any changes to
 * task struct between the compile-time and runtime will cause the returned PPID
 * to be invalid. So the value should be vetted in userspace.
 */
int get_ppid(struct task_struct *task)
{
    u32 ppid;
    struct task_struct *parent;
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read(&ppid, sizeof(ppid), &parent->pid);
    return ppid;
}

/*
 * get_process_start_time returns the start time in nanoseconds based on the
 * offset from boot time. In userspace this value should be added to boottime
 * which can be obtained from /proc/stat (note that value is given in seconds
 * since epoch).
 *
 * Any changes to task struct between the compile-time and runtime will cause
 * the returned PPID to be invalid. So the value should be vetted in userspace.
 */
u64 get_process_start_time(struct task_struct *task)
{
    u64 real_start_time_ns;
    bpf_probe_read(&real_start_time_ns, sizeof(real_start_time_ns), &task->real_start_time);
    return real_start_time_ns;
}

SEC("kprobe/SyS_execve")
int kprobe__sys_exeve(struct pt_regs *ctx)
{
    u64 ktime_ns = bpf_ktime_get_ns();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task(); // 4.8
    u32 cpu = bpf_get_smp_processor_id();

    // Read general execve attributes.
    struct execve_data_t execve_data = {
        .ktime_ns = ktime_ns,
        .real_start_time_ns = get_process_start_time(task),
        .pid = bpf_get_current_pid_tgid() >> 32,
        .uid = bpf_get_current_uid_gid() >> 32,
        .gid = bpf_get_current_uid_gid(),
        .ppid = get_ppid(task),
    };
    bpf_get_current_comm(&execve_data.comm, sizeof(execve_data.comm)); // 4.2
    bpf_perf_event_output(ctx, &execve_events, cpu, &execve_data, sizeof(execve_data));

    // Read execve arguments.
    struct execve_arg_t arg_data = {
        .pid = execve_data.pid,
    };

    // Read filename to executable.
    bpf_probe_read(arg_data.arg, sizeof(arg_data.arg), (void *)PT_REGS_PARM1(ctx));
    bpf_perf_event_output(ctx, &execve_events, cpu, &arg_data, sizeof(arg_data)); // 4.4

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

SEC("kprobe/do_exit")
int kprobe__do_exit(struct pt_regs *ctx)
{
    struct exit_data_t exit_data = {
        .ktime_ns = bpf_ktime_get_ns(),
        .pid = bpf_get_current_pid_tgid() >> 32,
    };

    u32 cpu = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &execve_events, cpu, &exit_data, sizeof(exit_data));

    return 0;
}

// Code is licensed under Apache 2.0 which is GPL compatible.
char _license[] SEC("license") = "GPL";

// This number will be interpreted by the elf loader to set the current
// running kernel version.
__u32 _version SEC("version") = 0xFFFFFFFE;
