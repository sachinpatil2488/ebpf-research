// Author : Sachin Patil
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 sachinp*/

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int PATH_MAX = 256;

SEC("tracepoint/syscalls/sys_enter_openat")
/*
  sys_enter_openat(
    	int __syscall_nr;
    	int dfd;
    	const char * filename;
    	int flags;
    	umode_t mode);
 **/
int itracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    unsigned int dfd = (unsigned int)ctx->args[0];

    const char * name_ptr = (const char *)ctx->args[1];
    char fileName[PATH_MAX];
    bpf_probe_read_user(&fileName, sizeof(fileName), name_ptr);

    int flags = (int)ctx->args[2];
    
    umode_t mode = (umode_t)ctx->args[3];

    unsigned long pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk("Tripwire eBPF trace [openat] : { pid : %lu, fd : %lu, name: %s, flags : %d, mode : %u }\n", 
		    pid, dfd, fileName, flags, mode );

    return 0;
 }


