/*
    SysinternalsEBPF

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

//====================================================================
//
// sysinternalsEBPF_common.h
//
// Defines and maps needed by sysinternalsEBPF_helpers.c
//
//====================================================================

#ifndef SYSINTERNALS_EBPF_COMMON_H
#define SYSINTERNALS_EBPF_COMMON_H

//#include "vmlinux.h"
#include <stdint.h>
#include <linux/version.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <asm/unistd_64.h>
#include <asm/ptrace.h>
#include <sysinternalsEBPFshared.h>

// debug tracing can be found using:
// #cat /sys/kernel/debug/tracing/trace_pipe

#ifdef DEBUG_K
#define BPF_PRINTK( format, ... ) \
    char fmt[] = format; \
    bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__ ); 
#else
#define BPF_PRINTK ((void)0);
#endif

// missing stddef.h defines
#define NULL ((void *)0)
#define true 1
#define false 0

// x64 syscall macros
#define SYSCALL_PT_REGS_PARM1(x) ((x)->rdi)
#define SYSCALL_PT_REGS_PARM2(x) ((x)->rsi)
#define SYSCALL_PT_REGS_PARM3(x) ((x)->rdx)
#define SYSCALL_PT_REGS_PARM4(x) ((x)->r10)
#define SYSCALL_PT_REGS_PARM5(x) ((x)->r8)
#define SYSCALL_PT_REGS_PARM6(x) ((x)->r9)
#define SYSCALL_PT_REGS_RC(x)    ((x)->rax)

#define CMDLINE_MAX_LEN 16384 // must be power of 2
#define MAX_FDS 65535

#define MAX_MEM_DUMP 32768

#define ARG_ARRAY_SIZE 8
#define ARG_MASK 7

// Event arguments structure
typedef struct {
    unsigned long      syscallId;
    unsigned long      a[8]; // Should only be 6 but this helps with verifier
    unsigned long      returnCode;
} argsStruct;



// bpf_raw_tracepoint_args definition from /usr/src/linux/include/uapi/linux/bpf.h
struct bpf_our_raw_tracepoint_args {
    __u64 args[0];
};

// generic sys_enter argument struct for traditional tracepoints. Note that
// some or all of the 'a' array can't be derefenced depending on how many
// arguments a syscall expects; attempts to do so will cause the verifier
// to reject it.
struct tracepoint__syscalls__sys_enter {
    __uint64_t pad;
    __uint32_t __syscall_nr;
    __uint32_t pad2;
    __uint64_t a[6];
};


// all sys_exit arguments are the same for traditional tracepoints.
struct tracepoint__syscalls__sys_exit {
    __uint64_t pad;
    __uint32_t __syscall_nr;
    __uint32_t pad2;
    long ret;
};



#define MAX_PROC 512
#define ARGS_HASH_SIZE 10240

#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU 0xffffffffULL
#endif

// create a map to transport events to userland via perf ring buffer
/*struct bpf_map_def SEC("maps") eventMap = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, //BPF_MAP_TYPE_HASH doesnt stack....
	.key_size = sizeof(int),
	.value_size = sizeof(uint32_t),
	.max_entries = MAX_PROC, // MAX_PROC CPUs - this needs to accommodate most systems as this is CO:RE-alike
                        // Also, as this map is quite small (8 bytes per entry), we could potentially
                        // make this event bigger and it woulnd't cost much
};*/

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(uint32_t));
    __uint(max_entries, MAX_PROC);    
} eventMap SEC(".maps");


// create a map to hold the configuration
// only one entry, which is the config struct
/*struct bpf_map_def SEC("maps") configMap = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(ebpfConfig),
    .max_entries = 1,
};*/
 
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, ebpfConfig);
    __uint(max_entries, 1);
} configMap SEC(".maps");

// create a map to hold a temporary filepath as we build it - too big for stack
// one entry per cpu
/*struct bpf_map_def SEC("maps") temppathArray = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = PATH_MAX * 2,
    .max_entries = MAX_PROC,
};*/

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, PATH_MAX * 2);
    __uint(max_entries, MAX_PROC);
} temppathArray SEC(".maps");

// create a hash to hold event arguments between sys_enter and sys_exit
// shared by all cpus because sys_enter and sys_exit could be on different cpus
/*struct bpf_map_def SEC("maps") argsHash = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(argsStruct),
    .max_entries = ARGS_HASH_SIZE,
};*/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, ARGS_HASH_SIZE);
    __type(key, uint64_t);
    __type(value, argsStruct);
} argsHash SEC(".maps");

// create a map to hold perf_ring_buffer errors
/*struct bpf_map_def SEC("maps") perfErrorsMap = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(perfError),
    .max_entries = PERF_ERRORS_MAX + 2, // read and write indicies are at end
};*/

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, perfError);
    __uint(max_entries, PERF_ERRORS_MAX + 2);
} perfErrorsMap SEC(".maps");


#endif
