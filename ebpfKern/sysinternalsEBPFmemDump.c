/*
    SysmonForLinux

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
// sysinternalsEBPFmemDump.c
//
// eBPF program for dumping memory via trapping on uname syscall.
//
//====================================================================

#define FILEPATH_NUMDIRS 95

#include "sysinternalsEBPF_common.h"
#include "sysinternalsEBPF_helpers.c"
#include "memDumpShared.h"

//
// Create a map to hold the memory dump configuration.
// Only one entry, which is the config struct
//
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(memDumpConfig));
    __uint(max_entries, 1);
} memDumpConfigMap SEC(".maps");

//
// Create a map to hold the mem dump event as we build it - too big for stack.
// One entry per cpu
//
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(memDump));
    __uint(max_entries, MAX_PROC);
} memDumpStorageMap SEC(".maps");

struct tracepoint__skb_consume_skb {
    __uint64_t  pad;
    const void * skbaddr;
};

//--------------------------------------------------------------------
//
// sys_exit_uname
//
// Memory dumper from uname syscall.
//
//--------------------------------------------------------------------
SEC("tracepoint/syscalls/sys_exit_uname")
__attribute__((flatten))
int sys_exit_uname(struct tracepoint__syscalls__sys_exit *args)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint32_t cpuId = bpf_get_smp_processor_id();
    uint32_t configId = 0;
    const memDumpConfig *config;
    memDump *event;
    const void *addr = NULL;

    uint32_t userlandPid = 0;
    char *ptr = NULL;

    // retrieve config
    config = bpf_map_lookup_elem(&memDumpConfigMap, &configId);
    if (!config)
        return 0;
    userlandPid = config->userlandPid;

    // only respond to our controller
    if ((pidTid >> 32) != userlandPid)
        return 0;

    // retrieve map storage for event
    event = bpf_map_lookup_elem(&memDumpStorageMap, &cpuId);
    if (!event)
        return 0;

    if (config->type == task) {
        addr = (void *)bpf_get_current_task();
    } else {
        addr = config->addr;
    }

    if (bpf_probe_read(event->data, config->size & (MAX_MEM_DUMP -1), addr) != READ_OKAY) {
        return 0;
    }

    event->type = config->type;
    event->addr = addr;
    event->size = config->size;

    bpf_perf_event_output((void *)args, &eventMap, BPF_F_CURRENT_CPU, event, sizeof(memDump));

    return 0;
}

//--------------------------------------------------------------------
//
// consume_skb
//
// Memory dumper from packet being sent.
//
//--------------------------------------------------------------------
SEC("tracepoint/skb/consume_skb")
__attribute__((flatten))
int consume_skb(struct tracepoint__skb_consume_skb *args)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint32_t cpuId = bpf_get_smp_processor_id();
    uint32_t configId = 0;
    const memDumpConfig *config;
    memDump *event;
    const void *addr = NULL;

    uint32_t userlandPid = 0;
    char *ptr = NULL;

    // retrieve config
    config = bpf_map_lookup_elem(&memDumpConfigMap, &configId);
    if (!config)
        return 0;
    userlandPid = config->userlandPid;

    // only respond to our controller
    if ((pidTid >> 32) != userlandPid)
        return 0;

    // retrieve map storage for event
    event = bpf_map_lookup_elem(&memDumpStorageMap, &cpuId);
    if (!event)
        return 0;

    if (config->type == skb) {
        // read size bytes from skb
        if (bpf_probe_read(event->data, config->size & (MAX_MEM_DUMP -1), args->skbaddr) != READ_OKAY) {
            return 0;
        }
        addr = args->skbaddr;
    } else {
        // first read address from skb
        addr = args->skbaddr + (uint64_t)config->addr;
        if (bpf_probe_read(&addr, sizeof(addr), args->skbaddr + (uint64_t)config->addr) != READ_OKAY) {
            return 0;
        }

        // then read the actual buffer
        if (bpf_probe_read(event->data, config->size & (MAX_MEM_DUMP -1), addr) != READ_OKAY) {
            return 0;
        }
    }


    event->type = config->type;
    event->addr = addr;
    event->size = config->size;

    bpf_perf_event_output((void *)args, &eventMap, BPF_F_CURRENT_CPU, event, sizeof(memDump));

    return 0;
}

char _license[] SEC("license") = "GPL";

