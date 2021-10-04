/*
    SysinternalsEBPF

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

//====================================================================
//
// sysinternalsEBPFshared.h
//
// Header file shared between eBPF programs and userland.
//
//====================================================================

#ifndef SYSINTERNALS_EBPF_SHARED_H
#define SYSINTERNALS_EBPF_SHARED_H

#include <stdbool.h>
#include <stdint.h>
#include <sysinternalsEBPFoffsets.h>

//
// Return values
//
#define READ_OKAY 0
#define UPDATE_OKAY 0

#define NUM_ARGS 6

#define SYSCALL_ARRAY_SIZE 512

#define PERF_ERRORS_MAX 1024 // power of 2
#define PERF_ERRORS_READ_INDEX PERF_ERRORS_MAX // store indicies after values
#define PERF_ERRORS_WRITE_INDEX (PERF_ERRORS_READ_INDEX + 1)

//
// Configuration
//
typedef struct {
    unsigned int        userlandPid;
    bool                active[SYSCALL_ARRAY_SIZE]; // which syscalls are active
    uint64_t            bootNsSinceEpoch;
    Offsets             offsets;
} ebpfConfig;

//
// Perf error reports
//
typedef struct {
    union {
        long            error;
        uint32_t        index;
    };
    uint64_t            time;
} perfError;


#endif
