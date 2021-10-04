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
// sysinternalsEBPF.h
//
// Defines needed by SysinternalsEBPF.
//
//====================================================================

#ifndef SYSINTERNALS_EBPF_H
#define SYSINTERNALS_EBPF_H

#include "sysinternalsEBPFshared.h"

#define SYSINTERNALS_EBPF_INSTALL_DIR "/opt/sysinternalsEBPF"
#define CONFIG_FILE SYSINTERNALS_EBPF_INSTALL_DIR "/sysinternalsEBPF_offsets.conf"
#define OFFSETS_DB_FILE SYSINTERNALS_EBPF_INSTALL_DIR "/offsets.json"

// if we don't receive an event within the RESTART_TIMEOUT, we restart
#define RESTART_TIMEOUT 300

#define EBPF_RAW_SOCK_OBJ "sysinternalsEBPFrawSock.o"

#define MAP_PAGE_SIZE (16 * 1024)
#define DEBUGFS "/sys/kernel/debug/tracing/"

#ifndef STOPLOOP
    #define STOPLOOP 0
#endif

#define SYSINTERNALS_EBPF_UMASK 077

#define SYSCALL_MAX 335
#define SYSCALL_NAME_LEN 64

#define MAX_MEM_DUMP 32768

#endif
