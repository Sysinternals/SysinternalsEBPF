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
// libsysinternalsEBPF.h
//
// SysinternalsEBPF API
//
//====================================================================

#ifndef LIBSYSINTERNALSEBPF_H
#define LIBSYSINTERNALSEBPF_H

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>


#define SYSCALL_MAX 335
#define EBPF_GENERIC_SYSCALL 0xFFFF

// error codes
#define E_EBPF_SUCCESS                 0
#define E_EBPF_CATASTROPHIC            1
#define E_EBPF_NOTSUPPORTED            2
#define E_EBPF_NOPROG                  3
#define E_EBPF_NOMAP                   4
#define E_EBPF_NOATTACH                5
#define E_EBPF_NORB                    6
#define E_EBPF_NOFILEPATH              7
#define E_EBPF_INVALIDPARAMS           8
#define E_EBPF_NOTP                    9
#define E_EBPF_NORTP                  10
#define E_EBPF_NOOTHTP                11
#define E_EBPF_NOLOAD                 12
#define E_EBPF_CONFIGFAIL             13
#define E_EBPF_MAPUPDATEFAIL          14
#define E_EBPF_NORAWSOCK              15

#define E_DISC_CATASTROPHIC         1001
#define E_DISC_NOTSUPPORTED         1002
#define E_DISC_NOPROG               1003
#define E_DISC_NOMAP                1004
#define E_DISC_NOATTACH             1005
#define E_DISC_NORB                 1006
#define E_DISC_NOPDEATH             1007
#define E_DISC_NOTASK               1008
#define E_DISC_GET_COMM             1009
#define E_DISC_PID_OFFSET           1010
#define E_DISC_START_TIME_OFFSET    1011
#define E_DISC_COMM_OFFSET          1012
#define E_DISC_CREDS_OFFSET         1013
#define E_DISC_PWD_PATH_OFFSET      1014
#define E_DISC_DENTRY_NAME_OFFSET   1015
#define E_DISC_DENTRY_PARENT_OFFSET 1016
#define E_DISC_DENTRY_INODE_OFFSET  1017
#define E_DISC_MOUNT_OFFSET         1018
#define E_DISC_FD_OFFSET            1019
#define E_DISC_TTY_OFFSET           1020
#define E_DISC_MM_OFFSET            1021
#define E_DISC_EXE_PATH_OFFSET      1022
#define E_DISC_SKBUFF_OFFSET        1023

typedef struct {
    int                             error;
    const char                      *str;
} eBPFerrorString;

typedef enum {
    MAP_UPDATE_CREATE,
    MAP_UPDATE_OVERWRITE,
    MAP_UPDATE_CREATE_OR_OVERWRITE
} ebpfUpdateMapMode;

//
// Specify a kernel version
//
typedef struct {
    const unsigned int              major;
    const unsigned int              minor;
} ebpfKernelVersion;

//
// Specify EBPF tracepoint enter and exit programs and the syscall they are for;
// use EBPF_GENERIC_SYSCALL for the syscall to attach 'programN' to every syscall,
// where N specifies number of input arguments from 0 to 7. Rather than assuming
// 'programN' exists in object, it assumes 'program0', 'program1', ... 'program6'
// exist in object. Note, the last character will be replaced with the number
// representing the number of arguments, so make sure it ends in 'N' or '#'!
//
typedef struct {
    const unsigned int              syscall;
    const char                      *program;
} ebpfSyscallTPprog;

//
// Specify EBPF raw tracepoint enter and exit programs and the syscalls they are
// for; use EBPF_GENERIC_SYSCALL for the syscall to attach regardless of whether
// a specific syscall is active or not. Specify multiple syscalls for the same
// program by placing each in a separate element, with the same program name
// but each with a different syscall. These must be collected together to
// prevent a program being attached more than once.
//
typedef struct {
    const char                      *program;
    const unsigned int              syscall;
} ebpfSyscallRTPprog;

//
// Specify non-syscall tracepoint programs and the tracepoint to attach them to;
// specify pseudo syscall to check against in the activeSyscall array; use
// EBPF_GENERIC_SYSCALL to attach regardless.  Specify multiple psuedo syscalls
// for the same program as per above.
//
typedef struct {
    const char                      *family;
    const char                      *tracepoint;
    const char                      *program;
    const unsigned int              pseudoSyscall;
} ebpfTracepointProg;

typedef struct {
    const char                      *filename;
    const ebpfKernelVersion         minKernel;
    const ebpfKernelVersion         lessthanKernel;
    const bool                      rawSyscallTracepoints;
    const unsigned int              numSyscallTPenterProgs;
    const ebpfSyscallTPprog         *syscallTPenterProgs;
    const unsigned int              numSyscallTPexitProgs;
    const ebpfSyscallTPprog         *syscallTPexitProgs;
    const unsigned int              numSyscallRTPenterProgs;
    const ebpfSyscallRTPprog        *syscallRTPenterProgs;
    const unsigned int              numSyscallRTPexitProgs;
    const ebpfSyscallRTPprog        *syscallRTPexitProgs;
    const bool                      *activeSyscalls;
    const unsigned int              numOtherTPprogs;
    const ebpfTracepointProg        *otherTPprogs;
} ebpfTelemetryObject;

typedef struct {
    const char                      *name;
    const unsigned int              numElements;
    const void                      **keys;
    const void                      **values;
} ebpfTelemetryMapObject;

typedef struct {
    const double                    bootSecSinceEpoch;
    const bool                      enableRawSockCapture;
    const unsigned int              numEBPFobjects;
    const ebpfTelemetryObject       *objects;
    const unsigned int              numDefaultPaths;
    const char                      **defaultPaths;
    const unsigned int              numMapObjects;
    const ebpfTelemetryMapObject    *mapObjects;
} ebpfTelemetryConfig;


//
// EventCallback and EventLostCallback handle the events produced by the perf
// ring buffer.
// TelemetryReadyCallback is called when the telemetry has been started.
// TelemetryReloadConfig is called when SIGHUP is received, *in between*
// handling events (e.g. it won't interrupt the EventCallback).
//
typedef void (EventCallback)(void *ctx, int cpu, void *data, uint32_t size);
typedef void (EventLostCallback)(void *ctx, int cpu, uint64_t lostCnt);
typedef void (TelemetryReadyCallback)(void);
typedef void (TelemetryReloadConfig)(void);

//
// telemetryCloseAll can be called to shut everything down.
// telemetrySignalInterrupt should be called when a signal is received, other
// than SIGHUP, to inform the polling loop to treat the abrupt (error) exit
// of epoll() as a non-error.
// telemetryUpdateSyscalls should be called to change which syscalls are
// active; expected to be called from telemetryReloadConfig.
// telemetryMapLookupElem, telemetryMapUpdateElem and telemetryMapDeleteElem are
// wrappers for the bpf map functions.
//

int telemetryStart(
    const ebpfTelemetryConfig *ebpfConfig,
    EventCallback *eventCb,
    EventLostCallback *eventsLostCb,
    TelemetryReadyCallback *telemetryReady,
    TelemetryReloadConfig *telemetryReloadConfig,
    void *context,
    const char *argv[],
    int *fds
    );
const char *eBPFstrerror(int error);
void telemetryCloseAll(void);
void telemetrySignalInterrupt(int code);
void telemetryUpdateSyscalls(bool *activeSyscalls);
long telemetryMapLookupElem(int fd, const void *key, void *value);
long telemetryMapUpdateElem(int fd, const void *key, const void *value, ebpfUpdateMapMode mode);
long telemetryMapDeleteElem(int fd, const void *key);

bool fileExists(const char *filepath);
bool dirExists(const char *dirpath);
bool createDir(const char *dir, mode_t perms);
bool dropFile(const char *filepath, const char *start, const char *end, bool force, mode_t perms);


#endif

