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
// discoverOffsets.cpp
//
// Use eBPF to find kernel struct offsets via memory forensics.
//
//====================================================================

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <libbpf.h>
#include <bpf.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <signal.h>
#include <semaphore.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include "hexdump.h"
#include "libsysinternalsEBPF.h"
#include "sysinternalsEBPF.h"
#include "discoverOffsets.h"

#define MAP_PAGE_SIZE (16 * 1024)
#define DEBUGFS "/sys/kernel/debug/tracing/"

#define KERN_MEM_DUMP_OBJ "sysinternalsEBPFmemDump.o"

#define TEMPDIR_MODE 0700
#define TEMPUID 12345
#define TEMPGID 67890
#define LOGINUID_FILE "/proc/self/loginuid"
#define SESSIONID_FILE "/proc/self/sessionid"
#define EXEPATH_FILE "/proc/self/exe"
#define COMM_FILE "/proc/self/comm"
#define PDEATH_SIG SIGUSR1
#define TMPDIR1 "/tmp/"
#define TMPDIR2 "sysinternalsEBPFtmp"
#define SEM_NAME "/sysinternalsEBPF-getoffsets"

#define MIN_SAMPLE_SIZE 16
#define MAX_POINTER_DIFF (1L << 36)

#define RINGBUF_TIMEOUT 10 // milliseconds to wait for an event in the ring buffer
#define RINGBUF_REPEAT 10 // number of times to poll ring buffer to wait for an event

#define DUMP_SIZE 4096 // this is rather arbitrary but needs to be large enough to
                       // accommodate each of the structs
#define COMM_LEN 16

#define UDP_ADDR "127.0.0.1"
#define UDP_PORT 60606

enum            direction {forwards, backwards};

extern double   g_bootSecSinceEpoch;

static int      eventMapFd                  = 0;
static int      configMapFd                 = 0;
static struct   bpf_object  *bpfObj         = NULL;

static struct   bpf_program *bpfSysExit     = NULL;
static struct   bpf_program *bpfConsumeSkb  = NULL;

static struct   bpf_link *bpfSysExitLink    = NULL;
static struct   bpf_link *bpfConsumeSkbLink = NULL;

bool            stopping                    = false;
pid_t           thisPid                     = 0;

const char      tmpdir[]                    = TMPDIR1 TMPDIR2;
const char      *sysinternalsEBPFtmp        = tmpdir + strlen(TMPDIR1);
time_t          creation_time               = 0;

char            *memDumps[MAX_MEM_DUMP_TYPE];
uint64_t        memAddrs[MAX_MEM_DUMP_TYPE];
uint32_t        memSizes[MAX_MEM_DUMP_TYPE];

//--------------------------------------------------------------------
//
// memDumpEventCb
//
// Callback for receiving memory dumps from the kernel space.
//
//--------------------------------------------------------------------
static void memDumpEventCb(void *ctx, int cpu, void *data, __u32 size)
{
    if (data == NULL) {
        logMessage("memDumpEventCb invalid params\n");
        return;
    }

    memDump *d = NULL;
    if (size > MIN_SAMPLE_SIZE) {
        d = (memDump *)data;
        if (memDumps[d->type] != NULL) {
            free(memDumps[d->type]);
        }
        memDumps[d->type] = (char *)malloc(d->size);
        if (memDumps[d->type] == NULL) {
            logMessage("Out of memory\n");
            exit(1);
        }
        memcpy(memDumps[d->type], d->data, d->size);
        memSizes[d->type] = d->size;
        memAddrs[d->type] = (uint64_t)d->addr;
        stopping = true;
    }
}

//--------------------------------------------------------------------
//
// memDumpCloseAll
//
// Free all memory dumps and close down eBPF programs.
//
//--------------------------------------------------------------------
void memDumpCloseAll()
{
    for (int i=0; i<MAX_MEM_DUMP_TYPE; i++) {
        if (memDumps[i] != NULL) {
            free(memDumps[i]);
        }
    }
    bpf_link__destroy(bpfSysExitLink);
    bpf_link__destroy(bpfConsumeSkbLink);
    bpf_object__close(bpfObj);
}

//--------------------------------------------------------------------
//
// isPointer
//
// Checks if value is a pointer by comparing it with the address of
// the task struct.
//
//--------------------------------------------------------------------
bool isPointer(uint64_t ptr)
{
    if (labs(ptr - memAddrs[task]) < MAX_POINTER_DIFF) {
        return true;
    } else {
        return false;
    }
}

//--------------------------------------------------------------------
//
// near
//
// Checks if the difference between two values is within the specified
// range.
//
//--------------------------------------------------------------------
bool near(uint64_t a, uint64_t b, uint64_t range)
{
    if (labs(a - b) <= range) {
        return true;
    } else {
        return false;
    }
}

//--------------------------------------------------------------------
//
// align
//
// Aligns an offset to a particular alignment in the specified
// direction.
//
//--------------------------------------------------------------------
unsigned int align(unsigned int offset, unsigned int a,
        enum direction dir)
{
    unsigned int mod = offset % a;
    if (mod == 0) {
        return offset;
    }

    if (dir == forwards) {
        offset += a;
    }

    return offset - mod;
}

//--------------------------------------------------------------------
//
// get16
//
// Retrieves the unsigned 16 bit int from the given offset of the
// named memory dump.
//
//--------------------------------------------------------------------
uint16_t get16(enum memDumpType type, uint32_t offset)
{
    if (offset >= memSizes[type]) {
        logMessage("get16 invalid params\n");
        return 0;
    }

    return *(uint16_t *)&memDumps[type][offset];
}

//--------------------------------------------------------------------
//
// get32
//
// Retrieves the unsigned 32 bit int from the given offset of the
// named memory dump.
//
//--------------------------------------------------------------------
uint32_t get32(enum memDumpType type, uint32_t offset)
{
    if (offset >= memSizes[type]) {
        logMessage("get32 invalid params\n");
        return 0;
    }

    return *(uint32_t *)&memDumps[type][offset];
}

//--------------------------------------------------------------------
//
// get64
//
// Retrieves the unsigned 64 bit int from the given offset of the
// named memory dump.
//
//--------------------------------------------------------------------
uint64_t get64(enum memDumpType type, uint32_t offset)
{
    if (offset >= memSizes[type]) {
        logMessage("get64 invalid params\n");
        return 0;
    }

    return *(uint64_t *)&memDumps[type][offset];
}

//--------------------------------------------------------------------
//
// numElements
//
// Check whether there are enough elements remaining in buffer and
// return proprosed number if there are, or the number available if
// not.
//
//--------------------------------------------------------------------
uint32_t numElements(uint32_t proposed, enum memDumpType type,
        enum direction dir, uint32_t offset, uint32_t elementSize)
{
    if (dir == forwards) {
        if (proposed * elementSize < memSizes[type] - offset) {
            return proposed;
        } else {
            return (memSizes[type] - offset) / elementSize;
        }
    } else {
        if (proposed * elementSize < offset) {
            return proposed;
        } else {
            return offset / elementSize;
        }
    }
}

//--------------------------------------------------------------------
//
// searchUint16
//
// Searches the named memory dump in the given direction from the
// given offset (16 bit aligned), for a 16 bit value that is within
// the given difference of the given target, over a maximum of given
// 16 bit elements.
//
//--------------------------------------------------------------------
bool searchUint16(unsigned int *out, enum direction dir,
        enum memDumpType type, uint32_t startOffset, uint32_t numElem,
        uint16_t target, uint16_t diff)
{
    if (out == NULL) {
        logMessage("searchUint16 invalid params\n");
        return false;
    }

    numElem = numElements(numElem, type, dir, startOffset, sizeof(uint16_t));
    startOffset = align(startOffset, sizeof(uint16_t), dir);
    uint32_t mod = numElem * sizeof(uint16_t);
    uint32_t step = sizeof(uint32_t);
    if (dir == backwards) {
        mod = -mod;
        step = -step;
    }
    for (uint32_t i = startOffset; i != startOffset + mod; i += step) {
        if (near(get16(type, i), target, diff)) {
            out[0] = i;
            out[1] = -1;
            return true;
        }
    }
    return false;
}

//--------------------------------------------------------------------
//
// searchUint32
//
// Searches the named memory dump in the given direction from the
// given offset (32 bit aligned), for a 32 bit value that is within
// the given difference of the given target, over a specified maximum
// number of 32 bit elements.
//
//--------------------------------------------------------------------
bool searchUint32(unsigned int *out, enum direction dir,
        enum memDumpType type, uint32_t startOffset, uint32_t numElem,
        uint32_t target, uint32_t diff)
{
    if (out == NULL) {
        logMessage("searchUint32 invalid params\n");
        return false;
    }

    numElem = numElements(numElem, type, dir, startOffset, sizeof(uint32_t));
    startOffset = align(startOffset, sizeof(uint32_t), dir);
    uint32_t mod = numElem * sizeof(uint32_t);
    uint32_t step = sizeof(uint32_t);
    if (dir == backwards) {
        mod = -mod;
        step = -step;
    }
    for (uint32_t i = startOffset; i != startOffset + mod; i += step) {
        if (near(get32(type, i), target, diff)) {
            out[0] = i;
            out[1] = -1;
            return true;
        }
    }
    return false;
}

//--------------------------------------------------------------------
//
// searchUin64
//
// Searches the named memory dump in the given direction from the
// given offset (64 bit aligned), for a 64 bit value that is within
// the given difference of the given target, over a specified maximum
// number of 64 bit elements.
//
//--------------------------------------------------------------------
bool searchUint64(unsigned int *out, enum direction dir,
        enum memDumpType type, uint32_t startOffset, uint32_t numElem,
        uint64_t target, uint64_t diff)
{
    if (out == NULL) {
        logMessage("searchUint64 invalid params\n");
        return false;
    }

    numElem = numElements(numElem, type, dir, startOffset, sizeof(uint64_t));
    startOffset = align(startOffset, sizeof(uint64_t), dir);
    uint32_t mod = numElem * sizeof(uint64_t);
    uint32_t step = sizeof(uint64_t);
    if (dir == backwards) {
        mod = -mod;
        step = -step;
    }
    for (uint32_t i = startOffset; i != startOffset + mod; i += step) {
        if (near(get64(type, i), target, diff)) {
            out[0] = i;
            out[1] = -1;
            return true;
        }
    }
    return false;
}

//--------------------------------------------------------------------
//
// searchPtr
//
// Searches the named memory dump in the given direction from the
// given offset (64 bit aligned), for a 64 bit value that is
// considered to be a pointer, over a specified maximum number of 64
// bit elements.
//
//--------------------------------------------------------------------
bool searchPtr(unsigned int *out, enum direction dir,
        enum memDumpType type, uint32_t startOffset, uint32_t numElem)
{
    if (out == NULL) {
        logMessage("searchPtr invalid params\n");
        return false;
    }

    return searchUint64(out, dir, type, startOffset, numElem, memAddrs[task], MAX_POINTER_DIFF);
}

//--------------------------------------------------------------------
//
// searchStr
//
// Searches the named memory dump in the given direction from the
// given offset, for a given string, over a specified number of bytes.
//
//--------------------------------------------------------------------
bool searchStr(unsigned int *out, enum direction dir,
        enum memDumpType type, uint32_t startOffset, uint32_t numElem,
        const char *target)
{
    if (out == NULL || target == NULL) {
        logMessage("searchStr invalid params\n");
        return false;
    }

    numElem = numElements(numElem, type, dir, startOffset, sizeof(char));
    uint32_t mod = numElem;
    uint32_t step = 1;
    if (dir == backwards) {
        mod = -mod;
        step = -step;
    }
    for (uint32_t i = startOffset; i != startOffset + mod; i+= step) {
        if (strcmp(&memDumps[type][i], target) == 0) {
            out[0] = i;
            out[1] = -1;
            return true;
        }
    }
    return false;
}

//--------------------------------------------------------------------
//
// setConfigPid
//
// Set the config map to specify the kernel memory to dump for the
// specified process.
// Note, addr can be NULL.
//
//--------------------------------------------------------------------
bool setConfigPid(pid_t pid, enum memDumpType type, const void *addr,
        unsigned int size)
{
    unsigned int configEntry = 0;
    memDumpConfig config;

    config.userlandPid = pid;
    config.type = type;
    config.addr = addr;
    config.size = size;

    if (bpf_map_update_elem(configMapFd, &configEntry, &config, BPF_ANY)) {
        logMessage("ERROR: failed to set config: '%s'\n", strerror(errno));
        return false;
    }
    return true;
}

//--------------------------------------------------------------------
//
// setConfig
//
// Set the config map to specify the kernel memory to dump for the
// current process.
// Note, addr can be NULL.
//
//--------------------------------------------------------------------
bool setConfig(enum memDumpType type, const void *addr,
        unsigned int size)
{
    return setConfigPid(thisPid, type, addr, size);
}

//--------------------------------------------------------------------
//
// triggerTp
//
// Trigger the tracepoint to call the EBPF program.
//
//--------------------------------------------------------------------
void triggerTp()
{
    struct utsname unameTmp = { 0 };

    uname(&unameTmp);
}

//--------------------------------------------------------------------
//
// getMem
//
// Poll the perf ring buffer to receive the memory dump.
//
//--------------------------------------------------------------------
bool getMem(enum memDumpType type, struct perf_buffer *pb)
{
    stopping = false;
    unsigned int i = 0;

    if (pb == NULL)
        return false;

    while (!stopping && perf_buffer__poll(pb, RINGBUF_TIMEOUT) >= 0 && i < RINGBUF_REPEAT) {
        usleep(1000); // 1ms
        i++;
    }

    if (memDumps[type] == NULL) {
        return false;
    }
    return true;
}

//--------------------------------------------------------------------
//
// dumpStructPid
//
// Request memory dump from specified process.
// Note, addr can be NULL.
//
//--------------------------------------------------------------------
bool dumpStructPid(pid_t pid, enum memDumpType type, const void *addr,
        unsigned int size, struct perf_buffer *pb)
{
    // dump target struct
    if (!setConfigPid(pid, type, addr, size)) {
        return false;
    }

    triggerTp();

    if (!getMem(type, pb)) {
        return false;
    }
    return true;
}

//--------------------------------------------------------------------
//
// dumpStruct
//
// Request memory dump from current process.
// Note, addr can be NULL.
//
//--------------------------------------------------------------------
bool dumpStruct(enum memDumpType type, const void *addr,
        unsigned int size, struct perf_buffer *pb)
{
    return dumpStructPid(thisPid, type, addr, size, pb);
}

//--------------------------------------------------------------------
//
// searchDerefUint32
//
// Searches the first named memory dump in the given direction from
// the given offset (64 bit aligned), for a pointer, over a specified
// maximum number of 64 bit elements, which is then dumped as the
// second named memory dump, and the 32 bit value at the specified
// offset within it is checked whether it is within the given
// difference of the given target.
//
//--------------------------------------------------------------------
bool searchDerefUint32(unsigned int *out, enum direction dir,
        struct perf_buffer *pb, enum memDumpType from,
        enum memDumpType to, uint64_t startOffset, uint64_t numElem,
        uint32_t secondOffset, uint32_t target, uint32_t diff)
{
    if (out == NULL || pb == NULL) {
        logMessage("searchDerefUint32 invalid params\n");
        return false;
    }

    unsigned int off[2];

    if (!searchPtr(off, dir, from, startOffset, numElem)) {
        logMessage("Did not find pointer\n");
        return false;
    }

    if (memDumps[to] == NULL) {
        if (!dumpStruct(to, (void *)get64(from, off[0]), DUMP_SIZE, pb)) {
            logMessage("Did not get struct memory\n");
            return false;
        }
    }

    if (near(get32(to, secondOffset), target, diff)) {
        out[0] = off[0];
        out[1] = secondOffset;
        out[2] = -1;
        return true;
    } else {
        return false;
    }
}

//--------------------------------------------------------------------
//
// printOffset
//
// Print the specified number of offsets parameters for the given
// named offset array.
//
//--------------------------------------------------------------------
void printOffset(const char *name, const unsigned int *o, int num)
{
#if 0
    if (name == NULL || o == NULL) {
        logMessage("printOffset invalid params\n");
        return;
    }

    logMessage("%s = ", name);
    for (int i=0; i<num; i++) {
        logMessage("%d, ", o[i]);
    }
    logMessage("\n");
#endif
}

//--------------------------------------------------------------------
//
// getPidOffset
//
// Get the PID, parent and parent PID offsets.
//
//--------------------------------------------------------------------
bool getPidOffset(Offsets *offsets, struct perf_buffer *pb)
{
    if (offsets == NULL || pb == NULL) {
        logMessage("getPidOffset invalid params\n");
        return false;
    }

    // search for TID and PID
    if (searchUint32(offsets->pid, forwards, task, 0, memSizes[task] / sizeof(uint32_t), thisPid, 0)) {
        // first match is the TID; PID follows
        offsets->pid[0] += sizeof(uint32_t);
        printOffset("pid", offsets->pid, 2);
    } else {
        logMessage("pid offset not found\n");
        return false;
    }

    // real_parent should be the next pointer - certainly within 32 uint64_ts
    // confirm by checking PPID against parent->pid
    if (searchDerefUint32(offsets->ppid, forwards, pb, task, ptask, offsets->pid[0] + sizeof(uint32_t), 32,
            offsets->pid[0], getppid(), 0)) {
        offsets->parent[0] = offsets->ppid[0];
        printOffset("parent", offsets->parent, 2);
        printOffset("ppid", offsets->ppid, 3);
        return true;
    } else {
        logMessage("parent offset not found\n");
        return false;
    }
}

//--------------------------------------------------------------------
//
// getStartTimeOffset
//
// Get the start_bootime offset.
//
//--------------------------------------------------------------------
bool getStartTimeOffset(Offsets *offsets, time_t procStartTime)
{
    if (offsets == NULL) {
        logMessage("getStartTimeOffset invalid params\n");
        return false;
    }

    if (offsets->parent[0] == -1) {
        return false;
    }

    // find start_time (nanoseconds since boot) by searching forwards
    const time_t startTimeGuess = (procStartTime - (long)g_bootSecSinceEpoch) * 1000 * 1000 * 1000;
    if (searchUint64(offsets->start_time, forwards, task, offsets->parent[0] + sizeof(uint64_t), 128, startTimeGuess,
            2 * 1000 * 1000 * 1000)) {
        // first match is start_time; start_boottime / real_start_time (includes time in suspend) follows
        offsets->start_time[0] += sizeof(uint64_t);
        printOffset("start_time", offsets->start_time, 2);
        return true;
    } else {
        logMessage("start_time offset not found\n");
        return false;
    }
}

//--------------------------------------------------------------------
//
// getCommOffset
//
// Get the comm offset.
//
//--------------------------------------------------------------------
bool getCommOffset(Offsets *offsets, const char *comm)
{
    if (offsets == NULL || comm == NULL) {
        logMessage("getCommOffset invalid params\n");
        return false;
    }

    if (offsets->start_time[0] == -1) {
        return false;
    }

    // find comm by searching forwards
    if (searchStr(offsets->comm, forwards, task, offsets->start_time[0] + sizeof(uint64_t), 1024, comm)) {
        printOffset("comm", offsets->comm, 2);
        return true;
    } else {
        logMessage("comm offset not found\n");
        return false;
    }
}

//--------------------------------------------------------------------
//
// getCredsOffsets
//
// Get the creds offsets.
//
//--------------------------------------------------------------------
bool getCredsOffsets(Offsets *offsets, struct perf_buffer *pb)
{
    if (offsets == NULL || pb == NULL) {
        logMessage("getCredOffsets invalid param\n");
        return false;
    }

    sem_t *sem = NULL;

    if (offsets->comm[0] == -1) {
        return false;
    }

    // find cred struct by searching backwards
    // real_cred and cred both point to the same struct
    offsets->cred[0] = -1;
    uint64_t startOffset = offsets->comm[0] - sizeof(uint64_t);
    while (offsets->cred[0] == -1) {
        if (!searchPtr(offsets->cred, backwards, task, startOffset, 32)) {
            logMessage("cred offset not found\n");
            return false;
        }
        if (get64(task, offsets->cred[0]) != get64(task, offsets->cred[0] - sizeof(uint64_t))) {
            startOffset = offsets->cred[0] - sizeof(uint64_t);
            offsets->cred[0] = -1;
        }
    }
    if (offsets->cred[0] != -1) {
        printOffset("cred", offsets->cred, 2);
    } else {
        logMessage("cred offset not found\n");
        return false;
    }

    // save the task info
    const char *myTask = memDumps[task];
    uint64_t myAddr = memAddrs[task];
    uint32_t mySize = memSizes[task];
    memDumps[task] = NULL;
    memAddrs[task] = 0;
    memSizes[task] = 0;

    sem_unlink(SEM_NAME);

    pid_t child = fork();
    if (child == -1) {
        logMessage("Cannot fork to get cred struct\n");
        return false;
    }

    if (child == 0) {
        // set child process creds to known values and trigger EBPF program
        if(setgid(TEMPGID) < 0)
        {
            logMessage("Failed in call to setgid\n");
            exit(1);
        }

        if(setuid(TEMPUID) < 0)
        {
            logMessage("Failed in call to setuid\n");
            exit(1);
        }

        // create semaphore
        sem = sem_open(SEM_NAME, O_CREAT | O_EXCL, S_IRUSR | S_IWUSR, 0);
        if (sem == SEM_FAILED) {
            logMessage("Child cannot create semaphore\n");
            exit(1);
        }
        sem_wait(sem);
        triggerTp();
        sem_wait(sem);
        triggerTp();

        exit(0);
    }

    while ((sem = sem_open(SEM_NAME, 0)) == SEM_FAILED) {
        usleep(1000);
    }

    if (!setConfigPid(child, task, 0, DUMP_SIZE)) {
        logMessage("Cannot set config for child for task\n");
        return false;
    }

    sem_post(sem);

    if (!getMem(task, pb)) {
        logMessage("Did not get child task struct\n");
        return false;
    }

    if (!setConfigPid(child, cred, (void *)get64(task, offsets->cred[0]), DUMP_SIZE)) {
        logMessage("Cannot set config for child for cred\n");
        return false;
    }

    sem_post(sem);

    if (!getMem(cred, pb)) {
        logMessage("Did not get child cred struct\n");
        return false;
    }

    // cred struct starts with 32-bit atomic_t, then optional debug info,
    // then UID, GID, SUID, SGID, EUID, EGID, etc
    if (searchUint32(offsets->cred_uid, forwards, cred, 0, memSizes[cred] / sizeof(uint32_t), TEMPUID, 0)) {
        printOffset("cred_uid", offsets->cred_uid, 2);
    } else {
        return false;
    }

    // could search and confirm, but expectation is that any new cred types will be added
    // after existing ones, and that the existing order won't change

    offsets->cred_gid[0] = offsets->cred_uid[0] + sizeof(uint32_t);
    offsets->cred_suid[0] = offsets->cred_gid[0] + sizeof(uint32_t);
    offsets->cred_sgid[0] = offsets->cred_suid[0] + sizeof(uint32_t);
    offsets->cred_euid[0] = offsets->cred_sgid[0] + sizeof(uint32_t);
    offsets->cred_egid[0] = offsets->cred_euid[0] + sizeof(uint32_t);
    offsets->cred_fsuid[0] = offsets->cred_egid[0] + sizeof(uint32_t);
    offsets->cred_fsgid[0] = offsets->cred_fsuid[0] + sizeof(uint32_t);
    printOffset("cred_gid", offsets->cred_gid, 2);
    printOffset("cred_suid", offsets->cred_suid, 2);
    printOffset("cred_sgid", offsets->cred_sgid, 2);
    printOffset("cred_euid", offsets->cred_euid, 2);
    printOffset("cred_egid", offsets->cred_egid, 2);
    printOffset("cred_fsuid", offsets->cred_fsuid, 2);
    printOffset("cred_fsgid", offsets->cred_fsgid, 2);

    free(memDumps[task]);
    memDumps[task] = (void *)myTask;
    memAddrs[task] = myAddr;
    memSizes[task] = mySize;

    sem_unlink(SEM_NAME);
    kill(child, SIGHUP);

    return true;
}

//--------------------------------------------------------------------
//
// getPwdPathOffset
//
// Get pwd path offset.
//
//--------------------------------------------------------------------
bool getPwdPathOffset(Offsets *offsets, struct perf_buffer *pb,
        size_t commLen)
{
    if (offsets == NULL || pb == NULL) {
        logMessage("getPwdPathOffset invalid params\n");
        return false;
    }

    if (offsets->comm[0] == -1) {
        return false;
    }

    // after comm there are optional semaphore pointers, which will point to themselves or
    // very nearby as we haven't enabled any, and optional counters, that don't look like pointers,
    // followed by the pointer to the fs struct
    uint32_t startOffset = align(offsets->comm[0] + commLen, sizeof(uint64_t), forwards);

    while (!isPointer(get64(task, startOffset)) || near(get64(task, startOffset), memAddrs[task] + startOffset, 32)) {
        startOffset += sizeof(uint64_t);
    }

    offsets->pwd_path[0] = startOffset;

    if (!dumpStruct(fs, (void *)get64(task, startOffset), DUMP_SIZE, pb)) {
        logMessage("Could not dump fs struct\n");
        return false;
    }

    // fs struct contains various values, followed by 2 (embedded) struct paths,
    // the first for the root fs and the second for the pwd. A struct path consists
    // of 2 pointers, one to the vfsmount and one to the dentry.
    if (searchPtr(&offsets->pwd_path[1], forwards, fs, 0, memSizes[fs] / sizeof(uint64_t))) {
        if (isPointer(get64(fs, offsets->pwd_path[1])) &&
                isPointer(get64(fs, offsets->pwd_path[1] + sizeof(uint64_t))) &&
                isPointer(get64(fs, offsets->pwd_path[1] + (2 * sizeof(uint64_t)))) &&
                isPointer(get64(fs, offsets->pwd_path[1] + (3 * sizeof(uint64_t))))) {
            offsets->pwd_path[1] = offsets->pwd_path[1] + (2 * sizeof(uint64_t));
            printOffset("pwd_path", offsets->pwd_path, 3);
        }  else {
            logMessage("pwd_path offset not found (1)\n");
            logMessage("pwd_path[0] = %d\n", offsets->pwd_path[0]);
            logMessage("0 = 0x%016lx\n", get64(fs, offsets->pwd_path[1]));
            logMessage("1 = 0x%016lx\n", get64(fs, offsets->pwd_path[1] + sizeof(uint64_t)));
            logMessage("2 = 0x%016lx\n", get64(fs, offsets->pwd_path[1] + (2 * sizeof(uint64_t))));
            logMessage("3 = 0x%016lx\n", get64(fs, offsets->pwd_path[1] + (3 * sizeof(uint64_t))));
            return false;
        }
    } else {
        logMessage("pwd_path offset not found (2)\n");
        return false;
    }

    offsets->path_vfsmount[0] = 0;
    printOffset("path_vfsmount", offsets->path_vfsmount, 2);
    offsets->path_dentry[0] = sizeof(uint64_t);
    printOffset("path_dentry", offsets->path_dentry, 2);
    return true;
}

//--------------------------------------------------------------------
//
// getDentryNameOffset
//
// Get the dentry name offset.
//
//--------------------------------------------------------------------
bool getDentryNameOffset(Offsets *offsets, struct perf_buffer *pb)
{
    if (offsets == NULL || pb == NULL) {
        logMessage("getDentryNameOffset invalid params\n");
        return false;
    }

    if (offsets->pwd_path[1] == -1 || offsets->path_dentry[0] == -1) {
        return false;
    }

    if (!dumpStruct(dentry, (void *)get64(fs, offsets->pwd_path[1] + offsets->path_dentry[0]), DUMP_SIZE, pb)) {
        logMessage("Could not dump dentry struct\n");
        return false;
    }

    uint32_t startOffset;

    // search for dentry iname (short name)
    if (searchStr(offsets->dentry_iname, forwards, dentry, 0, memSizes[dentry], sysinternalsEBPFtmp)) {
        // search backwards for the qstr struct
        for (startOffset = align(offsets->dentry_iname[0] - sizeof(char), sizeof(uint64_t), backwards); startOffset >= 0;
                startOffset -= sizeof(uint64_t)) {
            if (!isPointer(get64(dentry, startOffset))) {
                offsets->dentry_name[0] = startOffset + sizeof(uint64_t);
                break;
            }
        }
        if (offsets->dentry_name[0] != -1) {
            // check it is the name
            if (!dumpStruct(pwd, (void *)get64(dentry, offsets->dentry_name[0]), DUMP_SIZE, pb)) {
                logMessage("Could not dump pwd\n");
                return false;
            }
            if (strcmp(sysinternalsEBPFtmp, memDumps[pwd]) == 0) {
                printOffset("dentry_iname", offsets->dentry_iname, 2);
                printOffset("dentry_name", offsets->dentry_name, 2);
                return true;
            } else {
                logMessage("dentry_name offset not found\n");
                return false;
            }
        } else {
            logMessage("dentry_name offset not found\n");
            return false;
        }
    } else {
        logMessage("dentry_name offset not found\n");
        return false;
    }
}

//--------------------------------------------------------------------
//
// getDentryParentOffset
//
// Get the dentry parent offset.
//
//--------------------------------------------------------------------
bool getDentryParentOffset(Offsets *offsets)
{
    if (offsets == NULL) {
        logMessage("getDentryParentOffset invalid params\n");
        return false;
    }

    if (offsets->dentry_name[0] == -1) {
        return false;
    }

    // search backwards from dentry name to find dentry parent
    if (searchPtr(offsets->dentry_parent, backwards, dentry, offsets->dentry_name[0] - sizeof(uint64_t),
            offsets->dentry_name[0] - sizeof(uint64_t) / sizeof(uint64_t))) {
        printOffset("dentry_parent", offsets->dentry_parent, 2);
        return true;
    } else {
        logMessage("dentry_parent offset not found\n");
        return false;
    }
}

//--------------------------------------------------------------------
//
// getDentryInodeOffsets
//
// Get the dentry inode offsets.
//
//--------------------------------------------------------------------
bool getDentryInodeOffsets(Offsets *offsets, struct perf_buffer *pb)
{
    if (offsets == NULL || pb == NULL) {
        logMessage("getDentryInodeOffsets invalid params\n");
        return false;
    }

    if (offsets->dentry_name[0] == -1) {
        return false;
    }

    // search forwards to find inode
    if (searchPtr(offsets->dentry_inode, forwards, dentry, offsets->dentry_name[0] + sizeof(uint64_t),
            (memSizes[dentry] - offsets->dentry_name[0] - sizeof(uint64_t)) / sizeof(uint64_t))) {
        printOffset("dentry_inode", offsets->dentry_inode, 2);
    } else {
        logMessage("dentry_inode offset not found\n");
        return false;
    }

    if (!dumpStruct(inode, (void *)get64(dentry, offsets->dentry_inode[0]), DUMP_SIZE, pb)) {
        logMessage("Could not dump inode struct\n");
        return false;
    }

    // search forwards to find inode mode
    if (searchUint16(offsets->inode_mode, forwards, inode, 0, memSizes[inode] / sizeof(uint16_t),
            __S_IFDIR | TEMPDIR_MODE, 0)) {
        printOffset("inode_mode", offsets->inode_mode, 2);
    } else {
        logMessage("inode_mode offset not found\n");
        return false;
    }

    // search forwards to find inode uid
    if (searchUint32(offsets->inode_ouid, forwards, inode, 0, memSizes[inode] / sizeof(uint32_t),
            TEMPUID, 0)) {
        printOffset("inode_ouid", offsets->inode_ouid, 2);
    } else {
        logMessage("inode_ouid offset not found\n");
        return false;
    }

    // search forwards to find inode gid
    if (searchUint32(offsets->inode_ogid, forwards, inode, 0, memSizes[inode] / sizeof(uint32_t),
            TEMPGID, 0)) {
        printOffset("inode_ogid", offsets->inode_ogid, 2);
    } else {
        logMessage("inode_ogid offset not found\n");
        return false;
    }

    // search forwards to find the atime
    if (searchUint64(offsets->inode_atime, forwards, inode, 0, memSizes[inode] / sizeof(uint64_t),
            creation_time, 1)) {
        printOffset("inode_atime", offsets->inode_atime, 2);
    } else {
        logMessage("inode_atime offset not found\n");
        return false;
    }

    // search forwards to find the mtime
    if (searchUint64(offsets->inode_mtime, forwards, inode, offsets->inode_atime[0] + sizeof(uint64_t),
            memSizes[inode] / sizeof(uint64_t), creation_time, 1)) {
        printOffset("inode_mtime", offsets->inode_mtime, 2);
    } else {
        logMessage("inode_mtime offset not found\n");
        return false;
    }

    // search forwards to find the ctime
    if (searchUint64(offsets->inode_ctime, forwards, inode, offsets->inode_mtime[0] + sizeof(uint64_t),
            memSizes[inode] / sizeof(uint64_t), creation_time, 1)) {
        printOffset("inode_ctime", offsets->inode_ctime, 2);
    } else {
        logMessage("inode_ctime offset not found\n");
        return false;
    }

    return true;
}

//--------------------------------------------------------------------
//
// getMountOffsets
//
// Get the mount offsets.
//
//--------------------------------------------------------------------
bool getMountOffsets(Offsets *offsets, struct perf_buffer *pb)
{
    if (offsets == NULL || pb == NULL) {
        logMessage("getMountOffsets invalid params\n");
        return false;
    }

    uint32_t startOffset;

    if (offsets->pwd_path[1] == -1 || offsets->path_vfsmount[0] == -1) {
        return false;
    }

    // dump the memory from before the vfsmount struct so we can back up and find the mount struct
    // (all vfsmount structs live inside a mount struct)
    if (!dumpStruct(mount, (void *)get64(fs, offsets->pwd_path[1] + offsets->path_vfsmount[0]) - 512,
            DUMP_SIZE, pb)) {
        logMessage("Could not dump mount struct\n");
        return false;
    }

    // assumption is that pointer before vfsmount is the mountpoint dentry pointer; one before that
    // is the parent mount struct pointer, and two before that are hash list pointers
    if (!searchPtr(offsets->mount_mountpoint, backwards, mount, 512 - sizeof(uint64_t),
            512 - sizeof(uint64_t))) {
        logMessage("mount_mountpoint offset not found\n");
        return false;
    }

    if (!dumpStruct(dentryMountpoint, (void *)get64(mount, offsets->mount_mountpoint[0]), DUMP_SIZE, pb)) {
        logMessage("Could not dump parent dentry struct\n");
        return false;
    }

    // the iname of this dentry should be printable ASCII
    for (startOffset = offsets->dentry_iname[0]; startOffset < offsets->dentry_iname[0] + 128; startOffset++) {
        const char c = memDumps[dentryMountpoint][startOffset];
        if (c == 0x00) {
            break;
        } else if (c < ' ' || c > '~') {
            logMessage("mount_mountpoint offset not found\n");
            return false;
        }
    }

    if (startOffset == offsets->dentry_iname[0] + 128) {
        logMessage("mount_mountpoint offset not found\n");
        return false;
    }

    // search backwards for mount parent
    if (!searchPtr(offsets->mount_parent, backwards, mount, offsets->mount_mountpoint[0] - sizeof(uint64_t),
            offsets->mount_mountpoint[0] - sizeof(uint64_t))) {
        logMessage("mount_parent offset not found\n");
        return false;
    }

    offsets->mount_mnt[0] = 512 - offsets->mount_parent[0] + (2 * sizeof(uint64_t));
    offsets->mount_mountpoint[0] = offsets->mount_mountpoint[0] - offsets->mount_parent[0] + (2 * sizeof(uint64_t));
    offsets->mount_parent[0] = 2 * sizeof(uint64_t);

    printOffset("mount_mnt", offsets->mount_mnt, 2);
    printOffset("mount_parent", offsets->mount_parent, 2);
    printOffset("mount_mountpoint", offsets->mount_mountpoint, 2);

    return true;
}

//--------------------------------------------------------------------
//
// getFdOffsets
//
// Get the fd offsets.
//
//--------------------------------------------------------------------
bool getFdOffsets(Offsets *offsets, struct perf_buffer *pb)
{
    if (offsets == NULL || pb == NULL) {
        logMessage("getFdOffsets invalid params\n");
        return false;
    }

    if (offsets->pwd_path[0] == -1) {
        return false;
    }

    // after the fs struct pointer in the task struct comes the pointer to the files struct
    if (!searchPtr(offsets->max_fds, forwards, task, offsets->pwd_path[0] + sizeof(uint64_t), 32)) {
        logMessage("max_fds offset not found\n");
        return false;
    }

    if (!dumpStruct(files, (void *)get64(task, offsets->max_fds[0]), DUMP_SIZE, pb)) {
        logMessage("Could not dump files struct\n");
        return false;
    }

    // the fdt pointer is the one after the two identical wait_queue_head list pointers
    uint32_t startOffset = 0;
    while ((!isPointer(get64(files, startOffset)) || get64(files, startOffset) != get64(files, startOffset + sizeof(uint64_t)))
            && startOffset < 128) {
        startOffset += sizeof(uint64_t);
    }

    if (startOffset == 128) {
        logMessage("max_fds fdt offset not found\n");
        return false;
    }

    startOffset += (2 * sizeof(uint64_t));

    offsets->max_fds[1] = startOffset;
    // max_fds is the first entry in the fdt
    offsets->max_fds[2] = 0;
    printOffset("max_fds", offsets->max_fds, 4);

    // the fd array is the next entry in the fdt
    offsets->fd_table[0] = offsets->max_fds[0];
    offsets->fd_table[1] = offsets->max_fds[1];
    offsets->fd_table[2] = offsets->max_fds[2] + sizeof(uint64_t);
    printOffset("fd_table", offsets->fd_table, 4);

    // the path struct is two pointers from the start of the file struct. This will be
    // confirmed in the testing phase
    offsets->fd_path[0] = 2 * sizeof(uint64_t);
    printOffset("fd_path", offsets->fd_path, 2);

    return true;
}

//--------------------------------------------------------------------
//
// getTtyOffset
//
// Get the tty offset.
//
//--------------------------------------------------------------------
bool getTtyOffset(Offsets *offsets, struct perf_buffer *pb)
{
    if (offsets == NULL || pb == NULL) {
        logMessage("getTtyOffset invalid params\n");
        return false;
    }

    uint32_t startOffset, i;

    if (offsets->max_fds[0] == -1) {
        return false;
    }

    // search forward for the empty 64 bit blocked, real_blocked and saved_sigmask
    for (startOffset = offsets->max_fds[0] + sizeof(uint64_t); startOffset < 4096; startOffset += sizeof(uint64_t)) {
        if (get64(task, startOffset) == 0 && get64(task, startOffset + sizeof(uint64_t)) == 0 &&
                get64(task, startOffset + (2 * sizeof(uint64_t))) == 0) {
            break;
        }
    }
    if (startOffset == 4096) {
        logMessage("tty offset not found (1)\n");
        return false;
    }

    // search backward for next pointer (sighand)
    if (!searchPtr(offsets->tty, backwards, task, startOffset - sizeof(uint64_t), 32)) {
        logMessage("tty offset not found (2)\n");
        return false;
    }

    // search backward for next pointer (signal struct)
    if (!searchPtr(offsets->tty, backwards, task, offsets->tty[0] - sizeof(uint64_t), 32)) {
        logMessage("tty offset not found (3)\n");
        return false;
    }

    if (!dumpStruct(signals, (void *)get64(task, offsets->tty[0]), DUMP_SIZE, pb)) {
        logMessage("Could not dump signal struct\n");
        return false;
    }

    // search forwards for the block in signal that represents counters for dead threads
    // as these should all be 0 - should be at least 16 empty 64bit counters
    for (startOffset = 0; startOffset < 2048; startOffset += sizeof(uint64_t)) {
        for (i=0; i<16; i++) {
            if (get64(signals, startOffset + (i * sizeof(uint64_t))) != 0) {
                startOffset += i * sizeof(uint64_t);
                break;
            }
        }
        if (i == 16) {
            break;
        }
    }

    if (startOffset == 2048) {
        logMessage("tty offset not found (4)\n");
        return false;
    }

    // startOffset is positioned at start of block of zeros representing the counters for dead
    // threads (of which we have none).  Preceding it somewhere will be:
    // 1 (bool leader - as we ran setsid() we are a session leader), followed by
    // NULL (pointer to tty struct - again, setsid() killed our TTY if we had one)
    // so search backwards for the 1, then search fowards for a NULL and assume that is the
    // pointer to the tty struct.
    unsigned int off[4];
    if (!searchUint64(off, backwards, signals, startOffset - sizeof(uint64_t), 16, 1, 0)) {
        logMessage("tty offset not found (5)\n");
        return false;
    }

    searchUint64(&offsets->tty[1], forwards, signals, off[0] + sizeof(uint64_t), 16, 0, 0);

    // as no TTY pointer, we can't deref and examine the tty struct. Luckily this struct doesn't
    // seem to change much, nor does it have optional members, plus the index member is near the
    // beginning. We can therefore assume the offset for the index is static.  If it is wrong,
    // we will get incorrect information for the PTS number, and the only ramification is that we
    // will not be able to obtain the logon time for the user running the process.
    offsets->tty[2] = 32;

    printOffset("tty", offsets->tty, 4);
    return true;
}

//--------------------------------------------------------------------
//
// getAuidOffset
//
// Get auid and ses offsets.
//
//--------------------------------------------------------------------
bool getAuidOffset(Offsets *offsets)
{
    if (offsets == NULL) {
        logMessage("getAuidOffset invalid params\n");
        return false;
    }

    FILE *fp = NULL;
    uint32_t loginId = -1;
    unsigned int sessionId = -1;

    if (offsets->tty[0] == -1) {
        return false;
    }

    // NOTE: If the audit subsystem wasn't compiled into the kernel (rare these days, but not
    // impossible, then the loginId and sessionId will not be present in /proc/self, nor in the
    // task struct. In these cases, the offsets will remain initialised to -1 and the Sysmon
    // telemetry program will not attempt to fetch them.

    // the session id is much more likely to be unique so search for that first
    fp = fopen(SESSIONID_FILE, "r");
    if (fp != NULL) {
        if(fscanf(fp, "%d", &sessionId) == EOF)
        {
            return false;
        }

        fclose(fp);

        fp = fopen(LOGINUID_FILE, "r");
        if (fp != NULL) {
            if(fscanf(fp, "%d", &loginId) == EOF)
            {
                return false;
            }

            fclose(fp);

            // search forwards for the session ID
            if (searchUint32(offsets->ses, forwards, task, offsets->tty[0] + sizeof(uint64_t), 128, sessionId, 0)) {
                if (sessionId == loginId) {
                    offsets->ses[0] += sizeof(uint32_t);
                }
                printOffset("ses", offsets->ses, 2);
            } else {
                logMessage("ses offset not found\n");
                return false;
            }

            // search backwards for the login ID
            if (searchUint32(offsets->auid, backwards, task, offsets->ses[0] - sizeof(uint32_t), 16, loginId, 0)) {
                printOffset("auid", offsets->auid, 2);
                return true;
            } else {
                logMessage("auid offset not found\n");
                return false;
            }
        }
    }
    return false;
}

//--------------------------------------------------------------------
//
// getMmOffsets
//
// Get the mm offsets.
//
//--------------------------------------------------------------------
bool getMmOffsets(Offsets *offsets, struct perf_buffer *pb, const char *argv[])
{
    if (offsets == NULL || pb == NULL || argv == NULL) {
        logMessage("getMmOffsets invalid params\n");
        return false;
    }

    unsigned int pdeath[4];
    uint32_t startOffset;

    if (offsets->pid[0] == -1) {
        return false;
    }

    // search backwards from the PID to find the pdeath_signal we set earlier

    if (!searchUint32(pdeath, backwards, task, offsets->pid[0] - (2 * sizeof(uint32_t)), 128, PDEATH_SIG, 0)) {
        logMessage("pdeath offset not found\n");
        return false;
    }

    // now search backwards for two adjacent pointers that point to the same location;
    // these will be mm and active_mm.
    for (startOffset = align(pdeath[0] - sizeof(uint32_t), sizeof(uint64_t), backwards); startOffset > 0;
            startOffset -= sizeof(uint64_t)) {
        if (isPointer(get64(task, startOffset)) && get64(task, startOffset) == get64(task, startOffset - sizeof(uint64_t))) {
            break;
        }
    }

    if (startOffset == 0) {
        logMessage("mm offset not found\n");
        return false;
    }

    offsets->mm_arg_start[0] = offsets->mm_arg_end[0] = offsets->mm_start_code[0] = offsets->mm_end_code[0] =
            startOffset - sizeof(uint64_t);

    if (!dumpStruct(mm, (void *)get64(task, offsets->mm_arg_start[0]), DUMP_SIZE, pb)) {
        logMessage("Could not dump mm struct\n");
        return false;
    }

    // find cmdline by searching forwards
    if (searchUint64(&offsets->mm_arg_start[1], forwards, mm, 0, 128, (uint64_t)argv[0], 0)) {
        printOffset("mm_arg_start", offsets->mm_arg_start, 2);
    } else {
        logMessage("mm_arg_start offset not found\n");
        return false;
    }

    // arg_end is the next pointer
    offsets->mm_arg_end[1] = offsets->mm_arg_start[1] + sizeof(uint64_t);
    printOffset("mm_arg_end", offsets->mm_arg_end, 3);

    // before arg_start should be start_stack, with brk and then start_brk preceding that.
    // and preceding those should be end_data, then start_data, then end_code, then start_code.
    // as access to *reliable* pointers for start and end of code are hard to identify, we
    // take it on trust that this block stays the same, but we do at least check that the
    // pointers we take aren't NULL.
    startOffset = offsets->mm_arg_start[1] - (4 * sizeof(uint64_t));
    if (get64(mm, startOffset) != 0 &&
            get64(mm, startOffset - sizeof(uint64_t)) != 0 &&
            get64(mm, startOffset - (2 * sizeof(uint64_t))) != 0 &&
            get64(mm, startOffset - (3 * sizeof(uint64_t))) != 0) {
        offsets->mm_start_code[1] = startOffset - (3 * sizeof(uint64_t));
    printOffset("mm_start_code", offsets->mm_start_code, 3);
    } else {
        logMessage("mm_start_code offset not found\n");
        return false;
    }

    // end_code is the next pointer
    offsets->mm_end_code[1] = offsets->mm_start_code[1] + sizeof(uint64_t);
    printOffset("mm_end_code", offsets->mm_end_code, 3);

    return true;
}

//--------------------------------------------------------------------
//
// getExePathOffset
//
// Get the exe path offset.
//
//--------------------------------------------------------------------
bool getExePathOffset(Offsets *offsets, struct perf_buffer *pb, const char *comm)
{
    if (offsets == NULL || pb == NULL || comm == NULL) {
        logMessage("getExePathOffset invalid params\n");
        return false;
    }

    uint32_t startOffset;
    char exePath[PATH_MAX];
    const char *exe = NULL;

    if (offsets->mm_arg_end[1] == -1) {
        return false;
    }

    if (readlink(EXEPATH_FILE, exePath, PATH_MAX) <= 0) {
        logMessage("Cannot read exe link\n");
        return false;
    }

    exe = strrchr(exePath, '/');
    if (exe == NULL) {
        logMessage("Cannot find exe name\n");
        return false;
    }

    // search forwards for owner (task) address - this is only present if CONFIG_MEMCG is enabled, which
    // appears to be the default for all distributions, and unlikely to be turned off except in extreme
    // tuning.  If it isn't there, we will look another way.
    unsigned int owner[4];

    offsets->exe_path[0] = offsets->mm_arg_end[0];
    if (searchUint64(owner, forwards, mm, offsets->mm_arg_end[1] + (3 * sizeof(uint64_t)), 256, memAddrs[task], 0)) {
        if (isPointer(get64(mm, owner[0] + (2 * sizeof(uint64_t))))) {
            offsets->exe_path[1] = owner[0] + (2 * sizeof(uint64_t));
            offsets->exe_path[2] = offsets->fd_path[0];
            printOffset("exe_path", offsets->exe_path, 4);
            return true;
        }
    }

    if (offsets->exe_path[1] == -1) {
        // owner pointer or exe path pointer not found

        // search forward and try all pointers expecting to find the exe path pointer that way
        for (startOffset = offsets->mm_arg_end[1] + (3 * sizeof(uint64_t)); startOffset < memSizes[mm];
                startOffset += sizeof(uint64_t)) {
            if (isPointer(get64(mm, startOffset))) {
                if (!dumpStruct(exeFile, (void *)get64(mm, startOffset), DUMP_SIZE, pb)) {
                    logMessage("Could not dump exe_file struct\n");
                    return false;
                }
                uint64_t dentry = get64(exeFile, offsets->fd_path[0] + offsets->path_dentry[0]);
                if (isPointer(dentry)) {
                    if (!dumpStruct(exeDentry, (void *)dentry, DUMP_SIZE, pb)) {
                        logMessage("Could not dump exe_dentry struct\n");
                        return false;
                    }
                    uint64_t exe_dname = get64(exeDentry, offsets->dentry_name[0]);
                    if (!dumpStruct(exeName, (void *)exe_dname, DUMP_SIZE, pb)) {
                        logMessage("Could not dump exe_name\n");
                        return false;
                    }
                    if (strcmp(exe, memDumps[exeName]) == 0) {
                        offsets->exe_path[1] = startOffset;
                        offsets->exe_path[2] = offsets->fd_path[0];
                        printOffset("exe_path", offsets->exe_path, 4);
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

//--------------------------------------------------------------------
//
// triggerSkb
//
// Send a packet to call the EBPF program.
//
//--------------------------------------------------------------------
void triggerSkb(int fd, struct sockaddr *saddr, size_t len)
{
    if (fd <= 0 || saddr == NULL) {
        logMessage("triggerSkb invalid params\n");
        return;
    }

    char buf[] = "A";
    if (sendto(fd, buf, 1, 0, saddr, len) < 0) {
        logMessage("Could not send UDP packet\n");
    }
}

//--------------------------------------------------------------------
//
// getSkbOffsets
//
// Get the skb offset.
//
//--------------------------------------------------------------------
bool getSkbOffsets(Offsets *offsets, struct perf_buffer *pb)
{
    if (offsets == NULL || pb == NULL) {
        logMessage("getSkbOffsts invalid params\n");
        return false;
    }

    int fd = 0;
    struct sockaddr_in saddr;
    uint32_t startOffset = 0;
    uint64_t addr = 0;
    unsigned char localhostx2[8] = {127, 0, 0, 1, 127, 0, 0, 1};

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        logMessage("Could not create socket\n");
        return false;
    }
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(UDP_ADDR);
    saddr.sin_port = UDP_PORT;

    setConfig(skb, NULL, 512);

    triggerSkb(fd, (struct sockaddr *)&saddr, sizeof(saddr));

    if (!getMem(skb, pb)) {
        logMessage("Did not receive skb memory dump\n");
        return false;
    }

    // search for stack pointers
    for (startOffset=0; startOffset < DUMP_SIZE; startOffset+=sizeof(uint64_t)) {
        addr = get64(skb, startOffset);
        if (near(addr, memAddrs[skb], MAX_POINTER_DIFF)) {
            setConfig(skdata, (const void *)(uint64_t)startOffset, 36);
            triggerSkb(fd, (struct sockaddr *)&saddr, sizeof(saddr));
            if (!getMem(skdata, pb)) {
                logMessage("Did not receive skdata memory dump\n");
                return false;
            }
            if (memcmp(&memDumps[skdata][28], localhostx2, sizeof(localhostx2)) == 0) {
                offsets->skb_head[0] = startOffset;
                offsets->skb_head[1] = -1;
                offsets->skb_data[0] = startOffset + sizeof(uint64_t);
                offsets->skb_data[1] = -1;
                if (searchUint16(offsets->skb_network_header, backwards, skb, startOffset - sizeof(uint64_t),
                        32, 0x10, 0)) {
                    printOffset("skb_head", offsets->skb_head, 2);
                    printOffset("skb_data", offsets->skb_data, 2);
                    printOffset("skb_network_header", offsets->skb_network_header, 2);
                    return true;
                } else {
                    logMessage("Did not find skb network_header\n");
                    return false;
                }
            }
        }
    }
    logMessage("Did not find packet data in skb\n");
    return false;
}

//--------------------------------------------------------------------
//
// getOffsets
//
// Get all the offsets.
//
//--------------------------------------------------------------------
int getOffsets(
    Offsets *offsets,
    const char *argv[],
    struct perf_buffer *pb,
    time_t procStartTime
    )
{
    if (offsets == NULL || argv == NULL || pb == NULL) {
        logMessage("getOffsets invalid params\n");
        return E_DISC_CATASTROPHIC;
    }

    FILE *fp = NULL;
    char comm[COMM_LEN + 1];
    size_t commLen = 0;

    // get the comm from /proc
    fp = fopen(COMM_FILE, "r");
    if (fp != NULL) {
        commLen = fread(comm, 1, sizeof(comm), fp);
        fclose(fp);
    }
    if (commLen == 0) {
        logMessage("Could not read comm\n");
        return E_DISC_GET_COMM;
    }
    comm[commLen] = 0x00;
    while (comm[commLen-1] == 0x0a) {
        commLen--;
        comm[commLen] = 0x00;
    }

    if (strlen(comm) == 0) {
        logMessage("Comm is empty\n");
        return E_DISC_GET_COMM;
    }

    if (!getPidOffset(offsets, pb))                     return E_DISC_PID_OFFSET;
    if (!getStartTimeOffset(offsets, procStartTime))    return E_DISC_START_TIME_OFFSET;
    if (!getCommOffset(offsets, comm))                  return E_DISC_COMM_OFFSET;
    if (!getCredsOffsets(offsets, pb))                  return E_DISC_CREDS_OFFSET;
    if (!getPwdPathOffset(offsets, pb, commLen))        return E_DISC_PWD_PATH_OFFSET;
    if (!getDentryNameOffset(offsets, pb))              return E_DISC_DENTRY_NAME_OFFSET;
    if (!getDentryParentOffset(offsets))                return E_DISC_DENTRY_PARENT_OFFSET;
    if (!getDentryInodeOffsets(offsets, pb))            return E_DISC_DENTRY_INODE_OFFSET;
    if (!getMountOffsets(offsets, pb))                  return E_DISC_MOUNT_OFFSET;
    if (!getFdOffsets(offsets, pb))                     return E_DISC_FD_OFFSET;
    if (!getTtyOffset(offsets, pb))                     return E_DISC_TTY_OFFSET;
         getAuidOffset(offsets); // note this could fail if audit subsystem is missing
    if (!getMmOffsets(offsets, pb, argv))               return E_DISC_MM_OFFSET;
    if (!getExePathOffset(offsets, pb, comm))           return E_DISC_EXE_PATH_OFFSET;

    if (!getSkbOffsets(offsets, pb))                    return E_DISC_SKBUFF_OFFSET;

    return E_EBPF_SUCCESS;
}

//--------------------------------------------------------------------
//
// discoverOffsets
//
// Discover the offsets for the required struct members.
//
//--------------------------------------------------------------------
int discoverOffsets(
    Offsets *offsets,
    const char *argv[],
    time_t procStartTime
    )
{
    if (offsets == NULL || argv == NULL) {
        logMessage("discoverOffsets invalid params\n");
        return E_DISC_CATASTROPHIC;
    }

    unsigned int major = 0, minor = 0;
    struct rlimit lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    char filepath[PATH_MAX] = SYSINTERNALS_EBPF_INSTALL_DIR "/" KERN_MEM_DUMP_OBJ;
    struct stat filepathStat;
    struct utsname unameStruct = { 0 };
    struct perf_buffer *pb;
    int ret;
    char cwd[PATH_MAX];

    memset(memDumps, 0, sizeof(memDumps));
    memset(offsets, 0xFF, sizeof(*offsets));

    if (setsid() < 0) {
        logMessage("sedsid() failed.\n");
        return E_DISC_CATASTROPHIC;
    }

    thisPid = getpid();

    // ignore the end of the child we spawn for getting creds
    signal(SIGCHLD, SIG_IGN);

    if (uname(&unameStruct) ) {
        logMessage("Couldn't find uname, '%s'\n", strerror(errno));
        return E_DISC_CATASTROPHIC;
    }

    if (sscanf(unameStruct.release, "%u.%u", &major, &minor) != 2) {
        logMessage("Couldn't find version\n");
        return E_DISC_CATASTROPHIC;
    }

    // <  4.15, no ebpf support due to no direct r/w access to maps
    if ((major < 4) || (major == 4 && minor < 15)) {
        logMessage("Kernel Version %u.%u not supported\n", major, minor);
        return E_DISC_NOTSUPPORTED;
    }

    // check path
    if (stat(filepath, &filepathStat) != 0 || !S_ISREG(filepathStat.st_mode)) {
        printf("Cannot access EBPF kernel object: %s\n", filepath);
        return 1;
    }

    setrlimit(RLIMIT_MEMLOCK, &lim);

    bpfObj = bpf_object__open(filepath);
    if (libbpf_get_error(bpfObj)) {
        logMessage("ERROR: failed to open prog: '%s'\n", strerror(errno));
        return E_DISC_NOPROG;
    }

    if ((bpfSysExit = bpf_object__find_program_by_name(bpfObj,"sys_exit_uname")) == NULL) {
        logMessage("ERROR: failed to find program: 'sys_exit_uname' '%s'\n", strerror(errno));
        return E_DISC_NOPROG;
    }

    if ((bpfConsumeSkb = bpf_object__find_program_by_name(bpfObj,"consume_skb")) == NULL) {
        logMessage("ERROR: failed to find program: 'consume_skb' '%s'\n", strerror(errno));
        return E_DISC_NOPROG;
    }

    bpf_program__set_type(bpfSysExit, BPF_PROG_TYPE_TRACEPOINT);
    bpf_program__set_type(bpfConsumeSkb, BPF_PROG_TYPE_TRACEPOINT);

    if (bpf_object__load(bpfObj)) {
        logMessage("ERROR: failed to load prog: '%s'\n", strerror(errno));
        return E_DISC_NOPROG;
    }

    eventMapFd = bpf_object__find_map_fd_by_name(bpfObj, "eventMap");
    if (eventMapFd <= 0) {
        logMessage("ERROR: failed to load eventMapFd: '%s'\n", strerror(errno));
        return E_DISC_NOMAP;
    }

    configMapFd = bpf_object__find_map_fd_by_name(bpfObj, "memDumpConfigMap");
    if (configMapFd <= 0) {
        logMessage("ERROR: failed to load configMapFd: '%s'\n", strerror(errno));
        return E_DISC_NOMAP;
    }

    setConfig(task, 0, DUMP_SIZE);

    bpfSysExitLink = bpf_program__attach_tracepoint(bpfSysExit, "syscalls", "sys_exit_newuname");
    if (libbpf_get_error(bpfSysExitLink))
        return E_DISC_NOATTACH;

    bpfConsumeSkbLink = bpf_program__attach_tracepoint(bpfConsumeSkb, "skb", "consume_skb");
    if (libbpf_get_error(bpfConsumeSkbLink))
        return E_DISC_NOATTACH;

    pb = perf_buffer__new(eventMapFd, MAP_PAGE_SIZE, memDumpEventCb, NULL, NULL, NULL); // param 2 is page_cnt == number of pages to mmap.
    ret = libbpf_get_error(pb);
    if (ret) {
        logMessage("ERROR: failed to setup perf_buffer: %d\n", ret);
        return E_DISC_NORB;
    }

    logMessage("Discovering offsets...");

    // move to a temporary directory for use in later checks
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        snprintf(cwd, sizeof(cwd), "/tmp/");
    }
    mkdir(tmpdir, TEMPDIR_MODE);
    if(chdir(tmpdir) == -1 )
    {
        logMessage("ERROR: Failed to change directories: %s\n", tmpdir);
        return E_DISC_CATASTROPHIC;
    }

    if(chown(tmpdir, TEMPUID, TEMPGID) == -1)
    {
        logMessage("ERROR: Failed to change ownership: %s\n", tmpdir);
        return E_DISC_CATASTROPHIC;
    }

    creation_time = time(NULL);

    // set up signal handler for PDEATH
    signal(PDEATH_SIG, SIG_IGN);

    // set PDEATH signal for later use as a canary
    if(prctl(PR_SET_PDEATHSIG, PDEATH_SIG) < 0) {
        logMessage("prctl failed\n");
        return E_DISC_NOPDEATH;
    }

    triggerTp();

    if (!getMem(task, pb)) {
        logMessage("Did not get task_struct\n");
        return E_DISC_NOTASK;
    }

    ret = getOffsets(offsets, argv, pb, procStartTime);

    if (ret == E_EBPF_SUCCESS) {
        logMessage("done\n");
    } else {
        logMessage("\nGet Offsets Error: %s\n", eBPFstrerror(ret));
    }

    memDumpCloseAll();

    if(chdir(cwd) == -1)
    {
        logMessage("ERROR: Failed to change directories: %s\n", cwd);
        return E_DISC_CATASTROPHIC;
    }

    rmdir(tmpdir);

    return ret;
}

