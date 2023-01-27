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
// sysinternalsEBPF_helpers.c
//
// Useful inline eBPF functions.
//
//====================================================================

#ifndef SYSINTERNALS_EBPF_HELPERS_C
#define SYSINTERNALS_EBPF_HELPERS_C

#include <string.h>

#ifndef AT_FDCWD
#define AT_FDCWD		-100
#endif

//
// Make a literal into a string for inclusion in asm statements
// use XSTR(val) for when you want "val" but you need val to have
// been already interpreted by the preprocessor.
//
#define STR(x) #x
#define XSTR(s) STR(s)


//--------------------------------------------------------------------
//
// eventOutput
//
// Write to perf ring buffer, logging errors.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline void eventOutput(void *ctx, void *map, uint64_t flags, void *data, uint64_t size)
{
    long ret = 0;
    perfError *indexPtr = NULL;
    uint32_t indexLocation = PERF_ERRORS_WRITE_INDEX;
    uint32_t writeIndex = 0;
    perfError perror;

    ret = bpf_perf_event_output(ctx, map, flags, data, size);

    if (ret == 0)
        return;

    // error occurred so store in perfErrorsMap ring buffer
    perror.error = ret;
    perror.time = bpf_ktime_get_ns();

    // get the current write index
    indexPtr = (perfError *)bpf_map_lookup_elem(&perfErrorsMap, &indexLocation);
    if (indexPtr == NULL)
        return;

    // store error at write index
    writeIndex = indexPtr->index & (PERF_ERRORS_MAX - 1);
    bpf_map_update_elem(&perfErrorsMap, &writeIndex, &perror, BPF_ANY);

    // increment index
    indexPtr->index = (indexPtr->index + 1) & (PERF_ERRORS_MAX - 1);
    writeIndex = indexPtr->index;

    // get current read index
    indexLocation = PERF_ERRORS_READ_INDEX;
    indexPtr = (perfError *)bpf_map_lookup_elem(&perfErrorsMap, &indexLocation);

    if (indexPtr == NULL)
        return;

    // check if write index has caught read index
    if (indexPtr->index == writeIndex) {
        // increment read index
        indexPtr->index = (indexPtr->index + 1) & (PERF_ERRORS_MAX - 1);
    }
}

//--------------------------------------------------------------------
//
// derefMember
//
// Return a pointer to a struct member.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline const void *derefMember(const void *base, const unsigned int *refs)
{
    unsigned int i;
    const void *ref = base;
    const void *result = ref;
    unsigned int breakindex = NUM_REDIRECTS - 1;
    bool breakloop = false; // problems with clang loop unrolling led to this...

    if (!refs || refs[0] == DEREF_END)
        return NULL;

#ifdef NOLOOPS
    #pragma unroll
#endif
    for (i=0; i<NUM_REDIRECTS - 1; i++) {
        if (!breakloop) {
            if (refs[i+1] == DEREF_END) {
                breakindex = i;
                breakloop = true;
            } else {
                if (bpf_probe_read(&result, sizeof(result), ref + refs[i]) != READ_OKAY)
                    return NULL;
                ref = result;
                if (!ref)
                    return NULL;
            }
        }
    }

    return result + refs[breakindex & (NUM_REDIRECTS - 1)];
}

//--------------------------------------------------------------------
//
// derefPtr
//
// Return value pointed to by struct member.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline uint64_t derefPtr(const void *base, const unsigned int *refs)
{
    uint64_t result = 0;
    const void *ref;

    ref = derefMember(base, refs);

    if (bpf_probe_read(&result, sizeof(result), ref) != READ_OKAY)
        return 0;

    return result;
}

//--------------------------------------------------------------------
//
// derefStringInto
//
// Extract a string from a struct.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline bool derefStringInto(char *dest, unsigned int size, const void *base, const unsigned int *refs)
{
    unsigned int i;
    const void *ref = base;
    uint64_t result = 0;

    ref = derefMember(base, refs);

    if (ref && bpf_probe_read_str(dest, size, ref) > 0)
        return true;
    else {
        *dest = 0x00;
        return false;
    }
}

//--------------------------------------------------------------------
//
// derefInodeFromFd
//
// Get inode from file descriptor.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline const void *derefInodeFromFd(const void *task, unsigned int fd, const ebpfConfig *config)
{
    const void **fd_table = NULL;
    const void *file = NULL;
    const void *path = NULL;
    const void *dentry = NULL;
    const void *inode = NULL;

#ifdef EBPF_CO_RE
    fd_table = (const void**) BPF_CORE_READ((struct task_struct *)task, files, fdt, fd);
#else
    fd_table = (const void **)derefPtr(task, config->offsets.fd_table);
#endif
    if (!fd_table)
        return NULL;
    if (bpf_probe_read(&file, sizeof(file), &fd_table[fd & MAX_FDS]) != READ_OKAY || !file)
        return NULL;
#ifdef EBPF_CO_RE
    inode = BPF_CORE_READ((struct file *)file, f_path.dentry, d_inode);
    if (!dentry)
        return 0;
#else
    path = (const void *)derefMember(file, config->offsets.fd_path);
    if (!path)
        return NULL;
    if (bpf_probe_read(&dentry, sizeof(dentry), path + config->offsets.path_dentry[0]) != READ_OKAY || !dentry)
        return NULL;
    inode = (const void *)derefPtr(dentry, config->offsets.dentry_inode);
#endif
    if (!inode)
        return NULL;
    return inode;
}


//--------------------------------------------------------------------
//
// derefFilepathInto
//
// Extract filepath from dentry.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline uint32_t derefFilepathInto(char *dest, const void *dentry, const void *vfsmount, const ebpfConfig *config)
{
    int dlen, dlen2;
    char *dname = NULL;
    char *temp = NULL;
    unsigned int i;
    unsigned int size = 0;
    uint32_t map_id = bpf_get_smp_processor_id();
    const void *path = NULL;
    const void *newdentry = NULL;
    const void *mnt = NULL;
    uint32_t tsize = 0;

    // nullify string in case of error
    dest[0] = 0x00;

#ifdef EBPF_CO_RE
    mnt = container_of(vfsmount, struct mount, mnt);
#endif

    // retrieve temporary filepath storage
    temp = bpf_map_lookup_elem(&temppathArray, &map_id);
    if (!temp)
        return 0;

#ifdef NOLOOPS
    #pragma unroll
#endif
    for (i=0; i<FILEPATH_NUMDIRS; i++) {
#ifdef EBPF_CO_RE
        dname = (char*) BPF_CORE_READ((struct dentry *)dentry, d_name.name);
#else
        if (bpf_probe_read(&dname, sizeof(dname), dentry + config->offsets.dentry_name[0]) != READ_OKAY) {
            return 0;
        }
#endif
        if (!dname) {
            return 0;
        }
        // store this dentry name in start of second half of our temporary storage
        dlen = bpf_probe_read_str(&temp[PATH_MAX], PATH_MAX, dname);
        BPF_PRINTK("dname: (%s)\n", dname);
        // get parent dentry
#ifdef EBPF_CO_RE
        newdentry = (char*) BPF_CORE_READ((struct dentry *)dentry, d_parent);
#else
        bpf_probe_read(&newdentry, sizeof(newdentry), dentry + config->offsets.dentry_parent[0]);
#endif
        // copy the temporary copy to the first half of our temporary storage, building it backwards from the middle of it
        dlen2 = bpf_probe_read_str(&temp[(PATH_MAX - size - dlen) & (PATH_MAX - 1)], dlen & (PATH_MAX - 1), &temp[PATH_MAX]);
        // check if current dentry name is valid
        if (dlen2 <= 0 || dlen <= 0 || dlen >= PATH_MAX || size + dlen > PATH_MAX) {
            return 0;
        }
        if (size > 0)
        {
            asm volatile("%[tsize] = " XSTR(PATH_MAX) "\n"
                         "%[tsize] -= %[size]\n"
                         "%[tsize] -= 1\n"
                         "%[tsize] &= " XSTR(PATH_MAX - 1) "\n"
                        :[size]"+&r"(size), [tsize]"+&r"(tsize)
                        );

            temp[tsize & (PATH_MAX -1)] = '/';
        }
        size = (size + dlen2) & (PATH_MAX - 1);  // by restricting size to PATH_MAX we help the verifier keep the complexity
                                                // low enough so that it can analyse the loop without hitting the 1M ceiling
        // check if this is the root of the filesystem
        if (!newdentry || dentry == newdentry) {
            // check if we're on a mounted partition
            // find mount struct from vfsmount
#ifdef EBPF_CO_RE
            const void *parent = BPF_CORE_READ((struct mount *)mnt, mnt_parent);
#else
            mnt = vfsmount - config->offsets.mount_mnt[0];
            const void *parent = (const void *)derefPtr(mnt, config->offsets.mount_parent);
#endif
            // check if we're at the real root
            if (parent == mnt)
                break;
            // move to mount point
#ifdef EBPF_CO_RE
            newdentry = BPF_CORE_READ((struct mount *)mnt, mnt_mountpoint);
            mnt = parent;
#else
            vfsmount = parent + config->offsets.mount_mnt[0];
            newdentry = (const void *)derefPtr(mnt, config->offsets.mount_mountpoint);
#endif
            // another check for real root
            if (dentry == newdentry)
                break;
            size = (size - dlen2) & (PATH_MAX - 1);  // ditto above message about restricting size to PATH_MAX
        }

        // go up one directory
        dentry = newdentry;
    }

    // check if we exhausted the number of directories we can traverse
    if (i == FILEPATH_NUMDIRS) {
        // add a '+/' to the start to indicate it's not a full path

        // Following piece of asm is required as clang likes to optimise
        // an increment followed by ANDing with (PATH_MAX -1), into simply
        // XORing with (PATH_MAX -1) and then converting to 32 bits by
        // <<32, >>32. This means the verifier thinks max value is 2^32 -1,
        // instead of (PATH_MAX -1).

        asm volatile("%[size] += 1\n"
                     "%[tsize] = " XSTR(PATH_MAX) "\n"
                     "%[tsize] -= %[size]\n"
                     "%[tsize] &= " XSTR(PATH_MAX - 1) "\n"
                    :[size]"+&r"(size), [tsize]"+&r"(tsize)
                    );
        temp[tsize & (PATH_MAX -1)] = '/';

        asm volatile("%[size] += 1\n"
                     "%[tsize] -= 1\n"
                     "%[tsize] &= " XSTR(PATH_MAX - 1) "\n"
                    :[size]"+&r"(size), [tsize]"+&r"(tsize)
                    );
        temp[tsize & (PATH_MAX -1)] = '+';
    } else if (size == 1) {
        // smallest size is 1 as a 0 length read above would have bailed
        // so the shortest valid read would be a single null character.
        // assume this represents the root dir
        size++;
        temp[(PATH_MAX - size) & (PATH_MAX -1)] = '/';
    } else if (size > 2) {
        // size of 2 is simply "/" which is good. Need to check >2.

        // check if starting with '/'
        if (temp[(PATH_MAX - size) & (PATH_MAX -1)] == '/') {
            // check for double / ("//")
            if (temp[(PATH_MAX - (size - 1)) & (PATH_MAX -1)] == '/') {
                size--;
            }
        } else {
            // add a '/'

            asm volatile("%[size] += 1\n"
                         "%[tsize] = " XSTR(PATH_MAX) "\n"
                         "%[tsize] -= %[size]\n"
                         "%[tsize] &= " XSTR(PATH_MAX - 1) "\n"
                        :[size]"+&r"(size), [tsize]"+&r"(tsize)
                        );

            temp[tsize & (PATH_MAX -1)] = '/';
        }
    }

    // copy the path from the temporary location to the destination
    dlen = bpf_probe_read_str(dest, PATH_MAX, &temp[(PATH_MAX - size) & (PATH_MAX -1)]);

    if (dlen <= 0) {
        return 0;
    }

    return dlen;
}

//--------------------------------------------------------------------
//
// copyCommandline
//
// Copy commandline from mm struct.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline uint32_t copyCommandline(char *e, const void *task, const ebpfConfig *config)
{
    // read the more reliable cmdline from task_struct->mm->arg_start
#ifdef EBPF_CO_RE
    uint64_t arg_start = BPF_CORE_READ((struct task_struct *)task, mm, arg_start);
    uint64_t arg_end = BPF_CORE_READ((struct task_struct *)task, mm, arg_end);
#else
    uint64_t arg_start = derefPtr(task, config->offsets.mm_arg_start);
    uint64_t arg_end = derefPtr(task, config->offsets.mm_arg_end);
#endif

    if (arg_start >= arg_end)
        return 0;
    int arg_len = arg_end - arg_start;
    if (arg_len > (CMDLINE_MAX_LEN - 1))
        arg_len = CMDLINE_MAX_LEN - 1;

    arg_len = arg_len & (CMDLINE_MAX_LEN - 1);
    if (bpf_probe_read(e, arg_len, (void *)arg_start) != READ_OKAY)
        return 0;

    // add nul terminator just in case
    e[arg_len] = 0x00;
    return arg_len;
}

//--------------------------------------------------------------------
//
// fdToPath
//
// Extract pathname from a file descriptor.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline uint32_t fdToPath(char *fdPath, int fd, const void *task, const ebpfConfig *config)
{
    int byteCount;
    void* dentry = NULL;
    void* vfsmount = NULL;
    void* path = NULL;

    // check if fd is valid
#ifdef EBPF_CO_RE
    int maxFds = BPF_CORE_READ((struct task_struct *)task, files, fdt, max_fds);
#else
    int maxFds = derefPtr(task, config->offsets.max_fds);
#endif
    if (fd < 0 || fd > MAX_FDS || maxFds <= 0 || fd > maxFds) {
        return 0;
    }

    // resolve the fd to the fd_path
#ifdef EBPF_CO_RE
    const void **fdTable = (const void**) BPF_CORE_READ((struct task_struct *)task, files, fdt, fd);
#else
    const void **fdTable = (const void **)derefPtr(task, config->offsets.fd_table);
#endif
    if (!fdTable) {
        return 0;
    }

    const void *file = NULL;
    if (bpf_probe_read(&file, sizeof(file), &fdTable[fd & MAX_FDS]) != READ_OKAY || !file) {
        return 0;
    } else {
#ifdef EBPF_CO_RE
        dentry = BPF_CORE_READ((struct file *)file, f_path.dentry);
        if (!dentry)
            return 0;

        vfsmount = BPF_CORE_READ((struct file *)file, f_path.mnt);
        if (!vfsmount)
            return 0;
#else
        path = derefMember(task, config->offsets.fd_path);
        if (!path)
            return 0;
        if (bpf_probe_read(&dentry, sizeof(dentry), path + config->offsets.path_dentry[0]) != READ_OKAY)
            return 0;

        if (!dentry)
            return 0;

        // get a pointer to the vfsmount
        if (bpf_probe_read(&vfsmount, sizeof(vfsmount), path + config->offsets.path_vfsmount[0]) != READ_OKAY)
            return 0;
#endif
        return derefFilepathInto(fdPath, dentry, vfsmount, config);
    }
}

//--------------------------------------------------------------------
//
// resolveFdPath
//
// Wrapper for fdToPath().
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline uint32_t resolveFdPath(char *pathname, int fd, const void *task, const ebpfConfig *config)
{
    pathname[0] = 0x00;

    if (fd > 0)
        return fdToPath(pathname, fd, task, config);

    return 0;
}

//--------------------------------------------------------------------
//
// resolveDfdPath
//
// Extract dfd path followed by dfd pathname, separated by null, and
// return total size including null.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline uint32_t resolveDfdPath(char *dfdPath, int dfd, const char *pathname, const void *task, const ebpfConfig *config)
{
    int byteCount;
    int dfdCount;

    if (pathname) {
        if (bpf_probe_read(dfdPath, 1, (void *)pathname) < 0) {
            BPF_PRINTK("ERROR, reading pathname (0x%lx)\n", pathname);
            return 0;
        }

        if (dfdPath[0] == '/') { // absolute path
            if ((byteCount = bpf_probe_read_str(dfdPath, PATH_MAX,
                    (void *)pathname)) < 0) {
                BPF_PRINTK("ERROR, reading pathname (0x%lx), returned %ld\n", pathname, byteCount);
                dfdPath[0] = 0x00;
                return 0;
            }
            return byteCount;
        }
    }
    if (dfd == AT_FDCWD) { // relative to current working directory
        dfdPath[0] = 'C';
        dfdPath[1] = 0x00;
        if (pathname) {
            if ((byteCount = bpf_probe_read_str(dfdPath + 2, PATH_MAX - 2,
                    (void *)pathname)) < 0) {
                BPF_PRINTK("ERROR, reading pathname (0x%lx), returned %ld\n", pathname, byteCount);
                return 0;
            }
            return byteCount + 2;
        } else {
            return 2;
        }
    }
    // relative to FD
    dfdPath[0] = 'U';
    dfdPath[1] = 0x00;
    dfdCount = 2;
#ifndef SUB4096
    if ((dfdCount = fdToPath(dfdPath, dfd, task, config)) == 0) {
        dfdPath[0] = 'U';
        dfdPath[1] = 0x00;
        dfdCount = 2;
    }
#endif
    if (pathname) {
        if ((byteCount = bpf_probe_read_str(dfdPath + dfdCount, PATH_MAX - dfdCount,
                (void *)pathname)) < 0) {
            BPF_PRINTK("ERROR, reading pathname (0x%lx), returned %ld\n", pathname, byteCount);
            return 0;
        }
        return byteCount + dfdCount;
    } else {
        return dfdCount;
    }
}

//--------------------------------------------------------------------
//
// initArgs
//
// Set the initial values for the event arguments.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline void initArgs(argsStruct *eventArgs, unsigned long syscallId)
{
    memset(eventArgs, 0, sizeof(argsStruct));
    eventArgs->syscallId = syscallId;
#ifdef NOLOOPS
    #pragma unroll
#endif
    for (unsigned int i=0; i<ARG_ARRAY_SIZE; i++) {
        eventArgs->a[i] = 0;
    }
}

//--------------------------------------------------------------------
//
// sysEnterCheckAndInit
//
// Check if this is an event to process.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline bool sysEnterCheckAndInit(argsStruct *eventArgs, const ebpfConfig *config, uint32_t syscall, uint64_t pidTid)
{
    // don't report any syscalls for the userland PID
    if ((pidTid >> 32) == config->userlandPid)
        return false;

    // initialise the args
    initArgs(eventArgs, syscall);

    return true;
}

//--------------------------------------------------------------------
//
// sysEnterCompleteAndStore
//
// Complete and store event.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline void sysEnterCompleteAndStore(const argsStruct *eventArgs, uint32_t syscall, uint64_t pidTid)
{
    argsStruct args;
    memset(&args, 0, sizeof(argsStruct));
    // store args in the hash
#ifdef NOLOOPS
    #pragma unroll
#endif
    for (int i=0; i<NUM_ARGS; i++) {
        args.a[i] = eventArgs->a[i];
    }
    args.syscallId = eventArgs->syscallId;
    long ret = 0;
    if ((ret = bpf_map_update_elem(&argsHash, &pidTid, &args, BPF_ANY)) != UPDATE_OKAY) {
        BPF_PRINTK("ERROR, HASHMAP: failed to update args map, %ld\n", ret);
    }
}

//--------------------------------------------------------------------
//
// copyExePath
//
// Extract exe path from dentry.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline uint32_t copyExePath(char *dest, const void *base, const ebpfConfig *config)
{
    const void *path = NULL;
    const void *dentry = NULL;
    const void *vfsmount = NULL;

#ifdef EBPF_CO_RE
    dentry = BPF_CORE_READ((struct task_struct *)base, mm, exe_file, f_path.dentry);
    if (!dentry)
        return 0;

    vfsmount = BPF_CORE_READ((struct task_struct *)base, mm, exe_file, f_path.mnt);
    if (!vfsmount)
        return 0;
#else
    path = derefMember(base, config->offsets.exe_path);
    if (!path)
        return 0;
    if (bpf_probe_read(&dentry, sizeof(dentry), path + config->offsets.path_dentry[0]) != READ_OKAY)
        return 0;

    if (!dentry)
        return 0;

    // get a pointer to the vfsmount
    if (bpf_probe_read(&vfsmount, sizeof(vfsmount), path + config->offsets.path_vfsmount[0]) != READ_OKAY)
        return 0;
#endif

    return derefFilepathInto(dest, dentry, vfsmount, config);
}

//--------------------------------------------------------------------
//
// copyPwdPath
//
// Extract pwd path from dentry.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline uint32_t copyPwdPath(char *dest, const void *base, const ebpfConfig *config)
{
    const void *path = NULL;
    const void *dentry = NULL;
    const void *vfsmount = NULL;

#ifdef EBPF_CO_RE
    dentry = BPF_CORE_READ((struct task_struct *)base, fs, pwd.dentry);
    if (!dentry)
        return 0;

    vfsmount = BPF_CORE_READ((struct task_struct *)base, fs, pwd.mnt);
    if (!vfsmount)
        return 0;
#else
    path = derefMember(base, config->offsets.pwd_path);
    if (!path)
        return 0;
    if (bpf_probe_read(&dentry, sizeof(dentry), path + config->offsets.path_dentry[0]) != READ_OKAY)
        return 0;

    if (!dentry)
        return 0;

    // get a pointer to the vfsmount
    if (bpf_probe_read(&vfsmount, sizeof(vfsmount), path + config->offsets.path_vfsmount[0]) != READ_OKAY)
        return 0;
#endif

    return derefFilepathInto(dest, dentry, vfsmount, config);
}

//--------------------------------------------------------------------
//
// getUid
//
// Get the uid.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline uint64_t getUid(struct task_struct* task, const ebpfConfig *config)
{
    uint64_t ret = 0;
#ifdef EBPF_CO_RE
    ret = BPF_CORE_READ((struct task_struct *)task, cred, uid.val);
#else
    const void *cred = (const void *)derefPtr(task, config->offsets.cred);
    if (cred) {
        ret = derefPtr(cred, config->offsets.cred_uid);
    }
#endif

    return ret;
}


#endif