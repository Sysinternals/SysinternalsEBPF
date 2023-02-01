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
// telemetryLoader.c
//
// eBPF telemetry loader and controller.
//
//====================================================================

#include <unistd.h>
#include <asm/unistd.h>
#include <stdlib.h>
#include <libbpf.h>
#include <sys/resource.h>
#include <bpf.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/utsname.h>
#include <types.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <net/ethernet.h>
#include <linux/limits.h>
#include "libsysinternalsEBPF.h"
#include "discoverOffsets.h"
#include "unameOffsets.h"
#include "searchOffsets.h"
#include "sysinternalsEBPF.h"
#include "syscalls.h"


typedef void (EventCallback_u32)(void *ctx, int cpu, void *data, __u32 size);
typedef void (EventLostCallback_u64)(void *ctx, int cpu, __u64 lostCnt);

bool linkTPprogs(const ebpfTelemetryObject *obj, const bool *activeSyscalls);
bool linkRTPprogs(const ebpfTelemetryObject *obj, const bool *activeSyscalls);
bool linkOtherTPprogs(const ebpfTelemetryObject *obj, const bool *activeSyscalls);

extern const syscallNames       syscallNumToName[SYSCALL_MAX+1];

static struct bpf_object        *bpfObj = NULL;
struct perf_buffer_opts         pbOpts = {};
struct perf_buffer              *pb = NULL;

typedef struct {
    unsigned int                numProgs;
    struct bpf_program          **prog;
    unsigned int                numLinks;
    struct bpf_link             **link;
} ebpfTPprogs;

const ebpfTelemetryObject       *object = NULL;
ebpfConfig                      config;
int                             configMapFd = 0;
int                             perfErrorsMapFd = 0;

unsigned int                    numSysEnter;
unsigned int                    numSysExit;
unsigned int                    numRawSysEnter;
unsigned int                    numRawSysExit;
unsigned int                    numOtherTp;

static ebpfTPprogs              *bpfSysEnter;
static ebpfTPprogs              *bpfSysExit;

static struct bpf_program       **bpfRawSysEnter;
static struct bpf_program       **bpfRawSysExit;
static struct bpf_link          **bpfRawSysEnterLink;
static struct bpf_link          **bpfRawSysExitLink;

static struct bpf_program       **bpfOtherTp;
static struct bpf_link          **bpfOtherTpLink;

bool                            rawTracepoints = false;
enum direction                  {forwards, backwards};

struct bpf_object               *rawBpfObj = NULL;
int                             rawSock = -1;

double                          g_bootSecSinceEpoch = 0;

bool                            running = true;
bool                            signalInterrupt = false;

eBPFerrorString                 eBPFerrorStrings[] =
{
{   E_EBPF_SUCCESS,             "Operation completed successfully"},
{   E_EBPF_CATASTROPHIC,        "Catastrophic failure"},
{   E_EBPF_NOTSUPPORTED,        "Operation not supported"},
{   E_EBPF_NOPROG,              "eBPF object could not be located"},
{   E_EBPF_NOMAP,               "eBPF map could not be located"},
{   E_EBPF_NOATTACH,            "eBPF program could not be attached"},
{   E_EBPF_NORB,                "perf ring buffer could not be started"},
{   E_EBPF_NOFILEPATH,          "eBPF program could not be opened"},
{   E_EBPF_INVALIDPARAMS,       "Invalid parameters"},
{   E_EBPF_NOTP,                "Syscall tracepoint programs could not be located"},
{   E_EBPF_NORTP,               "Syscall raw tracepoint programs could not be located"},
{   E_EBPF_NOOTHTP,             "Non-syscall tracepoint programs could not be located"},
{   E_EBPF_NOLOAD,              "eBPF object could not be loaded"},
{   E_EBPF_CONFIGFAIL,          "Configuration could not be loaded"},
{   E_EBPF_MAPUPDATEFAIL,       "Map could not be updated"},
{   E_EBPF_NORAWSOCK,          "Raw socket program could not be attached"},

{   E_DISC_CATASTROPHIC,        "Discovery - catastrophic failure"},
{   E_DISC_NOTSUPPORTED,        "Discovery - operation not supported"},
{   E_DISC_NOPROG,              "Discovery - eBPF programs could not be loaded"},
{   E_DISC_NOMAP,               "Discovery - map could not be located"},
{   E_DISC_NOATTACH,            "Discovery - eBPF program could not be attached"},
{   E_DISC_NORB,                "Discovery - perf ring buffer could not be started"},
{   E_DISC_NOPDEATH,            "Discovery - cannot set PDEATH signal"},
{   E_DISC_NOTASK,              "Discovery - could not obtain task struct"},
{   E_DISC_GET_COMM,            "Discovery - could not read COMM from /proc"},
{   E_DISC_PID_OFFSET,          "Discovery - could not find PID offset"},
{   E_DISC_START_TIME_OFFSET,   "Discovery - could not find start_time offset"},
{   E_DISC_COMM_OFFSET,         "Discovery - could not find COMM offset"},
{   E_DISC_CREDS_OFFSET,        "Discovery - could not find creds offsets"},
{   E_DISC_PWD_PATH_OFFSET,     "Discovery - could not find path offset"},
{   E_DISC_DENTRY_NAME_OFFSET,  "Discovery - could not find dentry name offset"},
{   E_DISC_DENTRY_PARENT_OFFSET,"Discovery - could not find dentry parent offset"},
{   E_DISC_DENTRY_INODE_OFFSET, "Discovery - could not find dentry inode offset"},
{   E_DISC_MOUNT_OFFSET,        "Discovery - could not find mount offset"},
{   E_DISC_FD_OFFSET,           "Discovery - could not find the file descriptor offsets"},
{   E_DISC_TTY_OFFSET,          "Discovery - could not find the TTY offsets"},
{   E_DISC_MM_OFFSET,           "Discovery - could not find the MM offsets"},
{   E_DISC_EXE_PATH_OFFSET,     "Discovery - could not find the exe offsets"},
{   E_DISC_SKBUFF_OFFSET,       "Discovery - could not find the skbuff offsets"},
};


//--------------------------------------------------------------------
//
// eBPFstrerror
//
// Convert an eBPF error number to a printable error string.
//
//--------------------------------------------------------------------
const char *eBPFstrerror(int error)
{
    unsigned int i;
    unsigned int numErrors = sizeof(eBPFerrorStrings) / sizeof(*eBPFerrorStrings);

    for (i=0; i<numErrors; i++) {
        if (eBPFerrorStrings[i].error == error)
            return eBPFerrorStrings[i].str;
    }

    return "";
}


//--------------------------------------------------------------------
//
// telemetryCloseAll
//
// Shut down all eBPF telemetry and free memory.
//
//--------------------------------------------------------------------
void telemetryCloseAll()
{

    unsigned int i, j;

    if (!rawTracepoints) {
        for (i=0; i<numSysEnter; i++) {
            ebpfTPprogs *s = &bpfSysEnter[i];
            for (j=0; j<s->numLinks; j++) {
                if (s->link[j] != NULL) {
                    bpf_link__destroy(s->link[j]);
                }
            }
            if (s->prog)
                free(s->prog);
            if (s->link)
                free(s->link);
        }
        if (bpfSysEnter) {
            free(bpfSysEnter);
            bpfSysEnter = NULL;
        }

        for (i=0; i<numSysExit; i++) {
            ebpfTPprogs *s = &bpfSysExit[i];
            for (j=0; j<s->numLinks; j++) {
                if (s->link[j] != NULL) {
                    bpf_link__destroy(s->link[j]);
                }
            }
            if (s->prog)
                free(s->prog);
            if (s->link)
                free(s->link);
        }
        if (bpfSysExit) {
            free(bpfSysExit);
            bpfSysExit = NULL;
        }
    } else {
        for (i=0; i<numRawSysEnter; i++) {
            if (bpfRawSysEnterLink[i] != NULL) {
                bpf_link__destroy(bpfRawSysEnterLink[i]);
            }
        }
        if (bpfRawSysEnterLink) {
            free(bpfRawSysEnterLink);
            bpfRawSysEnterLink = NULL;
        }
        if (bpfRawSysEnter) {
            free(bpfRawSysEnter);
            bpfRawSysEnter = NULL;
        }

        for (i=0; i<numRawSysExit; i++) {
            if (bpfRawSysExitLink[i] != NULL) {
                bpf_link__destroy(bpfRawSysExitLink[i]);
            }
        }
        if (bpfRawSysExitLink) {
            free(bpfRawSysExitLink);
            bpfRawSysExitLink = NULL;
        }
        if (bpfRawSysExit) {
            free(bpfRawSysExit);
            bpfRawSysExit = NULL;
        }
    }

    if (numOtherTp > 0) {
        for (i=0; i<numOtherTp; i++) {
            if (bpfOtherTp[i] != NULL) {
                bpf_link__destroy(bpfOtherTpLink[i]);
            }
        }
        if (bpfOtherTp) {
            free(bpfOtherTp);
            bpfOtherTp = NULL;
        }
        if (bpfOtherTpLink) {
            free(bpfOtherTpLink);
            bpfOtherTpLink = NULL;
        }
    }

    if (bpfObj) {
        bpf_object__close(bpfObj);
        bpfObj = NULL;
    }

    if (pb) {
        perf_buffer__free(pb);
        pb = NULL;
    }

    if (rawSock != -1) {
        close(rawSock);
        bpf_object__close(rawBpfObj);
        rawBpfObj = NULL;
        rawSock = -1;
    }
}

//--------------------------------------------------------------------
//
// telemetrySignalInterrupt
//
// Inform the control loop that the signal just received was expected,
// to avoid the control loop assuming the error exit from the poll was
// a catastrophic error.
//
//--------------------------------------------------------------------
void telemetrySignalInterrupt(int code)
{
    signalInterrupt = true;
}

//--------------------------------------------------------------------
//
// telemetryUpdateSyscalls
//
// Stop running eBPF programs and relink with new activeSyscalls array
// values. Used to update when the configuration changes.
//
//--------------------------------------------------------------------
void telemetryUpdateSyscalls(bool *activeSyscalls)
{
    if (activeSyscalls == NULL) {
        fprintf(stderr, "ebpfTelemetryUpdateSyscalls invalid params\n");
        return;
    }

    unsigned int i, j;
    unsigned int configEntry = 0;

    if (!rawTracepoints) {
        // destroy old links
        for (i=0; i<numSysEnter; i++) {
            ebpfTPprogs *p = &bpfSysEnter[i];
            for (j=0; j<p->numLinks; j++) {
                if (p->link[j] != NULL) {
                    bpf_link__destroy(p->link[j]);
                    p->link[j] = NULL;
                }
            }
        }

        for (i=0; i<numSysExit; i++) {
            ebpfTPprogs *p = &bpfSysExit[i];
            for (j=0; j<p->numLinks; j++) {
                if (p->link[j] != NULL) {
                    bpf_link__destroy(p->link[j]);
                    p->link[j] = NULL;
                }
            }
        }

        // link to new syscall config
        linkTPprogs(object, activeSyscalls);
    } else {
        // destroy old links
        for (i=0; i<numRawSysEnter; i++) {
            if (bpfRawSysEnterLink[i] != NULL) {
                bpf_link__destroy(bpfRawSysEnterLink[i]);
            }
        }

        for (i=0; i<numRawSysExit; i++) {
            if (bpfRawSysExitLink[i] != NULL) {
                bpf_link__destroy(bpfRawSysExitLink[i]);
            }
        }

        // link to new syscall config
        linkRTPprogs(object, activeSyscalls);
    }

    // destroy old links
    if (numOtherTp > 0) {
        for (i=0; i<numOtherTp; i++) {
            if (bpfOtherTpLink[i] != NULL) {
                bpf_link__destroy(bpfOtherTpLink[i]);
            }
        }
    }

    // link to new syscall config
    linkOtherTPprogs(object, activeSyscalls);

    // update syscall config in EBPF
    memcpy(config.active, activeSyscalls, sizeof(config.active));
    bpf_map_update_elem(configMapFd, &configEntry, &config, BPF_ANY);
}

//--------------------------------------------------------------------
//
// connectRawSock
//
// Connect the raw socket eBPF program to a new raw socket.
// (Enables skb/consume_skb tracepoint to see outbound packets.)
//
//--------------------------------------------------------------------
bool connectRawSock(const ebpfTelemetryConfig *ebpfConfig)
{
    char filepath[] = SYSINTERNALS_EBPF_INSTALL_DIR "/" EBPF_RAW_SOCK_OBJ;
    struct stat filepathStat;
    int rawProgFd = -1;
    struct bpf_program *rawBpfProg = NULL;

    // check path
    if (stat(filepath, &filepathStat) != 0 || !S_ISREG(filepathStat.st_mode)) {
        fprintf(stderr, "ERROR: cannot access EBPF kernel object: %s\n", filepath);
        return false;
    }

    struct bpf_object_open_opts openopts = {};
    openopts.sz = sizeof(struct bpf_object_open_opts);
    if(ebpfConfig->btfFile)
    {
        openopts.btf_custom_path = ebpfConfig->btfFile;
    }

    rawBpfObj = bpf_object__open_file(filepath, &openopts);
    if (libbpf_get_error(bpfObj)) {
        fprintf(stderr, "ERROR: failed to open prog: %s '%s'\n", filepath, strerror(errno));
        return false;
    }

    rawBpfProg = bpf_object__find_program_by_name(rawBpfObj, "rawEBPFprog");
    if (rawBpfProg == NULL) {
        fprintf(stderr, "ERROR: failed to locate program: %s '%s'\n", filepath, strerror(errno));
        return false;
    }

    bpf_program__set_type(rawBpfProg, BPF_PROG_TYPE_SOCKET_FILTER);

    if (bpf_object__load(rawBpfObj)) {
        fprintf(stderr, "ERROR: failed to load prog: %s '%s'\n", filepath, strerror(errno));
        return false;
    }

    rawProgFd = bpf_program__fd(rawBpfProg);

    if (rawProgFd < 0) {
        fprintf(stderr, "ERROR: failed to find prog: %s '%s'\n", filepath, strerror(errno));
        return false;
    }

    rawSock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (rawSock < 0) {
        fprintf(stderr, "ERROR: cannot open raw socket: '%s'\n", strerror(errno));
        return false;
    }

    if (setsockopt(rawSock, SOL_SOCKET, SO_ATTACH_BPF, &rawProgFd, sizeof(rawProgFd)) < 0) {
        fprintf(stderr, "ERROR: setsockopt failed on raw socket: '%s'\n", strerror(errno));
        return false;
    }

    return true;
}

//--------------------------------------------------------------------
//
// insertConfigOffsets
//
// Extract offsets from comma-separated string and insert into array.
//
//--------------------------------------------------------------------
bool insertConfigOffsets(unsigned int *item, char *value)
{
    if (item == NULL || value == NULL) {
        fprintf(stderr, "insertConfigOffsets invalid params\n");
        return false;
    }

    const char *offset = NULL;
    unsigned int i;
    char *innerStrtok = NULL;

    offset = strtok_r(value, " ,", &innerStrtok);
    if (!offset) {
        item[0] = -1;
        return false;
    }

    i = 0;

    while (offset && i < (NUM_REDIRECTS - 1)) {
        item[i] = atoi(offset);
        offset = strtok_r(NULL, " ,", &innerStrtok);
        i++;
    }
    item[i] = DEREF_END;

    return true;
}

//--------------------------------------------------------------------
//
// populateConfigOffsets
//
// Obtain kernel struct offsets from the config file, the offsets
// database, or via discovery, and store in the config..
//
//--------------------------------------------------------------------
bool populateConfigOffsets(ebpfConfig *c, const char *argv[],
        time_t procStartTime)
{
    if (c == NULL || argv == NULL) {
        fprintf(stderr, "populateConfigOffsets invalid params\n");
        return false;
    }

    FILE *config;
    char *line = NULL;
    size_t len = 0;
    ssize_t readLen;
    char *param = NULL;
    char *value = NULL;
    char *whitespace = NULL;
    unsigned int *item = NULL;
    char *outerStrtok = NULL;

    if(!fileExists(BTF_KERNEL_FILE))
    {
        config = fopen(CONFIG_FILE, "r");
        if (!config) {
            if (searchOffsets(&c->offsets)) {
                fprintf(stderr, "Discovery process: from database\n");
                return true;
            }

            fprintf(stderr, "Discovery process: auto discovery\n");
            return (discoverOffsets(&c->offsets, argv, procStartTime) == E_EBPF_SUCCESS);
        }

        fprintf(stderr, "Discovery process: getOffsets\n");

        while ((readLen = getline(&line, &len, config)) >= 0) {
            if (readLen > 0 && line[0] == '#')
                continue;
            whitespace = line;
            while (*whitespace == ' ')
                whitespace++;
            param = strtok_r(whitespace, " =", &outerStrtok);
            if (!param)
                continue;
            value = strtok_r(NULL, "\n", &outerStrtok);
            if (!value)
                continue;
            whitespace = value;
            while (*whitespace == ' ' || *whitespace == '=')
                whitespace++;
            value = whitespace;

            item = findConfigItem(&c->offsets, param);

            if (item)
                insertConfigOffsets(item, value);
        }

        free(line);
        fclose(config);
    }
    else
    {
        fprintf(stderr, "Discovery process: BTF-CORE\n");
    }

    return true;
}

//--------------------------------------------------------------------
//
// combineKernelVersion
//
// Converts the kernel version to a uint32_t that can be easily
// compared.
//
//--------------------------------------------------------------------
uint32_t combineKernelVersion(uint32_t major, uint32_t minor)
{
    return (major << 16) + minor;
}

//--------------------------------------------------------------------
//
// getKernelVersion
//
// Get the kernel version from the uname and return as a uint32_t.
//
//--------------------------------------------------------------------
uint32_t getKernelVersion()
{
    unsigned int                major = 0, minor = 0;
    struct utsname              unameStruct = {{ 0 }};

    if (uname(&unameStruct)){
        fprintf(stderr, "Couldn't find uname, '%s'\n", strerror(errno));
        return 0;
    }

    if (sscanf(unameStruct.release, "%u.%u", &major, &minor) == 2){
        fprintf(stderr, "Found Kernel version: %u.%u\n", major, minor);
    } else {
        fprintf(stderr, "Couldn't find version\n");
        return 0;
    }

    return combineKernelVersion(major, minor);
}

//--------------------------------------------------------------------
//
// getObjectAndPath
//
// Search the telemetry config for a suitable kernel object.
//
//--------------------------------------------------------------------
const ebpfTelemetryObject *getObjectAndPath(char *filepath,
        unsigned int size, const ebpfTelemetryConfig *ebpfConfig)
{
    if (filepath == NULL || ebpfConfig == NULL) {
        fprintf(stderr, "getObjectAndPath invalid params\n");
        return NULL;
    }

    const char                  *filename = NULL;
    struct stat                 filepathStat;
    const ebpfTelemetryObject   *ebpfObj = NULL;
    unsigned int                i = 0;

    // combine kernel major and minor for easy comparisons
    uint32_t combinedKernelVersion = getKernelVersion();

    // find first matching EBPF ELF object
    for (i=0; i<ebpfConfig->numEBPFobjects; i++) {
        ebpfObj = &ebpfConfig->objects[i];
        uint32_t minVersion = combineKernelVersion(ebpfObj->minKernel.major, ebpfObj->minKernel.minor);
        uint32_t ltVersion = combineKernelVersion(ebpfObj->lessthanKernel.major, ebpfObj->lessthanKernel.minor);
        if (combinedKernelVersion >= minVersion &&
                (ltVersion == 0 || combinedKernelVersion < ltVersion)) {
            filename = ebpfObj->filename;
            break;
        }
    }

    if (filename == NULL) {
        fprintf(stderr, "Kernel version not supported\n");
        return NULL;
    }

    // discover path
    for (i=0; i<ebpfConfig->numDefaultPaths; i++) {
        snprintf(filepath, size, "%s/%s", ebpfConfig->defaultPaths[i], filename);
        if (stat(filepath, &filepathStat) == 0 && S_ISREG(filepathStat.st_mode)) {
            return ebpfObj;
        }
    }

    fprintf(stderr, "Cannot locate EBPF kernel object: %s\n", filename);
    return NULL;
}

//--------------------------------------------------------------------
//
// locateTPprogs
//
// Build arrays of enter and exit syscall tracepoint programs, with
// space for links.
//
//--------------------------------------------------------------------
bool locateTPprogs(const ebpfTelemetryObject *obj)
{
    if (obj == NULL) {
        fprintf(stderr, "locateTPprogs invalid params\n");
        return false;
    }

    unsigned int                i;

    bpfSysEnter = (ebpfTPprogs *)calloc(sizeof(ebpfTPprogs), numSysEnter);
    bpfSysExit = (ebpfTPprogs *)calloc(sizeof(ebpfTPprogs), numSysExit);
    if (bpfSysEnter == NULL || bpfSysExit == NULL) {
        if (bpfSysEnter) {
            free (bpfSysEnter);
            bpfSysEnter = NULL;
        }
        if (bpfSysExit) {
            free (bpfSysExit);
            bpfSysExit = NULL;
        }
        fprintf(stderr, "Cannot calloc\n");
        return false;
    }

    // sys_enter tracepoints
    for (i=0; i<numSysEnter; i++) {
        const ebpfSyscallTPprog *p = &obj->syscallTPenterProgs[i];
        ebpfTPprogs *s = &bpfSysEnter[i];
        if (p->syscall == EBPF_GENERIC_SYSCALL) {
            // attach this to all active syscall enter tracepoints
            s->numProgs = NUM_ARGS + 1;
            s->numLinks = SYSCALL_MAX + 1;
        } else {
            // attach this to specified enter tracepoint
            s->numProgs = 1;
            s->numLinks = 1;
        }

        s->prog = (struct bpf_program **)calloc(sizeof(struct bpf_program *), s->numProgs);
        s->link = (struct bpf_link **)calloc(sizeof(struct bpf_link *), s->numLinks);
        if (s->prog == NULL || s->link == NULL) {
            if (s->prog) {
                free( s->prog);
                s->prog = NULL;
            }
            if (s->link) {
                free( s->link);
                s->link = NULL;
            }
            fprintf(stderr, "Cannot calloc\n");
            return false;
        }

        if (p->syscall == EBPF_GENERIC_SYSCALL) {
            // attach this to all active syscall enter tracepoints
            char *programName = strdup(p->program);
            unsigned int programNameLen = strlen(programName);
            unsigned int n = 0;
            for (n=0; n<7; n++) {
                programName[programNameLen - 1] = '0' + n;
                if ((s->prog[n] = bpf_object__find_program_by_name(bpfObj, programName)) == NULL) {
                    fprintf(stderr, "ERROR: failed to find program: '%s' '%s'\n", programName, strerror(errno));
                    return false;
                }
                bpf_program__set_type(s->prog[n], BPF_PROG_TYPE_TRACEPOINT);
            }
        } else {
            // attach this to specified enter tracepoint
            if ((s->prog[0] = bpf_object__find_program_by_name(bpfObj, p->program)) == NULL) {
                fprintf(stderr, "ERROR: failed to find program: '%s' '%s'\n", p->program, strerror(errno));
                return false;
            }
            bpf_program__set_type(s->prog[0], BPF_PROG_TYPE_TRACEPOINT);
        }
    }

    // sys_exit tracepoints
    for (i=0; i<numSysExit; i++) {
        const ebpfSyscallTPprog *p = &obj->syscallTPexitProgs[i];
        ebpfTPprogs *s = &bpfSysExit[i];
        s->numProgs = 1; // all exit programs have same number of arguments
        if (p->syscall == EBPF_GENERIC_SYSCALL) {
            // attach this to all active syscall exit tracepoints
            s->numLinks = SYSCALL_MAX + 1;
        } else {
            // attach this to specified exit tracepoint
            s->numLinks = 1;
        }

        s->prog = (struct bpf_program **)calloc(sizeof(struct bpf_program *), s->numProgs);
        s->link = (struct bpf_link **)calloc(sizeof(struct bpf_link *), s->numLinks);
        if (s->prog == NULL || s->link == NULL) {
            if (s->prog) {
                free( s->prog);
                s->prog = NULL;
            }
            if (s->link) {
                free( s->link);
                s->link = NULL;
            }
            fprintf(stderr, "Cannot calloc\n");
            return false;
        }

        if ((s->prog[0] = bpf_object__find_program_by_name(bpfObj, p->program)) == NULL) {
            fprintf(stderr, "ERROR: failed to find program: '%s' '%s'\n", p->program, strerror(errno));
            return false;
        }
        bpf_program__set_type(s->prog[0], BPF_PROG_TYPE_TRACEPOINT);
    }

    return true;
}

//--------------------------------------------------------------------
//
// locateRTPprogs
//
// Build arrays for enter and exit raw syscall tracepoint programs and
// links.
//
//--------------------------------------------------------------------
bool locateRTPprogs(const ebpfTelemetryObject *obj)
{
    if (obj == NULL) {
        fprintf(stderr, "locateRTPprogs invalid params\n");
        return false;
    }

    unsigned int                i;

    bpfRawSysEnter = (struct bpf_program **)calloc(sizeof(struct bpf_program *), numRawSysEnter);
    bpfRawSysEnterLink = (struct bpf_link **)calloc(sizeof(struct bpf_link *), numRawSysEnter);
    bpfRawSysExit = (struct bpf_program **)calloc(sizeof(struct bpf_program *), numRawSysExit);
    bpfRawSysExitLink = (struct bpf_link **)calloc(sizeof(struct bpf_link *), numRawSysExit);
    if (bpfRawSysEnter == NULL || bpfRawSysEnterLink == NULL ||
                bpfRawSysExit == NULL || bpfRawSysExitLink == NULL) {
        if (bpfRawSysEnter) {
            free( bpfRawSysEnter );
            bpfRawSysEnter = NULL;
        }
        if (bpfRawSysEnterLink) {
            free( bpfRawSysEnterLink );
            bpfRawSysEnterLink = NULL;
        }
        if (bpfRawSysExit) {
            free( bpfRawSysExit );
            bpfRawSysExit = NULL;
        }
        if (bpfRawSysExitLink) {
            free( bpfRawSysExitLink );
            bpfRawSysExitLink = NULL;
        }
        fprintf(stderr, "Cannot calloc\n");
        return false;
    }

    // raw sys_enter tracepoint
    for (i=0; i<numRawSysEnter; i++) {
        const ebpfSyscallRTPprog *p = &obj->syscallRTPenterProgs[i];
        if ((bpfRawSysEnter[i] = bpf_object__find_program_by_name(bpfObj, p->program)) == NULL) {
            fprintf(stderr, "ERROR: failed to find program: '%s' '%s'\n", p->program, strerror(errno));
            return false;
        }
        bpf_program__set_type(bpfRawSysEnter[i], BPF_PROG_TYPE_RAW_TRACEPOINT);
    }

    for (i=0; i<numRawSysExit; i++) {
        const ebpfSyscallRTPprog *p = &obj->syscallRTPexitProgs[i];
        if ((bpfRawSysExit[i] = bpf_object__find_program_by_name(bpfObj, p->program)) == NULL) {
            fprintf(stderr, "ERROR: failed to find program: '%s' '%s'\n", p->program, strerror(errno));
            return false;
        }
        bpf_program__set_type(bpfRawSysExit[i], BPF_PROG_TYPE_RAW_TRACEPOINT);
    }

    return true;
}

//--------------------------------------------------------------------
//
// locateOtherTPprogs
//
// Build arrays for non-syscall tracepoint programs and links.
//
//--------------------------------------------------------------------
bool locateOtherTPprogs(const ebpfTelemetryObject *obj)
{
    if (obj == NULL) {
        fprintf(stderr, "locateOtherTPprogs invalid params\n");
        return false;
    }

    unsigned int                i;

    bpfOtherTp = (struct bpf_program **)calloc(sizeof(struct bpf_program *), numOtherTp);
    bpfOtherTpLink = (struct bpf_link **)calloc(sizeof(struct bpf_link *), numOtherTp);
    if (bpfOtherTp == NULL || bpfOtherTpLink == NULL) {
        if (bpfOtherTp) {
            free( bpfOtherTp );
            bpfOtherTp = NULL;
        }
        if (bpfOtherTpLink) {
            free( bpfOtherTpLink );
            bpfOtherTpLink = NULL;
        }
        fprintf(stderr, "Cannot calloc\n");
        return false;
    }

    for (i=0; i<numOtherTp; i++) {
        const ebpfTracepointProg *p = &obj->otherTPprogs[i];
        if ((bpfOtherTp[i] = bpf_object__find_program_by_name(bpfObj, p->program)) == NULL) {
            fprintf(stderr, "ERROR: failed to find program: '%s' '%s'\n", p->program, strerror(errno));
            return false;
        }
        bpf_program__set_type(bpfOtherTp[i], BPF_PROG_TYPE_TRACEPOINT);
    }

    return true;
}

//--------------------------------------------------------------------
//
// populateConfig
//
// Initialise the eBPF config, including locating suitable kernel
// offsets.
//
//--------------------------------------------------------------------
bool populateConfig(ebpfConfig *config,
        const ebpfTelemetryObject *obj, const char *argv[],
        time_t procStartTime)
{
    if (config == NULL || obj == NULL || argv == NULL) {
        fprintf(stderr, "populateConfig invalid params\n");
        return false;
    }

    config->userlandPid = getpid();
    config->bootNsSinceEpoch = g_bootSecSinceEpoch * (1000 * 1000 * 1000);
    memcpy(config->active, obj->activeSyscalls, sizeof(config->active));
    if (!populateConfigOffsets(config, argv, procStartTime)) {
        fprintf(stderr, "Could not automatically discover kernel offsets.\n");
        fprintf(stderr, "Build and run the get_offsets module to generate the offsets config file:\n");
        fprintf(stderr, "/opt/sysinternalsEBPF/sysinternalsEBPF_offsets.conf\n\n");
        return false;
    }
    return true;
}

//--------------------------------------------------------------------
//
// linkTPprogs
//
// Link the required tracepoint programs based on the activeSyscalls
// config.
//
//--------------------------------------------------------------------
bool linkTPprogs(const ebpfTelemetryObject *obj,
        const bool *activeSyscalls)
{
    if (obj == NULL || activeSyscalls == NULL) {
        fprintf(stderr, "linkTPprogs invalid params\n");
        return false;
    }

    unsigned int            i;
    char                    tp[SYSCALL_NAME_LEN * 2];
    unsigned int            syscall = 0;

    for (i=0; i<numSysEnter; i++) {
        const ebpfSyscallTPprog *p = &obj->syscallTPenterProgs[i];
        ebpfTPprogs *s = &bpfSysEnter[i];
        memset(s->link, 0, sizeof(struct bpf_link *) * s->numLinks);
        if (p->syscall == EBPF_GENERIC_SYSCALL) {
            // attach this to all active syscall enter tracepoints
            for (syscall=0; syscall<=SYSCALL_MAX; syscall++) {
                if (activeSyscalls[syscall]) {
                    snprintf(tp, SYSCALL_NAME_LEN * 2, "sys_enter_%s", syscallNumToName[syscall].name);
                    unsigned int numArgs = syscallNumToName[syscall].numArgs;
                    s->link[syscall] = bpf_program__attach_tracepoint(s->prog[numArgs], "syscalls", tp);
                    if (libbpf_get_error(s->link[syscall]))
                        return false;
                }
            }
        } else if (activeSyscalls[p->syscall]) {
            snprintf(tp, SYSCALL_NAME_LEN * 2, "sys_enter_%s", syscallNumToName[p->syscall].name);
            s->link[0] = bpf_program__attach_tracepoint(s->prog[0], "syscalls", tp);
            if (libbpf_get_error(s->link[0]))
                return false;
        }
    }

    for (i=0; i<numSysExit; i++) {
        const ebpfSyscallTPprog *p = &obj->syscallTPexitProgs[i];
        ebpfTPprogs *s = &bpfSysExit[i];
        memset(s->link, 0, sizeof(struct bpf_link *) * s->numLinks);
        if (p->syscall == EBPF_GENERIC_SYSCALL) {
            // attach this to all active syscall exit tracepoints
            for (syscall=0; syscall<=SYSCALL_MAX; syscall++) {
                if (activeSyscalls[syscall]) {
                    snprintf(tp, SYSCALL_NAME_LEN * 2, "sys_exit_%s", syscallNumToName[syscall].name);
                    s->link[syscall] = bpf_program__attach_tracepoint(s->prog[0], "syscalls", tp);
                    if (libbpf_get_error(s->link[syscall]))
                        return false;
                }
            }
        } else if (activeSyscalls[p->syscall]) {
            snprintf(tp, SYSCALL_NAME_LEN * 2, "sys_exit_%s", syscallNumToName[p->syscall].name);
            s->link[0] = bpf_program__attach_tracepoint(s->prog[0], "syscalls", tp);
            if (libbpf_get_error(s->link[0]))
                return false;
        }
    }

    return true;
}

//--------------------------------------------------------------------
//
// linkRTPprogs
//
// Link the required raw tracepoint programs based on the
// activeSyscalls config.
//
//--------------------------------------------------------------------
bool linkRTPprogs(const ebpfTelemetryObject *obj,
        const bool *activeSyscalls)
{
    if (obj == NULL || activeSyscalls == NULL) {
        fprintf(stderr, "linkRTPprogs invalid params\n");
        return false;
    }

    unsigned int                i;
    const char                  *prev = NULL;
    const char                  *cur = NULL;
    bool                        alreadyAttached = false;

    memset(bpfRawSysEnterLink, 0, sizeof(struct bpf_link *) * numRawSysEnter);
    memset(bpfRawSysExitLink, 0, sizeof(struct bpf_link *) * numRawSysExit);

    for (i=0; i<numRawSysEnter; i++) {
        const ebpfSyscallRTPprog *p = &obj->syscallRTPenterProgs[i];
        cur = p->program;
        if (prev != NULL && strcmp(prev, cur) != 0) {
            alreadyAttached = false;
        }
        if ((prev == NULL || !alreadyAttached) && (p->syscall == EBPF_GENERIC_SYSCALL || activeSyscalls[p->syscall])) {
            bpfRawSysEnterLink[i] = bpf_program__attach_raw_tracepoint(bpfRawSysEnter[i], "sys_enter");
            if (libbpf_get_error(bpfRawSysEnterLink[i])) {
                fprintf(stderr, "Cannot link\n");
                return false;
            }
            alreadyAttached = true;
        }
        prev = cur;
    }

    prev = NULL;
    for (i=0; i<numRawSysExit; i++) {
        const ebpfSyscallRTPprog *p = &obj->syscallRTPexitProgs[i];
        cur = p->program;
        if (prev != NULL && strcmp(prev, cur) != 0) {
            alreadyAttached = false;
        }
        if ((prev == NULL || !alreadyAttached) && (p->syscall == EBPF_GENERIC_SYSCALL || activeSyscalls[p->syscall])) {
            bpfRawSysExitLink[i] = bpf_program__attach_raw_tracepoint(bpfRawSysExit[i], "sys_exit");
            if (libbpf_get_error(bpfRawSysExitLink[i])) {
                fprintf(stderr, "Cannot link\n");
                return false;
            }
            alreadyAttached = true;
        }
        prev = cur;
    }

    return true;
}

//--------------------------------------------------------------------
//
// linkOtherTPprogs
//
// Link the required non-syscall tracepoint programs based on the
// activeSyscalls config.
//
//--------------------------------------------------------------------
bool linkOtherTPprogs(const ebpfTelemetryObject *obj,
        const bool *activeSyscalls)
{
    if (obj == NULL || activeSyscalls == NULL) {
        fprintf(stderr, "linkOtherTPprogs invalid params\n");
        return false;
    }

    unsigned int                i;
    const char                  *prevProg = NULL;
    const char                  *curProg = NULL;
    const char                  *prevFamily = NULL;
    const char                  *curFamily = NULL;
    const char                  *prevTP = NULL;
    const char                  *curTP = NULL;
    bool                        alreadyAttached = false;

    memset(bpfOtherTpLink, 0, sizeof(struct bpf_link *) * numOtherTp);

    for (i=0; i<numOtherTp; i++) {
        const ebpfTracepointProg *p = &obj->otherTPprogs[i];
        curProg = p->program;
        curFamily = p->family;
        curTP = p->tracepoint;
        if (prevProg != NULL && (strcmp(prevProg, curProg) != 0 || strcmp(prevFamily, curFamily) != 0 ||
                strcmp(prevTP, curTP) != 0)) {
            alreadyAttached = false;
        }
        if ((prevProg == NULL || !alreadyAttached) && (p->pseudoSyscall == EBPF_GENERIC_SYSCALL ||
                activeSyscalls[p->pseudoSyscall])) {
            bpfOtherTpLink[i] = bpf_program__attach_tracepoint(bpfOtherTp[i], p->family, p->tracepoint);
            if (libbpf_get_error(bpfOtherTpLink[i])) {
                fprintf(stderr, "Cannot link\n");
                return false;
            }
            alreadyAttached = true;
        }
    }

    return true;
}

//--------------------------------------------------------------------
//
// populateOtherMaps
//
// Populate the user-specified eBPF maps from the config.
//
//--------------------------------------------------------------------
bool populateOtherMaps(int *fds, const unsigned int numMapObjects,
        const ebpfTelemetryMapObject *mapObjects)
{
    if (fds == NULL || mapObjects == NULL) {
        fprintf(stderr, "populateOtherMaps invalid params\n");
        return false;
    }

    unsigned int                i, j;

    for (i=0; i<numMapObjects; i++) {
        // find the named map
        fds[i] = bpf_object__find_map_fd_by_name(bpfObj, mapObjects[i].name);
        if (fds[i] <= 0) {
            fprintf(stderr, "ERROR: failed to load map_fd for map '%s': '%s'\n", mapObjects[i].name, strerror(errno));
            return false;
        }

        // populate the map
        for (j=0; j<mapObjects[i].numElements; j++) {
            if (bpf_map_update_elem(fds[i], mapObjects[i].keys[j], mapObjects[i].values[j], BPF_ANY)) {
                fprintf(stderr, "ERROR: failed to set map element %d for map '%s': '%s'\n",
                        j, mapObjects[i].name, strerror(errno));
                return false;
            }
        }
    }

    return true;
}

//--------------------------------------------------------------------
//
// telemetryMapLookupElem
//
// Wrapper for BPF function, that uses the statically linked libbpf.
//
//--------------------------------------------------------------------
long telemetryMapLookupElem(int fd, const void *key, void *value)
{
    if (key == NULL || value == NULL) {
        fprintf(stderr, "telemetryMapLookupElem invalid params\n");
        return -1;
    }

    return bpf_map_lookup_elem(fd, key, value);
}

//--------------------------------------------------------------------
//
// telemetryMapUpdateElem
//
// Wrapper for BPF function, that uses the statically linked libbpf.
//
//--------------------------------------------------------------------
long telemetryMapUpdateElem(int fd, const void *key, const void *value, ebpfUpdateMapMode mode)
{
    if (key == NULL || value == NULL) {
        fprintf(stderr, "telemetryMapUpdateElem invalid params\n");
        return -1;
    }

    uint64_t flags = 0;
    switch (mode) {
        case MAP_UPDATE_CREATE:
            flags = BPF_NOEXIST;
            break;
        case MAP_UPDATE_OVERWRITE:
            flags = BPF_EXIST;
            break;
        case MAP_UPDATE_CREATE_OR_OVERWRITE:
        default:
            flags = BPF_ANY;
    }
    return bpf_map_update_elem(fd, key, value, flags);
}

//--------------------------------------------------------------------
//
// telemetryMapDeleteElem
//
// Wrapper for BPF function, that uses the statically linked libbpf.
//
//--------------------------------------------------------------------
long telemetryMapDeleteElem(int fd, const void *key)
{
    if (key == NULL) {
        fprintf(stderr, "telemetryMapDeleteElem invalid params\n");
        return -1;
    }

    return bpf_map_delete_elem(fd, key);
}

//--------------------------------------------------------------------
//
// checkPerfErrors
//
// Check the perf errors ring buffer for any errors relating to the
// BPF perf ring buffer.
//
//--------------------------------------------------------------------
void checkPerfErrors()
{
    perfError                   readIndex;
    perfError                   writeIndex;
    perfError                   item;
    uint32_t                    readLocation = PERF_ERRORS_READ_INDEX;
    uint32_t                    writeLocation = PERF_ERRORS_WRITE_INDEX;
    struct tm                   timeFields;
    time_t                      curTimeSec;

    if (bpf_map_lookup_elem(perfErrorsMapFd, &readLocation, &readIndex) < 0)
        return;

    if (bpf_map_lookup_elem(perfErrorsMapFd, &writeLocation, &writeIndex) < 0)
        return;

    while (readIndex.index != writeIndex.index) {
        if (bpf_map_lookup_elem(perfErrorsMapFd, &readIndex.index, &item) >= 0) {
            curTimeSec = g_bootSecSinceEpoch + (item.time / (1000 * 1000 * 1000));
            if (gmtime_r(&curTimeSec, &timeFields)) {
                fprintf(stderr, "Perf Ring Buffer Error: %ld @ %04u-%02u-%02uT%02u:%02u:%02uZ\n",
                    item.error,
                    timeFields.tm_year + 1900, timeFields.tm_mon + 1, timeFields.tm_mday,
                    timeFields.tm_hour, timeFields.tm_min, timeFields.tm_sec);
            } else {
                fprintf(stderr, "Perf Ring Buffer Error: %ld\n", item.error);
            }
        }
        readIndex.index = (readIndex.index + 1) & (PERF_ERRORS_MAX - 1);
        bpf_map_update_elem(perfErrorsMapFd, &readLocation, &readIndex, BPF_ANY);
    }
}

//--------------------------------------------------------------------
//
// libbpf_print_fn
//
// Callback invoked by libbpf for logging
//
//--------------------------------------------------------------------
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

//--------------------------------------------------------------------
//
// ebpfStart
//
// Start up the eBPF telemetry engine.
//
//--------------------------------------------------------------------
int ebpfStart(
    const ebpfTelemetryConfig *ebpfConfig,
    char *filepath,
    time_t procStartTime,
    EventCallback *eventCb,
    EventLostCallback *eventsLostCb,
    void *context,
    const char *argv[],
    int *fds,
    bool restart
    )
{
    if (ebpfConfig == NULL || filepath == NULL || eventCb == NULL || eventsLostCb == NULL
            || argv == NULL || fds == NULL) {
        fprintf(stderr, "ebpfStart invalid params\n");
        return E_EBPF_INVALIDPARAMS;
    }

    int                         eventMapFd = 0;
    unsigned int                configEntry = 0;
    int                         ret;
    perfError                   perfIndex;
    uint32_t                    perfIndexIndex;
    struct bpf_program *prog;
    struct bpf_object_open_opts openopts = {};

    // If debug was specified, add extended eBPF logging
    if(ebpfConfig->debug)
    {
        libbpf_set_print(libbpf_print_fn);
    }

    // If we have a standalone BTF file, use it.
    openopts.sz = sizeof(struct bpf_object_open_opts);
    if(ebpfConfig->btfFile)
    {
        openopts.btf_custom_path = ebpfConfig->btfFile;
    }

    bpfObj = bpf_object__open_file(filepath, &openopts);
    if (libbpf_get_error(bpfObj)) {
        fprintf(stderr, "ERROR: failed to open prog: %s '%s'\n", filepath, strerror(errno));
        return E_EBPF_NOPROG;
    }

    if (!rawTracepoints) {
        // traditional syscall tracepoints
        if (!locateTPprogs(object)) {
            return E_EBPF_NOTP;
        }
    } else {
        // raw syscall tracepoints
        if (!locateRTPprogs(object)) {
            return E_EBPF_NORTP;
        }
    }

    if (numOtherTp > 0) {
        // other tracepoints
        if (!locateOtherTPprogs(object)) {

            bpf_object__for_each_program(prog, bpfObj) {
                    const char *name = bpf_program__name(prog);

                    fprintf(stderr, "Prog enum: '%s'\n", name);
            }



            return E_EBPF_NOOTHTP;
        }
    }

    if (bpf_object__load(bpfObj)) {
        fprintf(stderr, "ERROR: failed to load prog: '%s'\n", strerror(errno));
        return E_EBPF_NOLOAD;
    }

    // locate maps
    eventMapFd = bpf_object__find_map_fd_by_name(bpfObj, "eventMap");
    if (eventMapFd <= 0) {
        fprintf(stderr, "ERROR: failed to load eventMapFd: '%s'\n", strerror(errno));
        return E_EBPF_NOMAP;
    }

    configMapFd = bpf_object__find_map_fd_by_name(bpfObj, "configMap");
    if (configMapFd <= 0) {
        fprintf(stderr, "ERROR: failed to load configMapFd: '%s'\n", strerror(errno));
        return E_EBPF_NOMAP;
    }

    perfErrorsMapFd = bpf_object__find_map_fd_by_name(bpfObj, "perfErrorsMap");
    if (perfErrorsMapFd <= 0) {
        fprintf(stderr, "ERROR: failed to load perfErrorsMapFd: '%s'\n", strerror(errno));
        return E_EBPF_NOMAP;
    }

    // set up the configuration
    if (!restart) {
        if (!populateConfig(&config, object, argv, procStartTime)) {
            return E_EBPF_CONFIGFAIL;
        }
    }

    if (bpf_map_update_elem(configMapFd, &configEntry, &config, BPF_ANY)) {
        fprintf(stderr, "ERROR: failed to set config: '%s'\n", strerror(errno));
        return E_EBPF_MAPUPDATEFAIL;
    }

    // config perf error ring buffer
    perfIndexIndex = PERF_ERRORS_READ_INDEX;
    perfIndex.index = 0;
    if (bpf_map_update_elem(perfErrorsMapFd, &perfIndexIndex, &perfIndex, BPF_ANY)) {
        fprintf(stderr, "ERROR: failed to set perf error read index: '%s'\n", strerror(errno));
        return E_EBPF_MAPUPDATEFAIL;
    }

    perfIndexIndex = PERF_ERRORS_WRITE_INDEX;
    perfIndex.index = 0;
    if (bpf_map_update_elem(perfErrorsMapFd, &perfIndexIndex, &perfIndex, BPF_ANY)) {
        fprintf(stderr, "ERROR: failed to set perf error write index: '%s'\n", strerror(errno));
        return E_EBPF_MAPUPDATEFAIL;
    }

    // populate other maps
    if (!populateOtherMaps(fds, ebpfConfig->numMapObjects, ebpfConfig->mapObjects)) {
        fprintf(stderr, "ERROR: failed to populate other maps\n");
        return E_EBPF_MAPUPDATEFAIL;
    }

    // set up perf ring buffer
    pb = perf_buffer__new(eventMapFd, MAP_PAGE_SIZE, eventCb, (EventLostCallback_u64 *)eventsLostCb, context, /*&pbOpts*/ NULL); // param 2 is page_cnt == number of pages to mmap.
    //pb = perf_buffer__new(eventMapFd, MAP_PAGE_SIZE, &pbOpts); // param 2 is page_cnt == number of pages to mmap.
    ret = libbpf_get_error(pb);
    if (ret) {
        fprintf(stderr, "ERROR: failed to setup perf_buffer: %d\n", ret);
        return E_EBPF_NORB;
    }

    // link the programs
    if (!rawTracepoints) {
        if (!linkTPprogs(object, config.active)) {
            return E_EBPF_NOATTACH;
        }
    } else {
        if (!linkRTPprogs(object, config.active)) {
            return E_EBPF_NOATTACH;
        }
    }

    if (numOtherTp > 0) {
        if (!linkOtherTPprogs(object, config.active)) {
            return E_EBPF_NOATTACH;
        }
    }

    // enable raw socket if required
    if (ebpfConfig->enableRawSockCapture) {
        if (!connectRawSock(ebpfConfig)) {
            fprintf(stderr, "ERROR: failed to enable raw socket capture\n");
            return E_EBPF_NORAWSOCK;
        }
    }

    return E_EBPF_SUCCESS;
}

//--------------------------------------------------------------------
//
// getEbpfProgramSizes
//
// Returns the total number of programs in the object file and the
// program names and sizes in the out param
//
//--------------------------------------------------------------------
unsigned int getEbpfProgramSizes(char* objectPath, ebpfProgramSizes** progs)
{
    struct bpf_object* bpfObj = NULL;
    struct bpf_program* bpfProg = NULL;
    int progCount=0;

    bpfObj = bpf_object__open(objectPath);
    if(bpfObj!=NULL)
    {
        bpf_object__for_each_program(bpfProg, bpfObj)
        {
            progCount++;
        }

        if(progCount>0)
        {
            *progs = (ebpfProgramSizes*)calloc(sizeof(ebpfProgramSizes), progCount);
            if(*progs)
            {
                progCount=0;
                bpf_object__for_each_program(bpfProg, bpfObj)
                {
                    strcpy((*progs)[progCount].name, bpf_program__name(bpfProg));
                    (*progs)[progCount].size = bpf_program__insn_cnt(bpfProg);
                    progCount++;
                }
            }
        }
    }

    return progCount;
}

//--------------------------------------------------------------------
//
// telemetryStart
//
// The external-facing API for starting the eBPF telemetry.
//
//--------------------------------------------------------------------
int telemetryStart(
    const ebpfTelemetryConfig *ebpfConfig,
    EventCallback *eventCb,
    EventLostCallback *eventsLostCb,
    TelemetryReadyCallback *telemetryReady,
    TelemetryReloadConfig *telemetryReloadConfig,
    void *context,
    const char *argv[],
    int *fds
    )
{
    if (ebpfConfig == NULL || eventCb == NULL || eventsLostCb == NULL ||
            telemetryReady == NULL || telemetryReloadConfig == NULL ||
            argv == NULL || fds == NULL) {
        fprintf(stderr, "telemetryStart invalid params\n");
        return E_EBPF_INVALIDPARAMS;
    }

    unsigned int                i = 0;
    char                        filepath[PATH_MAX];
    unsigned int                isTesting = STOPLOOP;
    int                         ret;
    struct rlimit               lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    time_t                      procStartTime;
    uint64_t                    timeouts = 0;

    g_bootSecSinceEpoch = ebpfConfig->bootSecSinceEpoch;

    procStartTime = time(NULL);

    // get the appropriate kernel object
    object = getObjectAndPath(filepath, sizeof(filepath), ebpfConfig);
    if (object == NULL)
        return E_EBPF_NOFILEPATH;

    rawTracepoints = object->rawSyscallTracepoints;

    fprintf(stderr, "Using EBPF object: %s\n", filepath);

    setrlimit(RLIMIT_MEMLOCK, &lim);

    numSysEnter = object->numSyscallTPenterProgs;
    numSysExit = object->numSyscallTPexitProgs;
    numRawSysEnter = object->numSyscallRTPenterProgs;
    numRawSysExit = object->numSyscallRTPexitProgs;
    numOtherTp = object->numOtherTPprogs;

    ret = ebpfStart(ebpfConfig, filepath, procStartTime, eventCb, eventsLostCb, context, argv, fds, false);
    if (ret != E_EBPF_SUCCESS)
        return ret;

    //
    // Use SIGHUP to indicate the configuration should be reloaded
    //
    signal(SIGHUP, telemetrySignalInterrupt);

    fprintf(stderr, "Running...\n");

    telemetryReady();

    timeouts = 0;

    while (running) {
        ret = perf_buffer__poll(pb, 1000);
        if (ret == 0) {
            // no events means we timed out
            timeouts++;
            if (timeouts > RESTART_TIMEOUT) {
                fprintf(stderr, "Event timeout occurred (no event for %d seconds). Reloading eBPF...\n", RESTART_TIMEOUT);
                timeouts = 0;
                telemetryCloseAll();
                if (ebpfStart(ebpfConfig, filepath, procStartTime, eventCb, eventsLostCb, context, argv, fds, true)
                        != E_EBPF_SUCCESS) {
                    fprintf(stderr, "ebpfStart failed\n");
                    break;
                }
                fprintf(stderr, "Reloaded eBPF due to event timeout\n");
                continue;
            }
        } else if (ret > 0) {
            // events were received and processed
            timeouts = 0;
        }
#ifdef NDEBUG
        //
        // if we receive a SIGSTOP & SIGCONT, then perf_buffer__poll will return -1.
        // This is to be expected if the process is being debugged, but not otherwise.
        //
        if (ret < 0 && !signalInterrupt)
            running = false;
#endif
        if (signalInterrupt) {
            signalInterrupt = false;
            telemetryReloadConfig();
        }
        if (isTesting) {
            if (i++ > STOPLOOP) break;
        }
        checkPerfErrors();
    }

    telemetryCloseAll();

    return E_EBPF_SUCCESS;
}

