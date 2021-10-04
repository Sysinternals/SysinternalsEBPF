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
    51 Franklin Street, Fifth Floor, Boston, MA 021101301 USA.
*/

//====================================================================
//
// libsysinternalsEBPFinstaller.c
//
// Standalone installer executable that writes packed files to the
// correct locations. This installer can be copied to another host and
// when it is run it will install SysinternalsEBPF to that host
// without needing additional files.
//
//====================================================================

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "libsysinternalsEBPF.h"

#define SYSINTERNALSEBPF_DIR        "/opt/sysinternalsEBPF"
#define GETOFFSETS_DIR              SYSINTERNALSEBPF_DIR "/getOffsets"
#define EBPFKERN_DIR                SYSINTERNALSEBPF_DIR "/ebpfKern"
#define LIBBPF_DIR                  SYSINTERNALSEBPF_DIR "/libbpf"
#define SYSINTERNALSEBPF_BINARY     "libsysinternalsEBPFinstaller"
#define LIB_DEST                    "/usr/lib"
#define HEADER_DEST                 "/usr/include"
#define SYSINTERNALSEBPF_LIB        "libsysinternalsEBPF.so"
#define SYSINTERNALSEBPF_HEADER     "libsysinternalsEBPF.h"
#define OFFSETS_DB_FILE             "offsets.json"
#define MEM_DUMP_OBJ                "sysinternalsEBPFmemDump.o"
#define RAW_SOCK_OBJ                "sysinternalsEBPFrawSock.o"

extern char _binary_libsysinternalsEBPF_so_start[];
extern char _binary_libsysinternalsEBPF_so_end[];
extern char _binary_libsysinternalsEBPF_h_start[];
extern char _binary_libsysinternalsEBPF_h_end[];
extern char _binary_sysinternalsEBPFmemDump_o_start[];
extern char _binary_sysinternalsEBPFmemDump_o_end[];
extern char _binary_sysinternalsEBPFrawSock_o_start[];
extern char _binary_sysinternalsEBPFrawSock_o_end[];
extern char _binary_sysinternalsEBPFshared_h_start[];
extern char _binary_sysinternalsEBPFshared_h_end[];
extern char _binary_sysinternalsEBPFoffsets_h_start[];
extern char _binary_sysinternalsEBPFoffsets_h_end[];
extern char _binary_offsets_offsets_json_start[];
extern char _binary_offsets_offsets_json_end[];
extern char _binary_getOffsets_LICENSE_start[];
extern char _binary_getOffsets_LICENSE_end[];
extern char _binary_getOffsets_Makefile_start[];
extern char _binary_getOffsets_Makefile_end[];
extern char _binary_getOffsets_README_md_start[];
extern char _binary_getOffsets_README_md_end[];
extern char _binary_getOffsets_extractOffsets_c_start[];
extern char _binary_getOffsets_extractOffsets_c_end[];
extern char _binary_getOffsets_getOffsets_c_start[];
extern char _binary_getOffsets_getOffsets_c_end[];
extern char _binary_getOffsets_mount_h_start[];
extern char _binary_getOffsets_mount_h_end[];
extern char _binary_ebpfKern_LICENSE_start[];
extern char _binary_ebpfKern_LICENSE_end[];
extern char _binary_ebpfKern_sysinternalsEBPF_common_h_start[];
extern char _binary_ebpfKern_sysinternalsEBPF_common_h_end[];
extern char _binary_ebpfKern_sysinternalsEBPF_helpers_c_start[];
extern char _binary_ebpfKern_sysinternalsEBPF_helpers_c_end[];
extern char _binary_LICENSE_LPGL_2_1_start[];
extern char _binary_LICENSE_LPGL_2_1_end[];
extern char _binary_src_bpf_helpers_h_start[];
extern char _binary_src_bpf_helpers_h_end[];
extern char _binary_src_bpf_helper_defs_h_start[];
extern char _binary_src_bpf_helper_defs_h_end[];

mode_t dirMode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
mode_t fileMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
mode_t exeFileMode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

//--------------------------------------------------------------------
//
// main
//
// The whole installer. Uses functions in installer.c.
//
//--------------------------------------------------------------------
int main(int argc, char *argv[])
{
    int fd;
    void *addr = NULL;
    struct stat st;
    char exePath[] = "/proc/self/exe";
    bool force = true;

    if (argc != 1) {
        printf("Usage: %s\n", argv[0]);
        printf("Installs the libsysinternalsEBPF shared library, header and EBPF objects\n");
        printf("as an alternative to 'sudo make install'. This installer contains all the\n");
        printf("files necessary so is a portable way of installing on a system other than\n");
        printf("the one it was built on.\n");
        printf("Requires root privileges.\n\n");
        return 1;
    }

    umask(0022);

    if (!createDir(SYSINTERNALSEBPF_DIR, dirMode)) {
        fprintf(stderr, "Cannot create sysinternalsEBPF directory\n");
        fprintf(stderr, "Make sure you are root or sudo\n");
        return 1;
    }

    if (!createDir(GETOFFSETS_DIR, dirMode)) {
        fprintf(stderr, "Cannot create sysinternalsEBPF getOffsets directory\n");
        fprintf(stderr, "Make sure you are root or sudo\n");
        return 1;
    }

    if (!createDir(EBPFKERN_DIR, dirMode)) {
        fprintf(stderr, "Cannot create sysinternalsEBPF ebpfKern directory\n");
        fprintf(stderr, "Make sure you are root or sudo\n");
        return 1;
    }

    if (!createDir(LIBBPF_DIR, dirMode)) {
        fprintf(stderr, "Cannot create sysinternalsEBPF libbpf directory\n");
        fprintf(stderr, "Make sure you are root or sudo\n");
        return 1;
    }

    fd = open(exePath, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Cannot open own executable\n");
        return 1;
    }

    if (fstat(fd, &st) < 0) {
        fprintf(stderr, "Cannot stat own executable\n");
        close(fd);
        return 1;
    }

    addr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        fprintf(stderr, "Cannot map own executable\n");
        close(fd);
        return 1;
    }

    if (!dropFile(SYSINTERNALSEBPF_DIR "/" SYSINTERNALSEBPF_BINARY,
        addr,
        addr + st.st_size,
        force,
        exeFileMode)) {
        munmap(addr, st.st_size);
        close(fd);
        return 1;
    }

    munmap(addr, st.st_size);
    close(fd);

    if (!dropFile(LIB_DEST "/" SYSINTERNALSEBPF_LIB,
        _binary_libsysinternalsEBPF_so_start,
        _binary_libsysinternalsEBPF_so_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(HEADER_DEST "/" SYSINTERNALSEBPF_HEADER,
        _binary_libsysinternalsEBPF_h_start,
        _binary_libsysinternalsEBPF_h_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(SYSINTERNALSEBPF_DIR "/" MEM_DUMP_OBJ,
        _binary_sysinternalsEBPFmemDump_o_start,
        _binary_sysinternalsEBPFmemDump_o_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(SYSINTERNALSEBPF_DIR "/" RAW_SOCK_OBJ,
        _binary_sysinternalsEBPFrawSock_o_start,
        _binary_sysinternalsEBPFrawSock_o_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(SYSINTERNALSEBPF_DIR "/" OFFSETS_DB_FILE,
        _binary_offsets_offsets_json_start,
        _binary_offsets_offsets_json_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(GETOFFSETS_DIR "/LICENSE",
        _binary_getOffsets_LICENSE_start,
        _binary_getOffsets_LICENSE_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(GETOFFSETS_DIR "/Makefile",
        _binary_getOffsets_Makefile_start,
        _binary_getOffsets_Makefile_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(GETOFFSETS_DIR "/README.md",
        _binary_getOffsets_README_md_start,
        _binary_getOffsets_README_md_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(GETOFFSETS_DIR "/extractOffsets.c",
        _binary_getOffsets_extractOffsets_c_start,
        _binary_getOffsets_extractOffsets_c_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(GETOFFSETS_DIR "/getOffsets.c",
        _binary_getOffsets_getOffsets_c_start,
        _binary_getOffsets_getOffsets_c_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(GETOFFSETS_DIR "/mount.h",
        _binary_getOffsets_mount_h_start,
        _binary_getOffsets_mount_h_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(EBPFKERN_DIR "/LICENSE",
        _binary_ebpfKern_LICENSE_start,
        _binary_ebpfKern_LICENSE_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(EBPFKERN_DIR "/sysinternalsEBPF_common.h",
        _binary_ebpfKern_sysinternalsEBPF_common_h_start,
        _binary_ebpfKern_sysinternalsEBPF_common_h_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(EBPFKERN_DIR "/sysinternalsEBPF_helpers.c",
        _binary_ebpfKern_sysinternalsEBPF_helpers_c_start,
        _binary_ebpfKern_sysinternalsEBPF_helpers_c_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(EBPFKERN_DIR "/sysinternalsEBPFshared.h",
        _binary_sysinternalsEBPFshared_h_start,
        _binary_sysinternalsEBPFshared_h_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(EBPFKERN_DIR "/sysinternalsEBPFoffsets.h",
        _binary_sysinternalsEBPFoffsets_h_start,
        _binary_sysinternalsEBPFoffsets_h_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(LIBBPF_DIR "/LICENSE.LPGL-2.1",
        _binary_LICENSE_LPGL_2_1_start,
        _binary_LICENSE_LPGL_2_1_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(LIBBPF_DIR "/bpf_helpers.h",
        _binary_src_bpf_helpers_h_start,
        _binary_src_bpf_helpers_h_end,
        force,
        fileMode))
        return 1;

    if (!dropFile(LIBBPF_DIR "/bpf_helper_defs.h",
        _binary_src_bpf_helper_defs_h_start,
        _binary_src_bpf_helper_defs_h_end,
        force,
        fileMode))
        return 1;

    printf("Success!\n");
    printf("Library\t%s\tinstalled to\t%s\n", SYSINTERNALSEBPF_LIB, LIB_DEST);
    printf("Header\t%s\tinstalled to\t%s\n", SYSINTERNALSEBPF_HEADER, HEADER_DEST);
    printf("Support files installed to %s\n", SYSINTERNALSEBPF_DIR);

    return 0;
}


