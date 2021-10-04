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
// memDumpShared.h
//
// Header shared between eBPF and userland for offsets discovery
// process.
//
//====================================================================

#ifndef MEMDUMP_SHARED_H
#define MEMDUMP_SHARED_H

enum memDumpType {
    task,
    ptask,
    mm,
    cred,
    fs,
    dentry,
    dentryParent,
    dentryMountpoint,
    pwd,
    inode,
    mount,
    mountParent,
    files,
    signals,
    exeFile,
    exeDentry,
    exeName,
    skb,
    skdata,
    MAX_MEM_DUMP_TYPE
};

typedef struct {
    unsigned int       userlandPid;
    enum memDumpType   type;
    const void         *addr;
    unsigned int       size;
} memDumpConfig;

typedef struct {
    enum memDumpType   type;
    const void         *addr;
    unsigned int       size;
    char               data[MAX_MEM_DUMP];
} memDump;

#endif
