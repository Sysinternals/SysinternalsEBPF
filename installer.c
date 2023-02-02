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
// installer.c
//
// Functions used to install files.
//
//====================================================================

#include "/usr/include/fcntl.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>


//--------------------------------------------------------------------
//
// fileDelete
//
// Deletes specified file
//
//--------------------------------------------------------------------
bool fileDelete(const char *filepath)
{
    if (filepath == NULL) {
        fprintf(stderr, "fileDelete invalid params\n");
        return false;
    }

    return unlink(filepath) < 0 ? false : true;
}


//--------------------------------------------------------------------
//
// fileExists
//
// Report if specified file exists.
//
//--------------------------------------------------------------------
bool fileExists(const char *filepath)
{
    if (filepath == NULL) {
        fprintf(stderr, "fileExists invalid params\n");
        return false;
    }

    struct stat st;

    if (stat(filepath, &st) < 0)
        return false;
    if (S_ISREG(st.st_mode))
        return true;
    return false;
}

//--------------------------------------------------------------------
//
// dirExists
//
// Report if specified directory exists.
//
//--------------------------------------------------------------------
bool dirExists(const char *dirpath)
{
    if (dirpath == NULL) {
        fprintf(stderr, "dirExists invalid params\n");
        return false;
    }

    struct stat st;

    if (stat(dirpath, &st) < 0)
        return false;
    if (S_ISDIR(st.st_mode))
        return true;
    return false;
}

//--------------------------------------------------------------------
//
// createDir
//
// Create specified directory with specified permissions.
//
//--------------------------------------------------------------------
bool createDir(const char *dir, mode_t perms)
{
    if (dir == NULL) {
        fprintf(stderr, "createDir invalid params\n");
        return false;
    }

    struct stat st;

    if (stat(dir, &st) < 0) {
        if (mkdir(dir, perms) < 0) {
            return false;
        }
    } else {
        if (!S_ISDIR(st.st_mode)) {
            return false;
        }
        chmod(dir, perms);
    }
    return true;
}

//--------------------------------------------------------------------
//
// dropFile
//
// Create specified file with specified permissions, and write the
// data between start and end to it.
//
//--------------------------------------------------------------------
bool dropFile(const char *filepath, const char *start,
        const char *end, bool force, mode_t perms)
{
    if (filepath == NULL || start == NULL || end == NULL) {
        fprintf(stderr, "dropFile invalid params\n");
        return false;
    }

    int fd;
    size_t written = 0;
    ssize_t writeRet;
    size_t size = end - start;

    if (fileExists(filepath) && !force) {
        chmod(filepath, perms);
        return true;
    }

    unlink(filepath);

    fd = open(filepath, O_WRONLY|O_CREAT|O_TRUNC, perms);
    //fd = creat(filepath, perms);
    if (fd < 0) {
        fprintf(stderr, "Cannot write %s\n", filepath);
        return false;
    }

    while (written < size) {
        writeRet = write(fd, start + written, size - written);
        if (writeRet < 0) {
            close(fd);
            return 1;
        }
        written += writeRet;
    }
    close(fd);

    return true;
}


