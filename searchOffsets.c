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
// searchOffsets.c
//
// Search through the offsets database supplied by Project Freta to
// find offsets suitable for the running kernel.
//
//====================================================================

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <glib-object.h>
#include <json-glib/json-glib.h>
#include <sys/utsname.h>
#include "unameOffsets.h"
#include "searchOffsets.h"
#include "sysinternalsEBPF.h"

#define LINUX_VERSION "Linux version "

//--------------------------------------------------------------------
//
// strip
//
// Strip blank space from the start and end of a string.
//
// Note, this modifies the supplied pointer.
//
//--------------------------------------------------------------------
void strip(char **s)
{
    if (s == NULL || *s == NULL)
        return;

    while (**s == ' ' || **s == '\t') {
        *s = *s + 1;
    }

    char *p = *s + strlen(*s) - 1;
    while (*p == ' ' || *p == '\r' || *p == '\n' || *p == '\t') {
        *p = 0x00;
        p--;
    }
}

//--------------------------------------------------------------------
//
// isSuitable
//
// Checks whether the supplied version string is supported by
// SysinternalsEBPF.
//
//--------------------------------------------------------------------
bool isSuitable(char *uname)
{
    unsigned int major, minor;

    if (uname == NULL)
        return false;

    if (sscanf(uname, LINUX_VERSION "%u.%u", &major, &minor) != 2)
        return false;

    if (major < 4 || (major == 4 && minor < 15))
        return false;

    return true;
}

//--------------------------------------------------------------------
//
// extractVersion
//
// Extracts the useful version string from the supplied full version
// string.  If the version isn't suitable, it returns NULL.
//
//--------------------------------------------------------------------
char *extractVersion(char *uname)
{
    unsigned int i = 0;
    char *relVer = NULL;
    char *ptr = NULL;

    if (!isSuitable(uname))
        return NULL;

    i = strlen(uname) - 1;
    while (isspace(uname[i])) {
        uname[i] = 0x00;
        i--;
    }

    if (uname[i] == ')') {
        ptr = strrchr(uname, '(');
        *ptr = 0x00;
    }

    relVer = uname;
    strip(&relVer);
    return relVer;
}

//--------------------------------------------------------------------
//
// copyOffsetsList
//
// Read the offsets for the next struct member.
//
//--------------------------------------------------------------------
bool copyOffsetsList(char *name, unsigned int *o, JsonReader *reader)
{
    unsigned int i;
    unsigned int count = 0;

    if (name == NULL || o == NULL || reader == NULL)
        return false;

    if (!json_reader_read_member(reader, name)) {
        json_reader_end_member(reader);
        return false;
    }

    count = json_reader_count_elements(reader);

    for (i=0; i<count && i<NUM_REDIRECTS; i++, o++) {
        json_reader_read_element(reader, i);
        *o = json_reader_get_int_value(reader);
        json_reader_end_element(reader);
    }
    json_reader_end_member(reader);
    return true;
}

//--------------------------------------------------------------------
//
// unameCmp
//
// Compare two uname strings for qsort().
//
//--------------------------------------------------------------------
int unameCmp(const void *a, const void *b)
{
    if (a == NULL || b == NULL)
        return 1;

    unameOffsets *ua = (unameOffsets *)a;
    unameOffsets *ub = (unameOffsets *)b;

    return strcmp(ua->uname, ub->uname);
}

//--------------------------------------------------------------------
//
// getKernelProcVersion
//
// Get the running kernel's version string.
//
//--------------------------------------------------------------------
bool getKernelProcVersion(char *ver, size_t len)
{
    FILE *fp;
    unsigned int i;

    if (ver == NULL)
        return false;

    fp = fopen("/proc/version", "r");
    if (fp == NULL)
        return false;
    if (fread(ver, 1, len, fp) == 0) {
        fclose(fp);
        return false;
    }
    fclose(fp);

    i = strlen(ver) - 1;
    while (isspace(ver[i])) {
        ver[i] = 0x00;
        i--;
    }

    return true;
}

//--------------------------------------------------------------------
//
// searchOffsets
//
// Search the offsets database for an entry that matches the running
// kernel, and copy the given offsets to the supplied struct.
//
//--------------------------------------------------------------------
bool searchOffsets(Offsets *offsets)
{
    JsonParser *parser = NULL;
    GError *error = NULL;
    JsonReader *reader = NULL;
    char **unames = NULL;
    unsigned int i = 0;
    unsigned int unameCount = 0;
    char *unameStr = NULL;
    unameOffsets *suitableOffsets = NULL;
    unameOffsets *myoffsets;
    unameOffsets key;
    char keyName[1024];
    bool ret = false;

    if (offsets == NULL)
        return false;

    parser = json_parser_new();
    json_parser_load_from_file(parser, OFFSETS_DB_FILE, &error);
    if (error) {
        g_error_free(error);
        g_object_unref(parser);
        return false;
    }

    reader = json_reader_new(json_parser_get_root(parser));
    unames = json_reader_list_members(reader);

    i = 0;
    while (unames[i] != NULL) {
        if (isSuitable(unames[i])) {
            unameCount++;
        }
        i++;
    }

    if (unameCount > 0)
    {
        suitableOffsets = (unameOffsets *)malloc(sizeof(unameOffsets) * unameCount);
        if (suitableOffsets == NULL) {
            g_object_unref(parser);
            return false;
        }

        i = 0;
        unameCount = 0;
        while (unames[i] != NULL) {
            json_reader_read_member(reader, unames[i]);
            unameStr = extractVersion(unames[i]);
            if (unameStr != NULL) {
                suitableOffsets[unameCount].uname = unameStr;
                if (copyOffsets(&suitableOffsets[unameCount].offsets, reader)) {
                    unameCount++;
                }
            }
            json_reader_end_member(reader);
            i++;
        }

        qsort(suitableOffsets, unameCount, sizeof(unameOffsets), unameCmp);

        if (getKernelProcVersion(keyName, sizeof(keyName))) {
            key.uname = keyName;
            myoffsets = bsearch(&key, suitableOffsets, unameCount, sizeof(unameOffsets), unameCmp);
            if (myoffsets != NULL) {
                memcpy(offsets, &myoffsets->offsets, sizeof(myoffsets->offsets));
                ret = true;
            }
        }
    }

    free(suitableOffsets);
    g_strfreev(unames);
    g_object_unref(reader);
    g_object_unref(parser);

    return ret;
}
