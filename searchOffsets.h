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
// searchOffsets.h
//
// Functions exported by searchOffsets.c
//
//====================================================================

#ifndef SEARCH_OFFSETS_H
#define SEARCH_OFFSETS_H

#include <stdbool.h>
#include <glib-object.h>
#include <json-glib/json-glib.h>
#include "unameOffsets.h"
#include "sysinternalsEBPF.h"


unsigned int *findConfigItem(Offsets *o, const char *param);
bool copyOffsets(Offsets *offsets, JsonReader *reader);
bool copyOffsetsList(char *name, unsigned int *o, JsonReader *reader);
bool searchOffsets(Offsets *offsets);

#endif

