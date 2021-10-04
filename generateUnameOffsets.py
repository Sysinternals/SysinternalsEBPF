#!/usr/bin/python3

#    SysinternalsEBPF
#
#    Copyright (c) Microsoft Corporation
#
#    All rights reserved.
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

import sys
import json
import re

if len(sys.argv) < 2 or len(sys.argv) > 3:
    print(f'Usage: {sys.argv[0]} <reqd offsets json file> [[PUBLIC_]HEADER]')
    sys.exit(1)

header = False
public_header = False

if len(sys.argv) == 3 and sys.argv[2] == 'HEADER':
    header = True
elif len(sys.argv) == 3 and sys.argv[2] == 'PUBLIC_HEADER':
    public_header = True
else:
    data = []

with open(sys.argv[1]) as offsetsReqd:
    reqd = json.load(offsetsReqd)
    params = reqd["params"]
    params_opt = reqd["params_opt"]
    num_redirects = reqd["num_redirects"]
    deref_end = reqd["deref_end"]

    print('/*')
    print('SysinternalsEBPF')
    print('')
    print('Copyright (c) Microsoft Corporation')
    print('')
    print('All rights reserved.')
    print('')
    print('This library is free software; you can redistribute it and/or')
    print('modify it under the terms of the GNU Lesser General Public')
    print('License as published by the Free Software Foundation; either')
    print('version 2.1 of the License, or (at your option) any later version.')
    print('')
    print('This library is distributed in the hope that it will be useful,')
    print('but WITHOUT ANY WARRANTY; without even the implied warranty of')
    print('MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU')
    print('Lesser General Public License for more details.')
    print('')
    print('You should have received a copy of the GNU Lesser General Public')
    print('License along with this library; if not, write to the Free Software')
    print('Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA')
    print('*/\n')

    if public_header:
        print('#ifndef SYSINTERNALS_EBPF_OFFSETS_H')
        print('#define SYSINTERNALS_EBPF_OFFSETS_H\n')
        print('#include <stdbool.h>\n')
        print(f'#define NUM_REDIRECTS {num_redirects}')
        print(f'#define DEREF_END {deref_end}\n')
        print('// offsets')
        print('typedef struct {')
        for param in params:
            print(f'    unsigned int       {param}[NUM_REDIRECTS];')
        for param in params_opt:
            print(f'    unsigned int       {param}[NUM_REDIRECTS];')
        print('} Offsets;\n')
        print('#endif\n')
        sys.exit(0)

    if header:
        print('#ifndef UNAMEOFFSETS_H')
        print('#define UNAMEOFFSETS_H\n')
        print('#include <sysinternalsEBPFoffsets.h>\n')
        print('typedef struct {')
        print('    char *uname;')
        print('    Offsets offsets;')
        print('} unameOffsets;\n')
        print('unsigned int *findConfigItem(Offsets *o, const char *param);')
        print('#endif\n')
        sys.exit(0)

    count = 0
    print('#include <string.h>')
    print('#include <stdbool.h>')
    print('#include <glib-object.h>')
    print('#include <json-glib/json-glib.h>')
    print('#include "unameOffsets.h"')
    print('#include "searchOffsets.h"\n')
    print('unsigned int *findConfigItem(Offsets *o, const char *param)')
    print('{')
    first = True
    for param in params:
        output = '    '
        if not first:
            output += 'else '
        output += f'if (strcmp(param, "{param}"))\n'
        output += f'        return o->{param};'
        print(output)
        first = False
    for param in params_opt:
        print(f'    else if (strcmp(param, "{param}"))')
        print(f'        return o->{param};')
    print('    return NULL;')
    print('}\n')
    print('bool copyOffsets(Offsets *offsets, JsonReader *reader)')
    print('{')
    print('    memset(offsets, -1, sizeof(Offsets));')
    for param in params:
        print(f'    if (!copyOffsetsList("{param}", offsets->{param}, reader))')
        print('        return false;')
    for param in params_opt:
        print(f'    if (!copyOffsetsList("{param}", offsets->{param}, reader))')
        print(f'        memset(offsets->{param}, -1, sizeof(offsets->{param}));')
    print('    return true;')
    print('}\n')

