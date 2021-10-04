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
// hexdump.c
//
// Outputs binary data as hex for debugging.
//
//====================================================================

#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>

//--------------------------------------------------------------------
//
// hexdump
//
// Dump n bytes of the provided buffer as hex unsigned chars to stdout
//
//--------------------------------------------------------------------
void hexdump(const unsigned char *x, size_t n)
{
    if (x == NULL) {
        fprintf(stderr, "hexdump invalid params\n");
        return;
    }

    printf("\n");
    for (size_t i=0; i<n; i++) {
        if (i % 16 == 0) {
            printf("%08lx  ", i);
        }
        printf("0x%02x ", x[i]);
        if (i % 16 == 7) {
            printf(" ");
        }
        if (i % 16 == 15) {
            for (size_t j=i-15; j<=i; j++) {
                if (isprint(x[j])) {
                    printf("%c", x[j]);
                } else {
                    printf(".");
                }
                if (j % 16 == 7) {
                    printf(" ");
                }
            }
            printf("\n");
        }
    }
    printf("\n");
}


