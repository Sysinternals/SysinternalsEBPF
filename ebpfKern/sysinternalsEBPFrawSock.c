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
// sysinternalsEBPFrawSock.c
//
// Empty eBPF program that can be attached to a raw socket in order
// to cause outbound packets to hit the skb/consume_skb tracepoint.
//
//====================================================================

#include "sysinternalsEBPF_common.h"

//--------------------------------------------------------------------
//
// rawEBPFprog
//
// Raw socket filter that does nothing.
// But in doing nothing, it forces outbound packets via the
// skb/consume_skb tracepoint, which is in process context, and has
// access to full packet data.
//
//--------------------------------------------------------------------
SEC("rawSock")
__attribute__((flatten))
int rawEBPFprog(unsigned char *skbaddr)
{
   return 0;
}

char _license[] SEC("license") = "GPL";
