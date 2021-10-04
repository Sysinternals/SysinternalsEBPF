#    SysinternalsEBPF
#
#    Copyright (c) Microsoft Corporation
#
#    All rights reserved.
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

obj-m += getOffsets.o
KERN_MAJ=$(shell uname -r | cut -d. -f1)
KERN_MIN=$(shell uname -r | cut -d. -f2)
all:
	make CFLAGS_MODULE="-DKERN_MAJ=$(KERN_MAJ) -DKERN_MIN=$(KERN_MIN)" -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	cc -Wall -o extractOffsets extractOffsets.c -lelf
	@echo ""
	@echo Use \"make conf\" to extract the offsets
	@echo Save them to /opt/sysinternalsEBPF/sysinternalsEBPF_offsets.conf

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm extractOffsets
conf:
	@./extractOffsets getOffsets.ko
