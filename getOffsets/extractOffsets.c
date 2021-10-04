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
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

//====================================================================
//
// extractOffsets.c
//
// Extracts the offsets from the const globals in getOffsets.ko
//
//====================================================================

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/mman.h>
#include <errno.h>
#include <ctype.h>


int main(int argc, char *argv[])
{
    int fd = 0;
    Elf *elf = NULL;
    Elf_Scn *scn = NULL;
    Elf_Data *edata = NULL;
    GElf_Ehdr ehdr;
    GElf_Sym sym;
    GElf_Shdr shdr;
    int symbol_count = 0;
    unsigned int i, j;
    unsigned int rodata_scn = 1;
    unsigned long rodata_off = 0;
    struct stat st;
    unsigned char *file_data = NULL;
    unsigned char *rodata = NULL;
    char *sym_name = NULL;

    if (argc < 2) {
        printf("Usage: %s kernelModule\n", argv[0]);
        return 1;
    }

    if ((fd = open(argv[1], O_RDONLY)) <= 0) {
        printf("%s: cannot open file %s: %s\n", argv[0], argv[1], strerror(errno));
        return 1;
    }

    if (fstat(fd, &st) < 0) {
        printf("%s: cannot access file %s: %s\n", argv[0], argv[1], strerror(errno));
        return 1;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        printf("%s: WARNING Elf Library is out of date!\n", argv[0]);
    }

    //
    // init elf pointer
    //
    elf = elf_begin(fd, ELF_C_READ, NULL);
    gelf_getehdr(elf, &ehdr);

    //
    // find .rodata section number and file offset
    //
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);

        if (strcmp(elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name), ".rodata") == 0) {
            rodata_off = shdr.sh_offset;
            break;
        }

        rodata_scn++;
    }

    if (scn == NULL) {
        printf("%s: cannot find .rodata section\n", argv[0]);
        return 2;
    }

    //
    // map the whole file
    //
    file_data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (file_data == NULL || file_data == MAP_FAILED) {
        printf("%s: cannot mmap file %s: %s\n", argv[0], argv[1], strerror(errno));
        return 1;
    }

    //
    // get pointer to rodata section
    //
    rodata = file_data + rodata_off;
        
    //
    // reset section pointer to start of file
    //
    scn = NULL;

    //
    // find symbols
    //
    while((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);

        if (shdr.sh_type == SHT_SYMTAB && shdr.sh_entsize > 0) {
            edata = NULL;

            edata = elf_getdata(scn, edata);

            symbol_count = shdr.sh_size / shdr.sh_entsize;

            for(i = 0; i < symbol_count; i++) {                       
                gelf_getsym(edata, i, &sym);

                //
                // only want .rodata symbols
                //
                if (sym.st_shndx != rodata_scn)
                    continue;

                //
                // only want global objects
                //
                if (sym.st_info != ((STB_GLOBAL << 4) | STT_OBJECT))
                    continue;

                //
                // print symbol names in lowercase
                //
                sym_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                for (sym_name = elf_strptr(elf, shdr.sh_link, sym.st_name); *sym_name != 0x00; sym_name++) {
                    putchar(tolower(*sym_name));
                }
                printf(" = ");

                //
                // print offsets
                //
                for (j=0; j< sym.st_size / sizeof(unsigned long); j++) {
                    if (j != 0)
                        printf(", ");
                    printf("%ld", *(unsigned long *)(rodata + sym.st_value + (sizeof(unsigned long) * j)));
                }
                printf("\n");
            }
        }
    }

    munmap(file_data, st.st_size);

    return 0;
}



