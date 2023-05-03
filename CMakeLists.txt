#
#
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
#


#################################################################################
# NOTE:                                                                         #
# Please compile in a build directory rather than the source directory.         #
#                                                                               #
#    $ mkdir build; cd build                                                    #
#    $ cmake ..                                                                 #
#    $ make                                                                     #
#                                                                               #
# If you later change this CMakeLists.txt file, remake the build directory.     #
#                                                                               #
#    $ cd ..                                                                    #
#    $ rm -rf build                                                             #
#    $ mkdir build; cd build                                                    #
#    $ cmake ..                                                                 #
#    $ make                                                                     #
#                                                                               #
#################################################################################

cmake_minimum_required(VERSION 3.10)
cmake_policy(SET CMP0048 NEW)

# set the project name - version is MAJOR.MINOR.PATCH.RELEASE - releases start at 1
if (DEFINED ENV{VERSION})
  project(SysinternalsEBPF VERSION $ENV{VERSION})
else()
  project(SysinternalsEBPF VERSION 0.0.0.0)
endif()

configure_file(package/DEBIAN.in/control.in DEBIANcontrol)
configure_file(package/SPECS.in/spec.in SPECS.spec)

#
# enable Debug while pre-release; re-enable it post-release to add symbols to binary
#
#set(CMAKE_BUILD_TYPE Debug)
#option(DEBUG_K "Enter debug mode" On)

#
# external programs used by this build
#
set(LD "/usr/bin/ld")

#
# package name
#
set(PACKAGE_NAME "sysinternalsebpf")

#
# Compress man page
#
set(SYSEBPF_COMPRESS_MAN "sysinternalsebpf.3.gz")

add_custom_target(SYSEBPF_MAN_COMPRESS ALL
                  DEPENDS ${PROJECT_BINARY_DIR}/${SYSEBPF_COMPRESS_MAN}
                  )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/${SYSEBPF_COMPRESS_MAN}
                   COMMAND gzip -f -c "${CMAKE_SOURCE_DIR}/package/usr/share/man/man3/sysinternalsebpf.3" > ${PROJECT_BINARY_DIR}/${SYSEBPF_COMPRESS_MAN}
                   COMMENT "Compressing SysinternalsEBPF man page"
                   DEPENDS "${CMAKE_SOURCE_DIR}/package/usr/share/man/man3/sysinternalsebpf.3"
                  )

#
# report warnings as errors
# -g is required for BTF and CO:RE
#
add_compile_options(-Wall -Werror -g -D_FORTIFY_SOURCE=2 -fstack-protector-all -O2)

include(ExternalProject)

# Fetch libbpf
# FIX this so that it clones libbpf when the project is cloned
ExternalProject_Add(libbpf
    GIT_REPOSITORY https://github.com/libbpf/libbpf.git
#    GIT_TAG master
    GIT_TAG v1.1.0
    PREFIX ./libbpf
    CONFIGURE_COMMAND ""
    BUILD_COMMAND cd ../libbpf/src && bash -c "CFLAGS=\"-g -O2 -Werror -Wall -fPIC\" make"
    INSTALL_COMMAND ""
    )

set(libbpf_SOURCE_DIR ${CMAKE_BINARY_DIR}/libbpf/src/libbpf)

find_package(PkgConfig REQUIRED)
pkg_search_module(JSONGLIB REQUIRED json-glib-1.0)

# make sysinternalsEBPF
add_library(sysinternalsEBPF SHARED
            telemetryLoader.c
            discoverOffsets.c
            libsysinternalsEBPF.h
            discoverOffsets.h
            searchOffsets.c
            sysinternalsEBPF.h
            sysinternalsEBPFshared.h
            sysinternalsEBPFoffsets.h
            unameOffsets.h
            unameOffsets.c
            installer.c
            syscalls.h
            hexdump.c
            hexdump.h
            )

add_definitions("-fPIC")
add_dependencies(sysinternalsEBPF libbpf)
target_link_libraries(sysinternalsEBPF ${libbpf_SOURCE_DIR}/src/libbpf.a ${JSONGLIB_LIBRARIES} elf z)

if (STOPLOOP)
    message("setting STOPLOOP Count=${STOPLOOP}")
    target_compile_definitions(sysinternalsEBPF PUBLIC STOPLOOP=${STOPLOOP})
endif()

target_include_directories(sysinternalsEBPF PUBLIC
                           "${CMAKE_SOURCE_DIR}"
                           "${PROJECT_BINARY_DIR}"
                           "${libbpf_SOURCE_DIR}/src"
                           "${libbpf_SOURCE_DIR}/include"
                           "${libbpf_SOURCE_DIR}/include/asm"
                           "${libbpf_SOURCE_DIR}/include/linux"
                           "${libbpf_SOURCE_DIR}/include/tools"
                           "${libbpf_SOURCE_DIR}/include/uapi"
                           "${libbpf_SOURCE_DIR}/include/uapi/linux"
                           "${JSONGLIB_INCLUDE_DIRS}"
                           "/usr/include"
                           )

add_executable(libsysinternalsEBPFinstaller
    libsysinternalsEBPFinstaller.c
    installer.c
    libsysinternalsEBPF.so.o
    libsysinternalsEBPF.h.o
    sysinternalsEBPFshared.h.o
    sysinternalsEBPFoffsets.h.o
    sysinternalsEBPFmemDump.o.o
    sysinternalsEBPFrawSock.o.o
    offsets-offsets.json.o
    getOffsets-LICENSE.o
    getOffsets-Makefile.o
    getOffsets-README.md.o
    getOffsets-extractOffsets.c.o
    getOffsets-getOffsets.c.o
    getOffsets-mount.h.o
    ebpfKern-LICENSE.o
    ebpfKern-sysinternalsEBPF_common.h.o
    ebpfKern-sysinternalsEBPF_helpers.c.o
    libbpf-LICENSE.LGPL-2.1.o
    libbpf-src-bpf_helpers.h.o
    libbpf-src-bpf_helper_defs.h.o
    libbpf-src-bpf_core_read.h.o
)

add_custom_target(packages
    COMMAND "${CMAKE_SOURCE_DIR}/makePackages.sh"  "${CMAKE_SOURCE_DIR}" "${PROJECT_BINARY_DIR}" "${PACKAGE_NAME}" "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}" "${PROJECT_VERSION_TWEAK}"
    DEPENDS "${CMAKE_SOURCE_DIR}/package" "${PROJECT_BINARY_DIR}/libsysinternalsEBPFinstaller"
)

set(PACKED_SOURCE_FILES
    libsysinternalsEBPF.h
    sysinternalsEBPFshared.h
    )

set(PACKED_OFFSETS_FILES
    offsets.json
    )

set(PACKED_GETOFFSETS_FILES
    LICENSE
    Makefile
    README.md
    extractOffsets.c
    getOffsets.c
    mount.h
    )

set(PACKED_EBPFKERN_FILES
    LICENSE
    sysinternalsEBPF_common.h
    sysinternalsEBPF_helpers.c
    )

set(PACKED_LIBBPF_FILES
    LICENSE.LGPL-2.1
    )

set(PACKED_LIBBPF_SRC_FILES
    bpf_helpers.h
    bpf_helper_defs.h
    bpf_core_read.h
    )

set(PACKED_BINARY_FILES
    sysinternalsEBPFmemDump.o
    sysinternalsEBPFrawSock.o
    sysinternalsEBPFoffsets.h
    )

foreach(SRC_FILE IN LISTS PACKED_SOURCE_FILES)
add_custom_command(OUTPUT "${SRC_FILE}.o"
                   COMMAND cd "${CMAKE_SOURCE_DIR}" && "${LD}" -r -b binary -o "${PROJECT_BINARY_DIR}/${SRC_FILE}.o" "${SRC_FILE}"
                   COMMENT "Packing ${SRC_FILE} into ${SRC_FILE}.o"
                   DEPENDS "${CMAKE_SOURCE_DIR}/${SRC_FILE}"
                   )
endforeach(SRC_FILE)

foreach(OFFSETS_FILE IN LISTS PACKED_OFFSETS_FILES)
add_custom_command(OUTPUT "offsets-${OFFSETS_FILE}.o"
                   COMMAND cd "${CMAKE_SOURCE_DIR}" && "${LD}" -r -b binary -o "${PROJECT_BINARY_DIR}/offsets-${OFFSETS_FILE}.o" "offsets/${OFFSETS_FILE}"
                   COMMENT "Packing offsets/${OFFSETS_FILE} into offsets-${OFFSETS_FILE}.o"
                   DEPENDS "${CMAKE_SOURCE_DIR}/offsets/${OFFSETS_FILE}"
                   )
endforeach(OFFSETS_FILE)

foreach(GETOFFSETS_FILE IN LISTS PACKED_GETOFFSETS_FILES)
add_custom_command(OUTPUT "getOffsets-${GETOFFSETS_FILE}.o"
                   COMMAND cd "${CMAKE_SOURCE_DIR}" && "${LD}" -r -b binary -o "${PROJECT_BINARY_DIR}/getOffsets-${GETOFFSETS_FILE}.o" "getOffsets/${GETOFFSETS_FILE}"
                   COMMENT "Packing getOffsets/${GETOFFSETS_FILE} into getOffsets-${GETOFFSETS_FILE}.o"
                   DEPENDS "${CMAKE_SOURCE_DIR}/getOffsets/${GETOFFSETS_FILE}"
                   )
endforeach(GETOFFSETS_FILE)

foreach(EBPFKERN_FILE IN LISTS PACKED_EBPFKERN_FILES)
add_custom_command(OUTPUT "ebpfKern-${EBPFKERN_FILE}.o"
                   COMMAND cd "${CMAKE_SOURCE_DIR}" && "${LD}" -r -b binary -o "${PROJECT_BINARY_DIR}/ebpfKern-${EBPFKERN_FILE}.o" "ebpfKern/${EBPFKERN_FILE}"
                   COMMENT "Packing ebpfKern/${EBPFKERN_FILE} into ebpfKern-${EBPFKERN_FILE}.o"
                   DEPENDS "${CMAKE_SOURCE_DIR}/ebpfKern/${EBPFKERN_FILE}"
                   )
endforeach(EBPFKERN_FILE)

foreach(LIBBPF_FILE IN LISTS PACKED_LIBBPF_FILES)
add_custom_command(OUTPUT "libbpf-${LIBBPF_FILE}.o"
                   COMMAND cd "${libbpf_SOURCE_DIR}" && "${LD}" -r -b binary -o "${PROJECT_BINARY_DIR}/libbpf-${LIBBPF_FILE}.o" "${LIBBPF_FILE}"
                   COMMENT "Packing ${libbpf_SOURCE_DIR}/${LIBBPF_FILE} into libbpf-${LIBBPF_FILE}.o"
                   DEPENDS "${libbpf_SOURCE_DIR}/${LIBBPF_FILE}"
                   )
endforeach(LIBBPF_FILE)

foreach(LIBBPF_SRC_FILE IN LISTS PACKED_LIBBPF_SRC_FILES)
add_custom_command(OUTPUT "libbpf-src-${LIBBPF_SRC_FILE}.o"
                   COMMAND cd "${libbpf_SOURCE_DIR}" && "${LD}" -r -b binary -o "${PROJECT_BINARY_DIR}/libbpf-src-${LIBBPF_SRC_FILE}.o" "src/${LIBBPF_SRC_FILE}"
                   COMMENT "Packing ${libbpf_SOURCE_DIR}/src/${LIBBPF_SRC_FILE} into libbpf-src-${LIBBPF_SRC_FILE}.o"
                   DEPENDS "${libbpf_SOURCE_DIR}/src/${LIBBPF_SRC_FILE}"
                   )
endforeach(LIBBPF_SRC_FILE)

foreach(BIN_FILE IN LISTS PACKED_BINARY_FILES)
add_custom_command(OUTPUT "${BIN_FILE}.o"
                   COMMAND "${LD}" -r -b binary -o "${BIN_FILE}.o" "${BIN_FILE}"
                   COMMENT "Packing ${BIN_FILE} into ${BIN_FILE}.o"
                   DEPENDS "${PROJECT_BINARY_DIR}/${BIN_FILE}"
                   )
endforeach(BIN_FILE)

add_custom_command(OUTPUT "libsysinternalsEBPF.so.o"
                   COMMAND "${LD}" -r -b binary -o "libsysinternalsEBPF.so.o" "libsysinternalsEBPF.so"
                   COMMENT "Packing libsysinternalsEBPF.so into libsysinternalsEBPF.so.o"
                   DEPENDS sysinternalsEBPF
                   )



install(FILES
            ebpfKern/LICENSE
            ebpfKern/sysinternalsEBPF_common.h
            ebpfKern/sysinternalsEBPF_helpers.c
            sysinternalsEBPFshared.h
            "${PROJECT_BINARY_DIR}/sysinternalsEBPFoffsets.h"
        DESTINATION /opt/sysinternalsEBPF/ebpfKern
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )

install(FILES
            getOffsets/LICENSE
            getOffsets/Makefile
            getOffsets/README.md
            getOffsets/extractOffsets.c
            getOffsets/getOffsets.c
            getOffsets/mount.h
        DESTINATION /opt/sysinternalsEBPF/getOffsets
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)

install(FILES
            "${libbpf_SOURCE_DIR}/LICENSE.LGPL-2.1"
            "${libbpf_SOURCE_DIR}/src/bpf_helpers.h"
            "${libbpf_SOURCE_DIR}/src/bpf_helper_defs.h"
            "${libbpf_SOURCE_DIR}/src/bpf_core_read.h"
        DESTINATION /opt/sysinternalsEBPF/libbpf
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)

set(RESOURCE_FILES
    offsets/offsets.json
    "${PROJECT_BINARY_DIR}/sysinternalsEBPFmemDump.o"
    "${PROJECT_BINARY_DIR}/sysinternalsEBPFrawSock.o"
)


set_target_properties(sysinternalsEBPF PROPERTIES
    PUBLIC_HEADER libsysinternalsEBPF.h
    RESOURCE "${RESOURCE_FILES}"
    )

install(TARGETS sysinternalsEBPF
    LIBRARY DESTINATION lib ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION include ${CMAKE_INSTALL_INCLUDEDIR}
    RESOURCE DESTINATION /opt/sysinternalsEBPF/
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )

install(TARGETS libsysinternalsEBPFinstaller
        DESTINATION /opt/sysinternalsEBPF/
    )

# list of ebpf programs to make
set(EBPF_PROGS
               sysinternalsEBPFmemDump
               sysinternalsEBPFrawSock
)

# list of files the EBPF programs depend upon
set(EBPF_DEPENDS
               libbpf
               sysinternalsEBPFshared.h
               sysinternalsEBPFoffsets.h
               ebpfKern/sysinternalsEBPF_helpers.c
               ebpfKern/sysinternalsEBPF_common.h
)

#
# automatically generate sources from generateUnameOffsets.py and offsetsNeeded.json
#
add_custom_command(OUTPUT sysinternalsEBPFoffsets.h
                   COMMAND python3 "${CMAKE_SOURCE_DIR}/generateUnameOffsets.py" "${CMAKE_SOURCE_DIR}/offsetsNeeded.json" PUBLIC_HEADER > sysinternalsEBPFoffsets.h
                   COMMENT "Extracting sysinternalsEBPFoffsets.h"
                   DEPENDS "${CMAKE_SOURCE_DIR}/generateUnameOffsets.py" "${CMAKE_SOURCE_DIR}/offsetsNeeded.json"
                   )

add_custom_command(OUTPUT unameOffsets.h
                   COMMAND python3 "${CMAKE_SOURCE_DIR}/generateUnameOffsets.py" "${CMAKE_SOURCE_DIR}/offsetsNeeded.json" HEADER > unameOffsets.h
                   COMMENT "Extracting unameOffsets.h"
                   DEPENDS "${CMAKE_SOURCE_DIR}/generateUnameOffsets.py" "${CMAKE_SOURCE_DIR}/offsetsNeeded.json"
                   )

add_custom_command(OUTPUT unameOffsets.c
                   COMMAND python3 "${CMAKE_SOURCE_DIR}/generateUnameOffsets.py" "${CMAKE_SOURCE_DIR}/offsetsNeeded.json" > unameOffsets.c
                   COMMENT "Extracting unameOffsets.c"
                   DEPENDS "${CMAKE_SOURCE_DIR}/generateUnameOffsets.py" "${CMAKE_SOURCE_DIR}/offsetsNeeded.json"
                   )


########################################################
# Everything below this point should be fairly static. #
########################################################


#
# EBPF COMPILE OPTIONS
#
# This section specifies the options for building ebpf programs
#

# set binaries and options for clang and llc
set(CLANG "clang")
set(LLC "llc")
set(CLANG_OPTIONS -Wno-unused-value
                  -Wno-pointer-sign
                  -Wno-compare-distinct-pointer-types
                  -Wno-gnu-variable-sized-type-not-at-end
                  -Wno-address-of-packed-member
                  -Wno-tautological-compare
                  -Wno-unknown-warning-option
                  -g
                  )
set(CLANG_DEFINES -D __KERNEL__
                  -D __BPF_TRACING__
                  -D __TARGET_ARCH_x86
                  )
if (DEBUG_K)
    message("Using DEBUG_K Option...")
    list(APPEND CLANG_DEFINES -DDEBUG_K)
endif()

set(CLANG_INCLUDES
                   -I "/usr/include"
                   -I "/usr/include/x86_64-linux-gnu"
                   -I "${CMAKE_SOURCE_DIR}"
                   -I "${CMAKE_BINARY_DIR}"
                   -I "${libbpf_SOURCE_DIR}/src"
                   )

#
# EBPF
#
# This section makes the EBPF programs
#

# function to make ebpf programs
function(build_ebpf ebpfsrc)
    add_custom_command(TARGET sysinternalsEBPF
                       PRE_BUILD
                       COMMAND "${CLANG}" -nostdinc -isystem `gcc -print-file-name=include` ${CLANG_INCLUDES} ${CLANG_DEFINES} -O2 ${CLANG_OPTIONS} -target bpf -c "${CMAKE_SOURCE_DIR}/ebpfKern/${ebpfsrc}.c" -o "${ebpfsrc}.o"
                       COMMENT "Building EBPF object ${ebpfsrc}.o"
                       DEPENDS ebpfKern/${ebpfsrc}.c ${EBPF_DEPENDS}
                       )
endfunction()

# loop for all ebpf programs
foreach(EBPF_PROG IN LISTS EBPF_PROGS)

    # test to only build ebpf programs when they have changed
    if(${CMAKE_SOURCE_DIR}/ebpfKern/${EBPF_PROG}.c IS_NEWER_THAN ${CMAKE_BINARY_DIR}/${EBPF_PROG}.o)
        build_ebpf(${EBPF_PROG})
    endif()

    # add ebpf programs to clean
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${EBPF_PROG}.o)
endforeach(EBPF_PROG)


