#!/bin/sh

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

#################################################################################
#
# makePackages.sh
#
# Builds the directory trees for DEB and RPM packages and, if suitable tools are
# available, builds the actual packages too.
#
#################################################################################


if [ "$5" = "" ]; then
    echo "Usage: $0 <SourceDir> <BinaryDir> <package name> <package version> <package release>"
    exit 1
fi

# copy cmake vars
CMAKE_SOURCE_DIR=$1
PROJECT_BINARY_DIR=$2
PACKAGE_NAME=$3
PACKAGE_VER=$4
PACKAGE_REL=$5

DEB_PACKAGE_NAME="${PACKAGE_NAME}_${PACKAGE_VER}-${PACKAGE_REL}_amd64"
RPM_PACKAGE_NAME="${PACKAGE_NAME}-${PACKAGE_VER}-${PACKAGE_REL}"

# find packaging tools
DPKGDEB=`which dpkg-deb`
RPMBUILD=`which rpmbuild`

# clean up first
if [ -d "${PROJECT_BINARY_DIR}/deb" ]; then
    rm -rf "${PROJECT_BINARY_DIR}/deb"
fi

if [ -d "${PROJECT_BINARY_DIR}/rpm" ]; then
    rm -rf "${PROJECT_BINARY_DIR}/rpm"
fi

# copy deb files
mkdir -p "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}"
cp -a "${CMAKE_SOURCE_DIR}/package/DEBIAN" "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/"
cp "${PROJECT_BINARY_DIR}/DEBIANcontrol" "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/DEBIAN/control"
cp -a "${CMAKE_SOURCE_DIR}/package/usr" "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/"
mkdir -p "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/usr/bin"
cp "${PROJECT_BINARY_DIR}/libsysinternalsEBPFinstaller" "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/usr/bin/"

# make the deb
if [ "$DPKGDEB" != "" ]; then
    cd "${PROJECT_BINARY_DIR}/deb"
    "$DPKGDEB" -Zxz --build --root-owner-group "${DEB_PACKAGE_NAME}"
else
    echo "No dpkg-deb found"
fi

# copy rpm files
mkdir -p "${PROJECT_BINARY_DIR}/rpm/${RPM_PACKAGE_NAME}/SPECS"
cp -a "${PROJECT_BINARY_DIR}/SPECSRPM.spec" "${PROJECT_BINARY_DIR}/rpm/${RPM_PACKAGE_NAME}/SPECS/${RPM_PACKAGE_NAME}.spec"
mkdir "${PROJECT_BINARY_DIR}/rpm/${RPM_PACKAGE_NAME}/BUILD/"
cp "${CMAKE_SOURCE_DIR}/package/usr/share/man/man3/sysinternalsebpf.3.gz" "${PROJECT_BINARY_DIR}/libsysinternalsEBPFinstaller" "${PROJECT_BINARY_DIR}/libsysinternalsEBPF.so" "${PROJECT_BINARY_DIR}/rpm/${RPM_PACKAGE_NAME}/BUILD/"

if [ "$RPMBUILD" != "" ]; then
    cd "${PROJECT_BINARY_DIR}/rpm/${RPM_PACKAGE_NAME}"
    "$RPMBUILD" --define "_topdir `pwd`" -v -bb "SPECS/${RPM_PACKAGE_NAME}.spec"
    cp RPMS/x86_64/*.rpm ..
else
    echo "No rpmbuild found"
fi

