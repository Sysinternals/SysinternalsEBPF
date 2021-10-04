# SysinternalsEBPF build and install instructions

## Dependencies
For Ubuntu:
```
sudo apt update
sudo apt install build-essential gcc g++ make cmake libelf-dev llvm clang libzstd1 git libjson-glib-dev
```

## Build
```
cd
git clone *repo*
cd SysinternalsEBPF
mkdir build
cd build
cmake ..
make
```

## Install
SysinternalsEBPF can be installed in two different ways, either directly via
CMake (if just built) or by running the libsysinternalsEBPFinstaller binary.
The installer binary is portable and contains all the necessary files to
install sysinternalsEBPF onto a system.

Either:
```
sudo make install
```
Or:
```
sudo ./libsysinternalsEBPFinstaller
```
The shared library will be installed to /usr/lib; the header to
/usr/include; the offsets database and EBPF objects to
/opt/sysinternalsEBPF.  The libsysinternalsEBPFinstaller binary will also be
installed in /opt/sysinternalsEBPF (which can be copied to another system and
run to install sysinternalsEBPF there).

## Make Packages
Packages can be generated with:
```
make packages
```
The directories build/deb and build/rpm will be populated with the required
files. If dpkg-deb is available, the build/deb directory will be used to create
a deb package. Similarly if rpmbuild is available, the build/rpm directory will
be used to create an rpm package.

## Autodiscovery of Offsets
SysinternalsEBPF attempts to automatically discover the offsets of some members
of some kernel structs. If this fails, please provide details of the kernel
version (and config if possible) plus the error message to:
```
kevin.sheldrake AT microsoft.com
```
You can then generate a configuration file to override the autodiscovery by
building the getOffsets module in the /opt/sysinternals/getOffsets directory.
See the README.md in that directory for more information.

## Manual Page
A man page for SysinternalsEBPF can be found in the deb directory, and is
installed by both deb and rpm packages.

Use 'find' on the deb directory to locate it manually.

## License
SysinternalsEBPF is licensed under LGPL2.1.
SysinternalsEBPF includes libbpf, which is licensed under LGPL2.1.
Libbpf can be located at https://github.com/libbpf/libbpf
The SysinternalsEBPF library of eBPF code is licensed under GPL2.

