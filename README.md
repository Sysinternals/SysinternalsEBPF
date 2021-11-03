# SysinternalsEBPF build and install instructions

## Dependencies
For Ubuntu:
```
sudo apt update
sudo apt -y install build-essential gcc g++ make cmake libelf-dev llvm clang libzstd1 git libjson-glib-dev
```

## Build
```
cd
git clone https://github.com/Sysinternals/SysinternalsEBPF.git
cd SysinternalsEBPF
mkdir build
cd build
cmake ..
make
```

## (Build from Sysmon ADO internally)
*This is only required when cloning from the Sysmon ADO. Most users can ignore
this.*
```
cd
git clone <Sysmon ADO>
cd Sysmon/sysinternalsEBPF
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
sudo ./libsysinternalsEBPFinstaller
```
Or:
```
sudo make install
```
The shared library will be installed to /usr/lib; the header to
/usr/include; the offsets database and EBPF objects to
/opt/sysinternalsEBPF.  The libsysinternalsEBPFinstaller binary will also be
installed in /opt/sysinternalsEBPF (which can be copied to another system and
run to install sysinternalsEBPF there). *Note:* 'sudo make install' will use
the binary, include, and lib directories that cmake prefers or you have
overridden, whereas the installer and the packages (see below) use the paths
specified above.

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
A man page for SysinternalsEBPF can be found in the package directory, and is
installed by both deb and rpm packages.

Use 'find' on the package directory to locate it manually.

## License
SysinternalsEBPF is licensed under LGPL2.1.
SysinternalsEBPF includes libbpf, which is licensed under LGPL2.1.
Libbpf can be located at https://github.com/libbpf/libbpf
The SysinternalsEBPF library of eBPF code is licensed under GPL2.

