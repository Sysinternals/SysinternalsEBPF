# Build

## Prerequisites
- clang/llvm v10+


### Ubuntu
```
sudo apt update
sudo apt -y install build-essential gcc g++ make cmake libelf-dev llvm clang libzstd1 git libjson-glib-dev libc6-dev-i386
```

### Rocky Linux
```
yum install gcc gcc-c++ make cmake llvm clang elfutils-libelf-devel rpm-build json-glib-devel python3 glibc-devel.i686
```

### Debian
```
sudo apt -y install build-essential gcc g++ make cmake libelf-dev llvm clang libzstd1 git libjson-glib-dev libc6-dev-i386
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
sudo ./libsysinternalsEBPFinstaller -i
```
Or:
```
sudo make install
sudo ldconfig
```
The shared library will be installed to /lib/x86_64-linux-gnu (Debian) or
/lib64 (Fedora) or /usr/lib (pre multi arch Debian).; the header to /usr/include;
the offsets database and EBPF objects to /opt/sysinternalsEBPF.  The libsysinternalsEBPFinstaller
 binary will also be installed in /opt/sysinternalsEBPF (which can be copied to another
  system and run to install sysinternalsEBPF there). *Note:* 'sudo make install' will use
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

