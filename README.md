# SysinternalsEBPF [![Build Status](https://dev.azure.com/sysinternals/Tools/_apis/build/status/Sysinternals.SysinternalsEBPF?repoName=Sysinternals%2FSysinternalsEBPF&branchName=main)](https://dev.azure.com/sysinternals/Tools/_build/latest?definitionId=337&repoName=Sysinternals%2FSysinternalsEBPF&branchName=main)

## Build
Please see build instructions [here](BUILD.md).

## Autodiscovery of Offsets
SysinternalsEBPF attempts to automatically discover the offsets of some members
of some kernel structs. If this fails, please provide details of the kernel
version (and config if possible) plus the error message to the GitHub issues page.

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

