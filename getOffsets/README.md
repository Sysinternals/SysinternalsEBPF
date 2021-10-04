# SysinternalsEBPF getOffsets

getOffsets is a kernel module that obtains the offsets into kernel internals
and generates content for a sysinternalsEBPF\_offsets.conf file.  This file can
be used if SysinternalsEBPF cannot automatically discover the offsets by itself.

The output should be stored in:
/opt/sysinternalsEBPF/sysinternalsEBPF\_offsets.conf

# Dependencies
```
sudo apt install make gcc
```

# Build
From the /opt/sysinternals/getOffsets directory *on the target machine*:
```
make
```

# Generate config file
From the /opt/sysinternalsEBPF/getOffsets directory *on the target machine*:

```
make conf > /opt/sysinternalsEBPF/sysinternalsEBPF_offsets.conf
```

*Note: The module is not actually loaded - the offsets are stored statically as global
variables, and this step extracts them from the module file.*

# mount.h
getOffsets includes mount.h taken verbatim from the source of v4.15 of the Linux kernel.
This file can often be found at /usr/src/linux/fs/mount.h.

This source file hasn't materially changed (at least in relation to the struct mount that
we require) between v4.0 and v5.13 of the Linux kernel.  Post v5.13, if the definition of
struct mount changes, the source file getOffsets.c can be simply modified to pick up the
version in the Linux source - this will require the source code.  Alternatively, a suitable
version of this file can be extracted from the relevant archive of the kernel source and
placed in the SysinternalsEBPF/getOffsets directory.

# Licenses
getOffsets is licensed under GPL2.

getOffsets includes mount.h taken verbatim from the source of v4.15 of the Linux kernel;
this file is licensed under GPL2.


