# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Baseband-guard
#

obj-$(CONFIG_BBG) += bbg.o

bbg-y := baseband_guard.o
bbg-y += blkdev_helper.o
bbg-y += tracing/tracing.o

# Vendored from vc-teahouse/Baseband-guard.  Static on purpose: the upstream
# Makefile derives this by running git during kbuild parsing, which needs the
# network and makes the build unreproducible.
ccflags-y += -DBBG_VERSION=\"a54e0dc6\"

# security_file_ioctl_compat() exists in this tree, see the file_ioctl_compat
# entry in include/linux/lsm_hook_defs.h.  If a rebase ever drops it the
# LSM_HOOK_INIT() below this define stops compiling, which is the intended
# failure mode: silently losing the compat ioctl path would leave a hole.
ccflags-y += -DBB_HAS_IOCTL_COMPAT

# The LSM only initialises if it is listed in CONFIG_LSM.  Catch the mistake
# here rather than at runtime, where it would look like the guard is simply
# not working.
ifeq ($(CONFIG_BBG),y)
ifeq ($(findstring baseband_guard,$(CONFIG_LSM)),)
$(error CONFIG_BBG=y requires baseband_guard in CONFIG_LSM, listed after selinux)
endif
endif
