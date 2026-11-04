obj-$(CONFIG_KSU) := ksu.o
ksu-y := ksu_main.o

ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h

ifeq ($(filter /%,$(src)),)
KSU_KERNEL_DIR := $(srctree)/$(src)
else
KSU_KERNEL_DIR := $(src)
endif

ifeq ($(CONFIG_KSU_SUSFS), y)
## As we are building gki only, no KBUILD_EXTMOD is needed
## Since there is still a build error for 6.12 as $(src) returns absolute path, so here we just hardcode it
ccflags-y += -I$(srctree)/drivers/kernelsu -I$(srctree)/drivers/kernelsu/include
else
ccflags-y += -I$(KSU_KERNEL_DIR) -I$(KSU_KERNEL_DIR)/include
endif

MDIR    := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# ===== preinit runner =====
KSU_UAPI_INC := $(objtree)/usr/include
ifneq ($(wildcard $(KSU_UAPI_INC)/linux/unistd.h),)
ksu-y += preinit/preinit.o preinit/blob.o

KSU_RUNNER_CFLAGS := $(CLANG_FLAGS) -std=gnu11 -Os -Wall \
	-nostdinc -isystem $(shell $(CC) -print-file-name=include) \
	-I$(KSU_KERNEL_DIR)/preinit/runner/nolibc -I$(KSU_UAPI_INC) \
	-I$(KSU_KERNEL_DIR)/include \
	-ffreestanding -fno-stack-protector -fno-pic -fno-pie \
	-fno-asynchronous-unwind-tables -fno-unwind-tables \
	-ffunction-sections -fdata-sections

quiet_cmd_ksu_runner = RUNNER  $@
      cmd_ksu_runner = $(CC) $(KSU_RUNNER_CFLAGS) -c -o $@.o $< && \
		$(LD) -static -nostdlib -e _start --gc-sections -s -o $@ $@.o && \
		rm -f $@.o

$(obj)/preinit/runner.elf: $(KSU_KERNEL_DIR)/preinit/runner/runner.c \
		$(wildcard $(KSU_KERNEL_DIR)/preinit/runner/nolibc/*.h \
			   $(KSU_KERNEL_DIR)/preinit/runner/nolibc/sys/*.h \
			   $(KSU_KERNEL_DIR)/include/uapi/*.h) FORCE
	$(call if_changed,ksu_runner)

targets += preinit/runner.elf

$(obj)/preinit/blob.o: $(obj)/preinit/runner.elf
asflags-y += -DKSU_PREINIT_RUNNER_BIN=\"$(abspath $(obj)/preinit/runner.elf)\"

else
$(warning -- KernelSU: $(KSU_UAPI_INC) not found, preinit disabled)
ccflags-y += -DKSU_NO_PREINIT
endif
# ===== end preinit runner =====

REPO_NAME   := SukiSU-Ultra

# SukiSU-Ultra is vendored here without its git history. Upstream derives
# the version at build time from git and from the GitHub API (latest release
# tag and the live commit count of the main branch), which is neither
# available nor reproducible in-tree. Pin every value to the imported commit:
# https://github.com/SukiSU-Ultra/SukiSU-Ultra/commit/1cfa57340590971cba7521ed536da8ebbedc5f0a
# Update them whenever drivers/kernelsu/ is re-synced.
#   KSU_MAIN_COUNT  = git rev-list --count main  (main at 075ac81f, as the
#                     GitHub API reported it when this snapshot was imported)
#   VERSION_TAG     = latest GitHub release tag, without the leading "v"
#   KSU_COMMIT_SHA  = git rev-parse --short=8 HEAD  (the builtin snapshot)
#   KSU_BRANCH      = git rev-parse --abbrev-ref HEAD
VERSION_BASE    := 40000
VERSION_OFFSET  := 2815
KSU_MAIN_COUNT  := 3963
VERSION_TAG     := 4.3.0-r1
KSU_COMMIT_SHA  := 1cfa5734
KSU_BRANCH      := builtin
KSU_UAPI_VERSION := 6

KSU_VERSION     := $(shell expr $(VERSION_BASE) + $(KSU_MAIN_COUNT) - $(VERSION_OFFSET))
KSU_VERSION_FULL := v$(VERSION_TAG)-$(KSU_COMMIT_SHA)@$(KSU_BRANCH)

# The UAPI version itself is a constant in include/uapi/supercall.h; refuse
# to build if a re-sync changed it without updating the pins above.
KSU_UAPI_VERSION_SRC := $(shell sed -n 's/^DECLARE(__u32, KERNEL_SU_UAPI_VERSION, \([0-9]*\));$$/\1/p' $(KSU_KERNEL_DIR)/include/uapi/supercall.h)
ifneq ($(KSU_UAPI_VERSION_SRC),$(KSU_UAPI_VERSION))
$(error $(REPO_NAME): include/uapi/supercall.h declares UAPI version '$(KSU_UAPI_VERSION_SRC)', expected $(KSU_UAPI_VERSION); re-pin the version values above)
endif

$(info -- $(REPO_NAME) version: $(KSU_VERSION) [$(KSU_VERSION_FULL)], UAPI $(KSU_UAPI_VERSION))

ccflags-y += -DKSU_VERSION=$(KSU_VERSION)
ccflags-y += -DKSU_VERSION_FULL=\"$(KSU_VERSION_FULL)\"

KERNEL_VERSION := $(VERSION).$(PATCHLEVEL)
KERNEL_TYPE := Non-GKI
# Check for GKI 2.0 (5.10+ or 6.x+)
ifneq ($(shell test \( $(VERSION) -ge 5 -a $(PATCHLEVEL) -ge 10 \) -o $(VERSION) -ge 6; echo $$?),0)
# Check for GKI 1.0 (5.4)
ifeq ($(shell test $(VERSION)-$(PATCHLEVEL) = 5-4; echo $$?),0)
KERNEL_TYPE := GKI 1.0
endif
else
KERNEL_TYPE := GKI 2.0
endif
$(info -- KERNEL_VERSION: $(KERNEL_VERSION))
$(info -- KERNEL_TYPE: $(KERNEL_TYPE))

ifeq ($(CONFIG_KSU_SUSFS), y)
$(info -- $(REPO_NAME): using SUSFS_INLINE_HOOK)
else
$(info -- $(REPO_NAME): using Unknown)
endif

ifeq ($(CONFIG_KPM), y)
$(info -- KPM is enabled)
else
$(info -- KPM is disabled)
endif

# Check new vfs_getattr()
ifeq ($(shell grep -A1 "^int vfs_getattr" $(srctree)/fs/stat.c | grep -q "query_flags" ; echo $$?),0)
ccflags-y += -DKSU_HAS_NEW_VFS_GETATTR
endif

ifeq ($(shell grep -q " current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_CURRENT_SID
endif

ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_SELINUX_STATE
endif

ifeq ($(shell grep -q "strncpy_from_user_nofault" $(srctree)/include/linux/uaccess.h; echo $$?),0)
ccflags-y += -DKSU_HAS_STRNCPY_FROM_USER_NOFAULT
endif

ifeq ($(shell grep -q "atomic_t\s\+filter_count" $(srctree)/include/linux/seccomp.h; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_SECCOMP_FILTER_CNT
endif

# some old kernel backport this, check if put_seccomp_filter still exist
ifneq ($(shell grep -wq "put_seccomp_filter" $(srctree)/kernel/seccomp.c $(srctree)/include/linux/seccomp.h; echo $$?),0)
ifeq ($(shell grep -wq "seccomp_filter_release" $(srctree)/kernel/seccomp.c $(srctree)/include/linux/seccomp.h; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_SECCOMP_FILTER_RELEASE
endif
endif

ifeq ($(shell grep -q "^DEFINE_RWLOCK(policy_rwlock);" $(srctree)/security/selinux/ss/services.c; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_EXPORTED_POLICY_RWLOCK
endif

ifeq ($(shell grep -q "cpus_ptr;" $(srctree)/include/linux/sched.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_BACKPORTED_CPUS_PTR
endif

ifeq ($(shell grep -q "selinux_inode" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_HAS_SELINUX_INODE
endif

ifeq ($(shell grep -q "selinux_cred" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_HAS_SELINUX_CRED
endif

ifeq ($(shell grep -q "struct type_datum \*\*type_val_to_struct;" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
ccflags-y += -DKSU_TYPE_VAL_TO_STRUCT
endif

# half-assed-backport from 5.1
ifeq ($(shell grep -q "struct type_datum \*\*type_val_to_struct_array;" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
ccflags-y += -DKSU_TYPE_VAL_TO_STRUCT_ARRAY
endif

# https://github.com/torvalds/linux/commit/11276d5306b8e5b438a36bbff855fe792d7eaa61
ifeq ($(shell grep -q "DEFINE_STATIC_KEY_TRUE" $(srctree)/include/linux/jump_label.h 2>/dev/null; echo $$?),0)
$(info -- $(REPO_NAME)/compat: modern static_key_interface found)
ccflags-y += -DKSU_HAS_MODERN_STATIC_KEY_INTERFACE
endif

# Vendor backports may change these fields independently of LINUX_VERSION_CODE.
# Inspect the actual target source header, not the host kernel or KMI label.
ksu_netlink_cfg := $(shell sed -n '/struct netlink_kernel_cfg {/,/^};/p' $(srctree)/include/linux/netlink.h)
ifneq ($(findstring cb_mutex,$(ksu_netlink_cfg)),)
ccflags-y += -DKSU_NETLINK_CFG_HAS_CB_MUTEX=1
endif
ifneq ($(findstring compare,$(ksu_netlink_cfg)),)
ccflags-y += -DKSU_NETLINK_CFG_HAS_COMPARE=1
endif

KSU_PACKAGE_NAME ?= com.sukisu.ultra

ccflags-y += -DKSU_PACKAGE_NAME=\"$(KSU_PACKAGE_NAME)\"

## For susfs stuff ##
ifeq ($(shell test -e $(srctree)/fs/susfs.c; echo $$?),0)
$(eval SUSFS_VERSION=$(shell cat $(srctree)/include/linux/susfs.h | grep -E '^#define SUSFS_VERSION' | cut -d' ' -f3 | sed 's/"//g'))
$(info )
$(info -- SUSFS_VERSION: $(SUSFS_VERSION))
else
$(info -- You have not integrated susfs in your kernel yet.)
$(info -- Read: https://gitlab.com/simonpunk/susfs4ksu)
endif

ccflags-y += -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat -Wno-missing-prototypes
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function


# Keep a new line here!! Because someone may append config
