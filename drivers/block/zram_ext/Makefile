# SPDX-License-Identifier: GPL-2.0-only
# zram with the features GKI leaves off for its own zram.ko:
#  - writeback to a backing device;
#  - per-slot access time, so "echo <seconds> > idle" marks only slots not
#    accessed for that long (and debugfs block_state);
#  - recompression with secondary algorithms (recomp_algorithm, recompress).
ccflags-y += -DCONFIG_ZRAM_WRITEBACK=1
ccflags-y += -DCONFIG_ZRAM_MEMORY_TRACKING=1
ccflags-y += -DCONFIG_ZRAM_MULTI_COMP=1

zram_ext-y	:=	zcomp.o zram_drv.o

obj-$(CONFIG_ZRAM_EXT)	+=	zram_ext.o
