# SPDX-License-Identifier: GPL-2.0-only
# zram with the features GKI leaves off for its own zram.ko.
ccflags-y += -DCONFIG_ZRAM_WRITEBACK=1

zram_ext-y	:=	zcomp.o zram_drv.o

obj-$(CONFIG_ZRAM_EXT)	+=	zram_ext.o
