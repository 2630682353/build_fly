#
# Copyright (C) 2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=dpi
PKG_VERSION:=0.1
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

MODULE_NAME:=dpi-m.ko
MODULE_INIT:=dpi

include $(INCLUDE_DIR)/package.mk

define KernelPackage/dpi
  SUBMENU:=Network Support
  TITLE:=Kernel DPI Module
  FILES:=$(PKG_BUILD_DIR)/dpi-m.ko
  AUTOLOAD:=$(call AutoLoad,50,dpi)
  DEPENDS+=+klog +libipc
endef

define KernelPackage/dpi/description
  Kernel DPI Modules.
endef

include $(INCLUDE_DIR)/kernel-defaults.mk

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) $(KERNEL_MAKEOPTS) SUBDIRS="$(PKG_BUILD_DIR)" modules
endef

define Build/InstallDev
endef

define Package/dpi/install
	$(INSTALL_DIR) $(1)/usr/include
endef


define KernelPackage/dpi/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/$(MODULE_INIT).init $(1)/etc/init.d/$(MODULE_INIT)
	$(INSTALL_DIR)	$(1)/$(MODULES_SUBDIR)
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(MODULE_NAME) $(1)/$(MODULES_SUBDIR)
endef

$(eval $(call KernelPackage,dpi))
