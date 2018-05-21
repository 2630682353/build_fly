#
# Copyright (C) 2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=as
PKG_VERSION:=0.1
PKG_RELEASE:=1

MODULE_NAME := as.ko
MODULE_INIT := as

include $(INCLUDE_DIR)/package.mk

define KernelPackage/as
  SUBMENU:=Network Support
  TITLE:=Access Service Module
  FILES:=$(PKG_BUILD_DIR)/$(MODULE_NAME)
  AUTOLOAD:=$(call AutoLoad,50,as)
  DEPENDS+=+libipc +klog
endef

define KernelPackage/as/description
  Access Service Modules.
endef

include $(INCLUDE_DIR)/kernel-defaults.mk

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) $(KERNEL_MAKEOPTS) SUBDIRS="$(PKG_BUILD_DIR)" modules
endef

define KernelPackage/as/conffiles
/etc/config/as
endef

define Build/InstallDev
	$(INSTALL_DIR)	$(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/dpi-hook.h $(1)/usr/include/
endef

define KernelPackage/as/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/$(MODULE_INIT).init $(1)/etc/init.d/$(MODULE_INIT)
	$(INSTALL_DIR) $(1)/$(MODULE_SUBDIR)
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(MODULE_NAME) $(1)/$(MODULE_SUBDIR)
endef

$(eval $(call KernelPackage,as))
