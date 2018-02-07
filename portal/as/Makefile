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

include $(INCLUDE_DIR)/package.mk

define KernelPackage/as
  SUBMENU:=Network Support
  TITLE:=Access Service Module
  FILES:=$(PKG_BUILD_DIR)/as.ko
  AUTOLOAD:=$(call AutoLoad,50,as)
  DEPENDS+=+libipc
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

define KernelPackage/as/install
endef

$(eval $(call KernelPackage,as))
