#
# Copyright (C) 2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=klog
PKG_VERSION:=0.1
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

MODULE_NAME:=klog-m.ko
MODULE_INIT:=klog

include $(INCLUDE_DIR)/package.mk

define KernelPackage/klog
  SUBMENU:=Other modules
  TITLE:=Kernel Log Module
  FILES:=$(PKG_BUILD_DIR)/klog-m.ko
  AUTOLOAD:=$(call AutoLoad,50,klog)
endef

define KernelPackage/klog/description
  Kernel Log Modules.
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
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/klog.h $(1)/usr/include/
endef

define Package/klog/install
	$(INSTALL_DIR) $(1)/usr/include
endef

define KernelPackage/klog/conffiles
/etc/config/klog
endef

define KernelPackage/klog/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/$(MODULE_INIT).init $(1)/etc/init.d/$(MODULE_INIT)
	$(INSTALL_DIR)	$(1)/$(MODULES_SUBDIR)
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(MODULE_NAME) $(1)/$(MODULES_SUBDIR)
endef

$(eval $(call KernelPackage,klog))
