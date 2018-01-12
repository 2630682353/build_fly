#
# Copyright (C) 2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=klog-cfg
PKG_VERSION:=0.1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/klog-cfg
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=klog-cfg progress
  FILES:=$(PKG_BUILD_DIR)/klog-cfg
  AUTOLOAD:=$(call AutoLoad,50,klog-cfg)
endef

define Package/klog-cfg/description
  Klog-cfg progress for receive kernel's log.
endef

define Build/Configure
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/klog-cfg/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/klog-cfg $(1)/bin/	
endef
$(eval $(call BuildPackage,klog-cfg))
