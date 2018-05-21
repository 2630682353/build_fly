#
# Copyright (C) 2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=dpid
PKG_VERSION:=0.1
PKG_RELEASE:=1

PROGRAM_INIT:=dpid
PROGRAM_CFG:=dpid

include $(INCLUDE_DIR)/package.mk

define Package/dpid
  SECTION:=network
  CATEGORY:=Network
  TITLE:=DPID program
  FILES:=$(PKG_BUILD_DIR)/dpid
  AUTOLOAD:=$(call AutoLoad,50,dpid)
  DEPENDS += +libpthread +libshare +libjson-c +libcurl +libipc
endef

define Package/dpid/description
  DPID program for gather/format/compress/uploading kernel's dpi data.
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

define Package/dpid/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dpid $(1)/bin/	
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/$(PROGRAM_INIT).init $(1)/etc/init.d/$(PROGRAM_INIT)
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./etc/$(PROGRAM_CFG).cfg $(1)/etc/config/$(PROGRAM_CFG)
endef
$(eval $(call BuildPackage,dpid))
