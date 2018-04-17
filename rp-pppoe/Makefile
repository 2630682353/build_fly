include $(TOPDIR)/rules.mk

PKG_NAME:=rp-pppoe
PKG_VERSION:=3.12
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz

PKG_BUILD_DEPENDS:=ppp
include $(INCLUDE_DIR)/package.mk

define Package/rp-pppoe
	SUBMENU:=dial-in/up
    SECTION:=net
    CATEGORY:=Network
    DEPENDS:=+ppp
    TITLE:=PPPoE (PPP over Ethernet)
endef


define Package/rp-pppoe/conffiles
    /etc/ppp/pppoe-server-options
    /etc/default/pppoe-server
endef

TARGET_CFLAGS += -I$(PKG_BUILD_DIR)/src/libevent
CONFIGURE_PATH := ./src
CONFIGURE_ARGS += ac_cv_path_PPPD=/usr/sbin/pppd --enable-plugin=$(STAGING_DIR)/usr/include/
MAKE_FLAGS := DESTDIR="$(PKG_INSTALL_DIR)" install
MAKE_PATH := ./src

define Build/Configure
	sed -i '/"no defaults for cross-compiling"/d' $(PKG_BUILD_DIR)/src/configure
	$(Build/Configure/Default)
endef


define Package/rp-pppoe/install
	$(INSTALL_DIR) $(1)/etc/default
#    $(INSTALL_BIN) ./files/pppoe-server.default $(1)/etc/default/pppoe-server
	$(INSTALL_DIR) $(1)/etc/init.d
#    $(INSTALL_BIN) ./files/pppoe-server.init $(1)/etc/init.d/pppoe-server
	$(INSTALL_DIR) $(1)/etc/ppp
	$(INSTALL_DIR) $(1)/etc/ppp/plugins
	$(CP) $(PKG_INSTALL_DIR)/etc/ppp/pppoe-server-options $(1)/etc/ppp/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/pppoe-server $(1)/usr/sbin/
#    $(CP) $(PKG_INSTALL_DIR)/etc/ppp/plugins/rp-pppoe.so $(1)/etc/ppp/plugins/
endef

$(eval $(call BuildPackage,rp-pppoe))