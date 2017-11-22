include $(TOPDIR)/rules.mk

PKG_NAME:=libipc
PKG_VERSION:=0.1
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

INIT=netlink_kernel.init
KO=netlink_kernel.ko

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/libipc
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=libipc
endef

TARGET_CFLAGS += $(FPIC)

define Build/Compile
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./src/include/* $(PKG_BUILD_DIR)/kernel/
	$(MAKE) -C $(PKG_BUILD_DIR)/kernel \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		KDIR="$(LINUX_DIR)" \
		ARCH="$(LINUX_KARCH)"

	$(MAKE) -C $(PKG_BUILD_DIR)/user \
		$(TARGET_CONFIGURE_OPTS) \
		LDFLAGS="$(TARGET_LDFLAGS)"\
		

endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib  $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/include/* $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/user/libipc.so $(1)/usr/lib/
endef

define Package/libipc/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/$(MODULES_SUBDIR)
	$(CP) $(PKG_BUILD_DIR)/kernel/$(KO) $(1)/$(MODULES_SUBDIR)
	$(INSTALL_BIN) ./src/files/$(INIT) $(1)/etc/init.d/$(INIT)

	$(INSTALL_DIR) $(1)/usr/lib $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/user/libipc.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libipc))