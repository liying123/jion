include $(TOPDIR)/rules.mk
 
PKG_NAME:=tcp-server
PKG_RELEASE:=1
 
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
 
include $(INCLUDE_DIR)/package.mk
 
define Package/tcp-server
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=tcp-server -- prints a snarky message
	DEPENDS:=+libc
endef
 
define Package/tcp-server/description
	It's tcp-server first package demo.
endef
 
define Build/Prepare   #已修正
	echo "Here is Package/Prepare"
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef
 
define Package/tcp-server/install
	echo "Here is Package/install"
	$(INSTALL_DIR) $(1)/bin
	$(CP) /lib/x86_64-linux-gnu/libc.so.6 $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tcp-server $(1)/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tcp-server.sh $(1)/bin/
endef
 
$(eval $(call BuildPackage,tcp-server))   #已去除逗号后面的空格
