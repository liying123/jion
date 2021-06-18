include $(TOPDIR)/rules.mk
 
PKG_NAME:=host-trans
PKG_RELEASE:=1
 
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
 
include $(INCLUDE_DIR)/package.mk
 
define Package/host-trans
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=host-trans -- prints a snarky message
	DEPENDS:=+libc
endef
 
define Package/host-trans/description
	It's host-trans first package demo.
endef
 
define Build/Prepare   #已修正
	echo "Here is Package/Prepare"
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef
 
define Package/host-trans/install
	echo "Here is Package/install"
	$(INSTALL_DIR) $(1)/bin
	$(CP) /lib/x86_64-linux-gnu/libc.so.6 libz.so.1 $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/host-trans $(1)/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/host-trans.sh $(1)/bin/
endef
 
$(eval $(call BuildPackage,host-trans))   #已去除逗号后面的空格
