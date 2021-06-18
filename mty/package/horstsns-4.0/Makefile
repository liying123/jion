#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=horstsns
PKG_VERSION:=4.0
PKG_RELEASE:=2

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-git.tar.gz
#PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
#PKG_SOURCE_URL:=git://br1.einfach.org/horst
#PKG_SOURCE_PROTO:=git
#PKG_SOURCE_VERSION:=version-4.0

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/horstsns
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=wireless
	DEPENDS:=+libncurses +libpthread +libcurl +libroxml
	MAINTAINER:=Bruno Randolf <br1@einfach.org>
	TITLE:=Highly Optimized 802.11 Radio Scanning Tool
	URL:=http://br1.einfach.org/tech/horst/
endef

define Package/horstsns/description
	[horstsns] is a scanning and analysis tool for 802.11 wireless networks
	and especially IBSS (ad-hoc) mode and mesh networks (OLSR).
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/horstsns/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/horstsns $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/horstsns.sh $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,horstsns))
