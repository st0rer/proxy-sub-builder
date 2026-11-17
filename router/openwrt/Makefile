include $(TOPDIR)/rules.mk

PKG_NAME:=singbox-sub-client
PKG_VERSION:=1.1.0
PKG_RELEASE:=1

PKG_MAINTAINER:=st0rer <https://github.com/st0rer>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/singbox-sub-client
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing
  TITLE:=Autonomous sing-box subscription client with PBR and Gemini/Geo verification
  URL:=https://github.com/st0rer/proxy-sub-builder
  DEPENDS:=+sing-box +curl +jq +ca-bundle +kmod-tun +python3-light
  PKGARCH:=all
endef

define Package/singbox-sub-client/description
  Lightweight router agent consuming proxy-sub-builder subscriptions (VLESS Reality, Hysteria2, SS).
  Features 2-phase in-situ verification (Gemini/Geo-IP filter), tun interface management (gvisor, mtu 1200),
  Cloudflare worker failover watchdog, rp_filter relaxation, and policy-based routing (pbr) integration.
endef

define Package/singbox-sub-client/conffiles
/etc/config/sb-client
/etc/sing-box/config.json
/etc/sing-box/cf_node.json
endef

define Build/Compile
	# Pure python and shell scripts; no compilation needed.
endef

define Package/singbox-sub-client/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/sbgen.py $(1)/usr/bin/sbgen.py
	$(INSTALL_BIN) ./files/usr/bin/sb-refresh $(1)/usr/bin/sb-refresh
	$(INSTALL_BIN) ./files/usr/bin/cf-watchdog $(1)/usr/bin/cf-watchdog

	$(INSTALL_DIR) $(1)/usr/share/sb-client
	$(INSTALL_DATA) ./files/usr/share/sb-client/google-nets.txt $(1)/usr/share/sb-client/google-nets.txt

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/sb-client $(1)/etc/config/sb-client

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/sb-client $(1)/etc/init.d/sb-client

	$(INSTALL_DIR) $(1)/etc/hotplug.d/net
	$(INSTALL_BIN) ./files/etc/hotplug.d/net/50-sbtun-route $(1)/etc/hotplug.d/net/50-sbtun-route

	$(INSTALL_DIR) $(1)/etc/sing-box
endef

define Package/singbox-sub-client/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/sb-client enable
	echo "singbox-sub-client installed. Configure /etc/config/sb-client and run: /etc/init.d/sb-client start"
fi
exit 0
endef

define Package/singbox-sub-client/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/sb-client stop 2>/dev/null || true
	/etc/init.d/sb-client disable 2>/dev/null || true
fi
exit 0
endef

$(eval $(call BuildPackage,singbox-sub-client))
