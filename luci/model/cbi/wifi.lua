local nw = require "luci.model.network"


m = Map("wireless",translate("WIFI"),translate("无线域网配置参数"))
nw.init(m.uci)

local wnet = nw:get_wifinet("wlan0")
local wdev = wnet and wnet:get_device()

s = m:section(NamedSection, wnet.sid, "wifi-iface", translate("无线WIFI"))


s:option(Value, "ssid", translate("essid"))

pwd=s:option(ListValue, "encryption","是否需要密码")
pwd.widget = "radio"

pwd:value("psk2","是")
pwd:value("none","否")

pwd.orientation="horizontal"

password = s:option(Value, "key", translate("密码"))

password:depends("encryption", "psk2")




return m
