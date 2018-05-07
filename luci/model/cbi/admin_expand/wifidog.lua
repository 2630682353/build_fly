local nt = require "luci.sys".net
local fs = require "nixio.fs"
local has_wfg  = fs.access("/etc/config/wifidog")

if has_wfg then
m = Map("wifidog",
        translate(""))
s = m:section(TypedSection,"wifidog",translate(""))
s.addremove =  false
s.anonymous = true

sr=s:option(ListValue, "disabled", translate("Enable Wifidog"))
sr.rmempty = true
sr:value("0", translate("Enable"))
sr:value("1", translate("Disable"))

function m.on_commit()
        if m.uci:get("wifidog","wifidog", "disabled") == "0" then
                luci.sys.call("/etc/init.d/wifidog enable")
                luci.sys.call("/etc/init.d/wifidog restart")
        else
                luci.sys.call("/etc/init.d/wifidog disable")
                luci.sys.call("/etc/init.d/wifidog stop")
        end
end
        end
return m

