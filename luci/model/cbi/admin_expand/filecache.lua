local nt = require "luci.sys".net
local fs = require "nixio.fs"
local has_autu  = fs.access("/etc/config/wxserver")



if has_autu then 
luci.sys.call("/usr/sbin/wxauth giface")
m = Map("wxserver",translate(""))


s = m:section(TypedSection,"wxclass2",translate("")) 
s.addremove =  false
s.anonymous = true
sr=s:option(ListValue, "disabled", translate("Enable Filecache"))
sr.rmempty = true
sr:value("0", translate("Enable"))
sr:value("1", translate("Disable"))

ml = s:option(DynamicList, "cachehost", translate("cachehost")) 
ml.datatype = "blackif"


--[[
function m.on_before_save()
	if m.uci:get("wxserver","wxauth", "blackif")==nil or m.uci:get("wxserver","wxauth", "reset_au")==nil then
		m.uci:unload("wxserver")
		m.message = translate("Some input is null")
	else
		function m.on_commit()
			if m.uci:get("wxserver","wxauth", "disabled") == "0" then
				luci.sys.call("/etc/init.d/wxauth enable")
				luci.sys.call("/etc/init.d/wxauth restart")
				m.message = translate("Authentication Started")
			else 
				luci.sys.call("/etc/init.d/wxauth disable")
				luci.sys.call("/etc/init.d/wxauth stop")
				m.message = translate("Authentication Stopped")
			end
		end
	end

end
]]--
end

return m
