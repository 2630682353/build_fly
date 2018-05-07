local nt = require "luci.sys".net
local fs = require "nixio.fs"
local has_autu  = fs.access("/etc/config/wxserver")
local flag1 = true
local run1  = true
local fd1   = nil
local flag2 = true
local run2  = true
local fd2   = nil	


if has_autu then 
luci.sys.call("/usr/sbin/wxauth giface")
m = Map("wxserver",translate(""))


s1 = m:section(TypedSection,"wxserver","") 
s1.anonymous = true
s1.addremove = false
name1 = s1:option(DummyValue,"name", translate("Name"))


s = m:section(TypedSection,"wxclass",translate("")) 
s.addremove =  false
s.anonymous = true
sr=s:option(ListValue, "disabled", translate("Enable auth"))
sr.rmempty = true
sr:value("0", translate("Enable"))
sr:value("1", translate("Disable"))

server1 =  s:option(Value,"server", translate("Server"),translate("please start with http://"))
server1.datatype ="blackif"


sport1 =  s:option(Value,"sport", translate("Sport"))
sport1.datatype = "port"
blackif1 =  s:option(Value,"blackif", translate("Blackif"),translate("please start with http://"))
blackif1.datatype ="blackif"
intv1 = s:option(Value,"reset_au", translate("reauth time(Min)"), translate("can be 1~1440 minutes!"))
intv1.datatype = "and(uinteger,range(1,1440))"
--authiface = s:option(Value,"authiface", translate("Authiface"))
--authiface.template = "admin_expand/authiface"

linkssid = s:option(Value, "ssid", translate("linkssid"),translate("no more than 10 chinese word while 32 latin letters at most"))
linkssid.datatype = "ssid"

portal =  s:option(Value,"portal", translate("Portal"),translate("please start with http://"))
portal.datatype ="blackif"

sr=s:option(ListValue, "isContent", translate("Enable content"))
sr.rmempty = true
sr:value("1", translate("Enable"))
sr:value("0", translate("Disable"))

portal =  s:option(Value,"contentURL", translate("contentURL"),translate("please start with http://"))
portal.datatype ="blackif"

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

end

return m
