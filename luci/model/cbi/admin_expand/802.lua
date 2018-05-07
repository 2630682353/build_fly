local nt = require "luci.sys".net
local fs = require "nixio.fs"
local has_wa  = fs.access("/etc/config/802cfg")

m2 = Map("802cfg",
	translate(""))
s = m2:section(TypedSection,"802",translate("")) 
s.addremove =  false
s.anonymous = true

sr=s:option(ListValue, "disabled", translate("Enable 802X"))
sr.rmempty = true
sr:value("0", translate("Enable"))
sr:value("1", translate("Disable"))

identity =  s:option(Value,"identity", translate("User Name"))
identity.datatype = "ssid"

password =  s:option(Value,"password", translate("Password"))
password.datatype = "ssid"

iface =  s:option(Value,"iface", translate("Iface"))
iface.datatype = "ssid"

if m2.uci:get("802cfg","normal", "disabled")=='1' then
return m2
end
if m2.uci:get("802cfg","normal", "disabled")=='0' then
m1 = Map("802cfg",
	translate(""))
s1 = m1:section(TypedSection,"802",translate("")) 
s1.addremove =  false
s1.anonymous = true

address = s1:option(Value,"address", translate("Address"))
address.template = "admin_expand/address"

end

function m2.on_before_save()
	if m2.uci:get("802cfg","normal", "password")==nil or m2.uci:get("802cfg","normal", "identity")==nil then
		m2.uci:unload("802cfg")
		m2.message = translate("Some input is null")
	end
end

function m2.on_commit()
	if m2.uci:get("802cfg","normal", "disabled") == "0" then
		luci.sys.call("/etc/init.d/8021X enable")
		luci.sys.call("/etc/init.d/8021X start")
	else 
		luci.sys.call("/etc/init.d/8021X disable")
		luci.sys.call("/etc/init.d/8021X stop")
	end
end
return m1,m2
