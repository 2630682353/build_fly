local nt = require "luci.sys".net
local fs = require "nixio.fs"
local has_ac  = fs.access("/etc/config/aconf")

if has_ac then 
m = Map("aconf",
	translate(""))
s = m:section(TypedSection,"remoteac",translate("")) 
s.addremove =  false
s.anonymous = true

sr=s:option(ListValue, "disabled", translate("Enable AC"))
sr.rmempty = true
sr:value("0", translate("Enable"))
sr:value("1", translate("Disable"))

ipaddr =  s:option(Value,"sip", translate("Server IP"))
ipaddr.datatype = "ip4addr"

port =  s:option(Value,"acport", translate("AC Port"))
port.datatype = "port"

gap =  s:option(Value,"gap", translate("Time Interval"),translate("Time Interval, Must be smaller than 10000s"))
gap.datatype = "uinteger"
gap.datatype = "maxlength(5)"

function m.on_before_save()
	if m.uci:get("aconf","normal", "acport")==nil or m.uci:get("aconf","normal", "sip")==nil or m.uci:get("aconf","normal", "gap")==nil then
		m.uci:unload("aconf")
		m.message = translate("Some input is null")
	end
end

function m.on_commit()
	if m.uci:get("aconf","remoteac", "disabled") == "0" then
		luci.sys.call("/etc/init.d/ac_platform start")
	else 
		luci.sys.call("/etc/init.d/ac_platform stop")
	end
end
	end
return m
