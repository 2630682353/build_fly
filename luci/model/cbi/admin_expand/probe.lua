
local nt = require "luci.sys".net
local fs = require "nixio.fs"
local has_scan  = fs.access("/etc/config/cscan")
	arg[1] = "radio0"
local iw = luci.sys.wifi.getiwinfo(arg[1])


if has_scan then 
m = Map("cscan", translate(""))
s = m:section(TypedSection,"interface",translate("")) 
s.addremove =  false
s.anonymous = true

sr=s:option(ListValue, "disabled", translate("Enable Probe"))
sr.rmempty = true
sr:value("0", translate("Enable"))
sr:value("1", translate("Disable"))
name = s:option(Value,"ifname", translate("Ifacename"))		

ipaddr =  s:option(Value,"sip", translate("Server IP"))
ipaddr.datatype = "ip4addr"

port =  s:option(Value,"sport", translate("Server Port"))
port.datatype = "port"

mode=s:option(ListValue, "mode", translate("Mode"))
mode.rmempty = true
mode:value("1", translate("sigle channel"))
mode:value("2", translate("mixed channel"))

ch = s:option( Value, "channel", translate("Channel"))
ch:depends({mode ="1"})
ch:value("auto", translate("auto"))
local i = 0
for _, f in ipairs(iw and iw.freqlist or { }) do
	if i < 11 then 
		if not f.restricted then
			ch:value(f.channel, "%i (%.3f GHz)" %{ f.channel, f.mhz / 1000 })
		end
	end
	i = i+1
end

function m.on_before_save()
	if m.uci:get("cscan","scan", "ifname")==nil or m.uci:get("cscan","scan", "sip")==nil or m.uci:get("cscan","scan", "sport")==nil then
		m.uci:unload("cscan")
		m.message = translate("Some input is null")
	end
end
function m.on_commit()
	if m.uci:get("cscan","scan", "disabled") == "0" then
		luci.sys.call("/etc/init.d/sicnu_probe start")
	else 
		luci.sys.call("/etc/init.d/sicnu_probe stop")
	end
end
end
return m

