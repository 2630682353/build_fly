--[[
LuCI - Lua Configuration Interface

Copyright 2008 Steven Barth <steven@midlink.org>
Copyright 2011 Jo-Philipp Wich <xm@subsignal.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

$Id$
]]--

require("luci.sys")
require("luci.sys.zoneinfo")
require("luci.tools.webadmin")
require("luci.fs")
require("luci.config")

local nw = require "luci.model.network"
local nt = require "luci.sys".net
local wa = require "luci.tools.webadmin"
local ut = require "luci.util"
local fs = require "nixio.fs"

local m, s, o
local has_ntpd = luci.fs.access("/usr/sbin/ntpd")

m = Map("system", translate(""))
m:chain("luci")


s = m:section(TypedSection, "system", translate(""))
s.anonymous = true
s.addremove = false



--
-- System Properties


o = s:option(DummyValue, "_systime", translate("Local Time"))
o.template = "admin_system/clock_status"

--[[
o = s:taboption("general", Value, "hostname", translate("Hostname"))
o.datatype = "hostname"

function o.write(self, section, value)
	Value.write(self, section, value)
	luci.sys.hostname(value)
end

]]--
o = s:option(ListValue, "zonename", translate("Timezone"))
o:value("Asia/Shanghai")

for i, zone in ipairs(luci.sys.zoneinfo.TZ) do
	o:value(zone[1])
end

function o.write(self, section, value)
	local function lookup_zone(title)
		for _, zone in ipairs(luci.sys.zoneinfo.TZ) do
			if zone[1] == title then return zone[2] end
		end
	end

	AbstractValue.write(self, section, value)
	local timezone = lookup_zone(value) or "GMT0"
	self.map.uci:set("system", section, "timezone", timezone)
	luci.fs.writefile("/etc/TZ", timezone .. "\n")
end

--[[
--
-- Logging
--

o = s:taboption("logging", Value, "log_size", translate("System log buffer size"), "kiB")
o.optional    = true
o.placeholder = 16
o.datatype    = "uinteger"

o = s:taboption("logging", Value, "log_ip", translate("External system log server"))
o.optional    = true
o.placeholder = "0.0.0.0"
o.datatype    = "ip4addr"

o = s:taboption("logging", Value, "log_port", translate("External system log server port"))
o.optional    = true
o.placeholder = 514
o.datatype    = "port"

o = s:taboption("logging", ListValue, "conloglevel", translate("Log output level"))
o:value(8, translate("Debug"))
o:value(7, translate("Info"))
o:value(6, translate("Notice"))
o:value(5, translate("Warning"))
o:value(4, translate("Error"))
o:value(3, translate("Critical"))
o:value(2, translate("Alert"))
o:value(1, translate("Emergency"))

o = s:taboption("logging", ListValue, "cronloglevel", translate("Cron Log Level"))
o.default = 8
o:value(5, translate("Debug"))
o:value(8, translate("Normal"))
o:value(9, translate("Warning"))

]]--
--
-- Langauge & Style
--

o = s:option(ListValue, "_lang", translate("Language"))
o:value("zh_cn",translate("chinese"))

local i18ndir = luci.i18n.i18ndir .. "base."
for k, v in luci.util.kspairs(luci.config.languages) do
	local file = i18ndir .. k:gsub("_", "-")
	if k:sub(1, 1) ~= "." and luci.fs.access(file .. ".lmo") then
		o:value(k, v)
	end
end

function o.cfgvalue(...)
	return m.uci:get("luci", "main", "lang")
end

function o.write(self, section, value)
	m.uci:set("luci", "main", "lang", value)
end

--[[
o = s:taboption("language", ListValue, "_mediaurlbase", translate("Design"))
for k, v in pairs(luci.config.themes) do
	if k:sub(1, 1) ~= "." then
		o:value(v, k)
	end
end

function o.cfgvalue(...)
	return m.uci:get("luci", "main", "mediaurlbase")
end

function o.write(self, section, value)
	m.uci:set("luci", "main", "mediaurlbase", value)
end
]]--
--[[
--
-- NTP
--

if has_ntpd then

	-- timeserver setup was requested, create section and reload page
	if m:formvalue("cbid.system._timeserver._enable") then
		m.uci:section("system", "timeserver", "ntp",
			{
                	server = { "0.openwrt.pool.ntp.org", "1.openwrt.pool.ntp.org", "2.openwrt.pool.ntp.org", "3.openwrt.pool.ntp.org" }
			}
		)

		m.uci:save("system")
		luci.http.redirect(luci.dispatcher.build_url("admin/system", arg[1]))
		return
	end

	local has_section = false
	m.uci:foreach("system", "timeserver", 
		function(s) 
			has_section = true 
			return false
	end)

	if not has_section then

		s = m:section(TypedSection, "timeserver", translate("Time Synchronization"))
		s.anonymous   = true
		s.cfgsections = function() return { "_timeserver" } end

		x = s:option(Button, "_enable")
		x.title      = translate("Time Synchronization is not configured yet.")
		x.inputtitle = translate("Set up Time Synchronization")
		x.inputstyle = "apply"

	else
		
		s = m:section(TypedSection, "timeserver", translate("Time Synchronization"))
		s.anonymous = true
		s.addremove = false

		o = s:option(Flag, "enable", translate("Enable NTP client"))
		o.rmempty = false

		function o.cfgvalue(self)
			return luci.sys.init.enabled("sysntpd")
				and self.enabled or self.disabled
		end

		function o.write(self, section, value)
			if value == self.enabled then
				luci.sys.init.enable("sysntpd")
				luci.sys.call("env -i /etc/init.d/sysntpd start >/dev/null")
			else
				luci.sys.call("env -i /etc/init.d/sysntpd stop >/dev/null")
				luci.sys.init.disable("sysntpd")
			end
		end


		o = s:option(Flag, "enable_server", translate("Provide NTP server"))
		o:depends("enable", "1")


		o = s:option(DynamicList, "server", translate("NTP server candidates"))
		o.datatype = "host"
		o:depends("enable", "1")

		-- retain server list even if disabled
		function o.remove() end

	end
end
]]--
m1 = Map("system", translate(""))
                                                                                 
s = m1:section(TypedSection, "_dummy", "")                                        
s.addremove = false                                                              
s.anonymous = true                                                               
                                                                                 
pw1 = s:option(Value, "pw1", translate("Password"))                              
pw1.password = true                                                              
                                                                                 
pw2 = s:option(Value, "pw2", translate("Confirmation"))                          
pw2.password = true                                                              
                                                                                 
function s.cfgsections()                                                         
        return { "_pass" }                                                       
end                                                    
                                                       
function m1.on_commit(map)                              
        local v1 = pw1:formvalue("_pass")              
        local v2 = pw2:formvalue("_pass")              
                                                       
        if v1 and v2 and #v1 > 0 and #v2 > 0 then      
                if v1 == v2 then                       
                        if luci.sys.user.setpasswd(luci.dispatcher.context.authuser, v1) == 0 then
                                m1.message = translate("Password successfully changed!")           
                        else                                                                      
                                m1.message = translate("Unknown Error, password not changed!")     
                        end                                                                       
                else                                                                              
                        m1.message = translate("Given password confirmation did not match, password not changed!")
                end                                                                                              
        end                                                                                                      
end

if not luci.fs.access("/etc/config/wxserver") then
	return m, m1;
end

m2 = Map("wxserver", translate("")) 
s2 = m2:section(TypedSection, "allowed", translate("")) 
s2.addremove = false
s2.anonymous = true                                                               

ml = s2:option(DynamicList, "maclist", translate("MAC-List allowed")) 
ml.datatype = "macaddr"
nt.mac_hints(function(mac, name) ml:value(mac, "%s (%s)" %{ mac, name }) end)

function m2.on_commit()
	if m2.uci:get("wxserver","wxauth", "disabled") == "0" then                 
		local mact = m2.uci:get("wxserver", "hosts", "maclist")            
		if nil ~= mact then                                                               
			for _, mactx in ipairs(mact) do          
			luci.sys.call("/usr/sbin/wxauth firema %s" %mactx)
			m2.message = translate("Add hosts into trusts: %s" %mactx)
			end 
		end                                   
	end 
end
 
return m,m1,m2
