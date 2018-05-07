--[[
LuCI - Lua Configuration Interface

Copyright 2008 Steven Barth <steven@midlink.org>
Copyright 2011 Jo-Philipp Wich <xm@subsignal.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

]]--

module("luci.controller.admin.quick", package.seeall)

local fs = require "nixio.fs"

function index()
	local uci = require("luci.model.uci").cursor()
	local page

	page = node("admin","quick")
	page.target = firstchild()
	page.title  = _("Quickly  Setting")
	page.order  = 47
	page.index  = true

	page = entry({"admin","quick", "wifi_quick"}, cbi("admin_quick/wifi_quick"),"WIFI",3)
	page.leaf = true  
	
	page = entry({"admin","quick", "lan_quick"}, arcombine(cbi("admin_quick/network"), cbi("admin_quick/ifaces")),"LAN",1)
	page.leaf = true  

	page = entry({"admin","quick", "lan_info"}, call("lan_info"),nil)
	page.leaf = true  

	page = entry({"admin","quick", "wan_quick"}, arcombine(cbi("admin_quick/network1"), cbi("admin_quick/ifaces")),"WAN",2)
	page.leaf = true  
end

function lan_info(ifaces)
	local netm = require "luci.model.network".init()
	local rv   = { }

	local iface
	for iface in ifaces:gmatch("[%w%.%-_]+") do
		local net = netm:get_network(iface)
		local device = net and net:get_interface()
		if device then
			local data = {
				id         = iface,
				macaddr    = device:mac(),
				ipaddrs    = { }
			}

			local _, a
			for _, a in ipairs(device:ipaddrs()) do
				data.ipaddrs[#data.ipaddrs+1] = {
					addr      = a:host():string(),
					netmask   = a:mask():string(),
					prefix    = a:prefix()
				}
			end
			rv[#rv+1] = data
		end
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(rv)
	return
end
