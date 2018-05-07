--[[
LuCI - Lua Configuration Interface

Copyright 2008 Steven Barth <steven@midlink.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

$Id$
]]--

module("luci.controller.admin.index", package.seeall)


function index()
	local root = node()
	if not root.target then
		root.target = alias("admin")
		root.index = true
	end

	local page   = node("admin")
	page.target  = firstchild()
	page.title   = _("Administration")
	page.order   = 10
	page.sysauth = "root"
	page.sysauth_authenticator = "htmlauth"
	page.ucidata = true
	page.index = true
	entry({"admin", "statuss"}, template("statuss"), _("statuss"), 13).index = true
	entry({"admin", "lan"}, cbi("lan"),_("lan"), 15)
	entry({"admin", "lanv"}, template("lanv"),_("lanv"), 19)
	entry({"admin", "port_link"}, call("port_link"),_("port_link"), 20)
	entry({"admin", "wan"}, cbi("wan"),_("wan"), 14)
	entry({"admin", "wifi"}, cbi("wifi"),_("wifi"), 16)
	entry({"admin", "qos"}, template("qos"),_("wifi"), 17)
	entry({"admin", "systemSet"}, template("system"),_("systemSet"), 18)
entry({"admin", "test"}, call("test"),_("systemSet"), 50)
entry({"admin", "system","pwd"}, call("pwd"),_("systemPwd"), 51)
entry({"admin", "system","reboot"}, call("reboot"),_("systemReboot"), 51)
entry({"admin", "system","reset"}, call("reset"),_("systemReset"), 51)
entry({"admin", "network","lanv"}, call("lanv"),_("lanv"), 53)

	


	-- Empty services menu to be populated by addons
	entry({"admin", "services"}, firstchild(), _("Services"), 40).index = true

	entry({"admin", "logout"}, call("action_logout"), _("Logout"), 90)
end

function action_logout()
	local dsp = require "luci.dispatcher"
	local sauth = require "luci.sauth"
	if dsp.context.authsession then
		sauth.kill(dsp.context.authsession)
		dsp.context.urltoken.stok = nil
	end

	luci.http.header("Set-Cookie", "sysauth=; path=" .. dsp.build_url())
	luci.http.redirect(luci.dispatcher.build_url())
end


function test()
	require "luci.fs"
	local nw = require "luci.model.network"
	nw.init()
	local wnet = nw:get_wifinet("wlan0")
	local uci = require "luci.model.uci".cursor()
	local ssid=luci.http.formvalue("test")
	if ssid then

		uci:set("wireless",wnet.sid,"ssid",ssid)
		uci:commit("wireless")
		uci:apply("wireless",false)
--[[
		for _,k in pairs(s) do
		luci.http.write(k)
		luci.http.write('\n')
		end

		local rv={test1=1,test2=2,test3=3}
		luci.http.prepare_content("application/json")
]]--
		luci.http.write(ssid)
	end

end

function pwd()
	local pwd1=luci.http.formvalue("pwd1")
	local pwd2=luci.http.formvalue("pwd2")
	if pwd1 or pwd2 then
		if pwd1 == pwd2 then
			if(luci.sys.user.setpasswd("root", pwd1)==0) then
			luci.http.write("密码已经修改")
			else
			luci.http.write("未知错误")
			end
		else
			luci.http.write("密码不一致")
			
		end
	end

end
function reboot()
	local reboot=luci.http.formvalue("reboot")

	if reboot then
		luci.sys.reboot()
	end

end

function fork_exec(command)
	local pid = nixio.fork()
	if pid > 0 then
		return
	elseif pid == 0 then
		-- change to root dir
		nixio.chdir("/")

		-- patch stdin, out, err to /dev/null
		local null = nixio.open("/dev/null", "w+")
		if null then
			nixio.dup(null, nixio.stderr)
			nixio.dup(null, nixio.stdout)
			nixio.dup(null, nixio.stdin)
			if null:fileno() > 2 then
				null:close()
			end
		end

		-- replace with target command
		nixio.exec("/bin/sh", "-c", command)
	end
end

function reset()
	local reset_avail   = os.execute([[grep '"rootfs_data"' /proc/mtd >/dev/null 2>&1]]) == 0
	local reset=luci.http.formvalue("reset")

	if reset_avail and reset then
		luci.http.write("系统正在擦除配置分区，完成后将自动重启，新地址：192.168.1.1")
		fork_exec("killall dropbear uhttpd; sleep 1; mtd -r erase rootfs_data")
	else
		luci.http.write("执行错误")
	end

end

function port_link()
	local port = {}
	port[0] = luci.sys.exec("switch reg r 0x3008")
	port[1] = luci.sys.exec("switch reg r 0x3108")
	port[2] = luci.sys.exec("switch reg r 0x3208")
	port[3] = luci.sys.exec("switch reg r 0x3308")
	port[4] = luci.sys.exec("switch reg r 0x3408")
	local portmap = {}

	for i=0,4,1 do
		local f = string.sub(port[i], #port[i]-1, #port[i]-1)
		local num = tonumber(f, 16)

		if num%2==1 then
			portmap["port"..i] = 1
		else 
			portmap["port"..i] = 0
		end
	end
	
	luci.http.prepare_content("application/json")
	luci.http.write_json(portmap)

end

function lanv()
	local uci = require "luci.model.uci".cursor()
	local v1_ports=luci.http.formvalue("v1_ports")
	local v3_ports=luci.http.formvalue("v3_ports")
	local v4_ports=luci.http.formvalue("v4_ports")
	local v5_ports=luci.http.formvalue("v5_ports")
	uci:delete_all("network", "switch_vlan")
	uci:delete("network", "V3")
	uci:delete("network", "V4")
	uci:delete("network", "V5")
	uci:delete_all("dhcp", "dhcp", {interface='V3'})
	uci:delete_all("dhcp", "dhcp", {interface='V4'})
	uci:delete_all("dhcp", "dhcp", {interface='V5'})
	local fire_zone="lan";

	if v1_ports ~= '' then
		local v1_table = {device='mt762x',vlan='1',ports=v1_ports}
		uci:section("network", "switch_vlan", nil,v1_table)
	end

	local v2_table = {device='mt762x',vlan='2',ports="4"}
	uci:section("network", "switch_vlan", nil,v2_table)

	if v3_ports ~= '' then
		local v3_table = {device='mt762x',vlan='3',ports=v3_ports}
		uci:section("network", "switch_vlan", nil,v3_table)
		local v3_interface = {proto='static', ifname='eth0.3', netmask=luci.http.formvalue("v3_netmask"),
								ipaddr=luci.http.formvalue('v3_ipaddr'),gateway=luci.http.formvalue("v3_ipaddr")}
		uci:section("network", "interface", "V3", v3_interface)
		local v3_dhcp_ignore = luci.http.formvalue('v3_dhcp_ignore')
		if v3_dhcp_ignore ~= "1" then
			local v3_dhcp = {start=luci.http.formvalue('v3_start'),leasetime=luci.http.formvalue('v3_leasetime'),
								limit=luci.http.formvalue('v3_limit'), interface='V3'}
			uci:section("dhcp", "dhcp", nil, v3_dhcp)
		end
		fire_zone=fire_zone.." V3"
	end

	if v4_ports ~= '' then
		local v4_table = {device='mt762x',vlan='4',ports=v4_ports}
		uci:section("network", "switch_vlan", nil,v4_table)
		local v4_interface = {proto='static', ifname='eth0.4', netmask=luci.http.formvalue("v4_netmask"),
								ipaddr=luci.http.formvalue('v4_ipaddr'),gateway=luci.http.formvalue("v4_ipaddr")}
		uci:section("network", "interface", "V4", v4_interface)
		local v4_dhcp_ignore = luci.http.formvalue('v4_dhcp_ignore')
		if v4_dhcp_ignore ~= "1" then
			local v4_dhcp = {start=luci.http.formvalue('v4_start'),leasetime=luci.http.formvalue('v4_leasetime'),
								limit=luci.http.formvalue('v4_limit'), interface='V4'}
			uci:section("dhcp", "dhcp", nil, v4_dhcp)
		end
		fire_zone=fire_zone.." V4"
	end

	if v5_ports ~= '' then
		local v5_table = {device='mt762x',vlan='5',ports=v5_ports}
		uci:section("network", "switch_vlan", nil,v5_table)
		local v5_interface = {proto='static', ifname='eth0.5', netmask=luci.http.formvalue("v5_netmask"),
								ipaddr=luci.http.formvalue('v5_ipaddr'),gateway=luci.http.formvalue("v5_ipaddr")}
		uci:section("network", "interface", "V5", v5_interface)
		local v5_dhcp_ignore = luci.http.formvalue('v5_dhcp_ignore')
		if v5_dhcp_ignore ~= "1" then
			local v5_dhcp = {start=luci.http.formvalue('v5_start'),leasetime=luci.http.formvalue('v5_leasetime'),
								limit=luci.http.formvalue('v5_limit'), interface='V5'}
			uci:section("dhcp", "dhcp", nil, v5_dhcp)
		end
		fire_zone=fire_zone.." V5"
	end
	uci:commit("network")
	uci:commit("dhcp")
	uci:foreach("firewall", "zone",
				function(s)
					if s.name == 'lan' then
						uci:set("firewall", s['.name'], "network", fire_zone)
					end
				end)
	uci:commit("firewall")

	local res_json = {}
	res_json["v1_ports"] = v1_ports
	res_json["v3_ports"] = v3_ports
	res_json["code"] = 0
	luci.http.write_json(res_json);
	return

end
