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
	entry({"admin", "wan"}, cbi("wan"),_("wan"), 14)
	entry({"admin", "wifi"}, cbi("wifi"),_("wifi"), 16)
	entry({"admin", "qos"}, template("qos"),_("wifi"), 17)
	entry({"admin", "systemSet"}, template("system"),_("systemSet"), 18)
entry({"admin", "test"}, call("test"),_("systemSet"), 50)
entry({"admin", "system","pwd"}, call("pwd"),_("systemPwd"), 51)
entry({"admin", "system","reboot"}, call("reboot"),_("systemReboot"), 51)


	


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
