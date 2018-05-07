--[[
LuCI - Lua Configuration Interface
  
Copyright 2008 Steven Barth <steven@midlink.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

$Id$
]]--

module("luci.controller.admin.expand", package.seeall)

function index()
	entry({"admin", "expand"}, alias("admin", "expand", "Authentication"), _("Expand"), 35).index = true
	entry({"admin", "expand","Authentication"}, alias("admin", "expand", "Authentication","wxauth"), _("Authentication"), 35).index = true		
	entry({"admin", "expand", "Authentication","wxauth"}, cbi("admin_expand/weixin"), "Authentication",1)
	entry({"admin", "expand", "Authentication","filecache"}, cbi("admin_expand/filecache"),"filecache",2)



	entry({"admin", "expand", "802"}, cbi("admin_expand/802"), "802.1X",2)
	entry({"admin", "expand", "Ac"}, cbi("admin_expand/ac"), "AC",3)
	entry({"admin", "expand", "wifidog"}, cbi("admin_expand/wifidog"), "wifidog",4)
end


