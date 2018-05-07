--[[
LuCI - Lua Configuration Interface

Copyright 2011 Jo-Philipp Wich <xm@subsignal.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0
]]--

local map, section, net = ...

local username, password, ac, service
local ipv6, defaultroute, metric, peerdns, dns,
      keepalive_failure, keepalive_interval, demand, mtu


username = section:taboption("general", Value, "username", translate("PAP/CHAP username"))


password = section:taboption("general", Value, "password", translate("PAP/CHAP password"))
password.password = true


ac = section:taboption("general", Value, "ac",
	translate("Access Concentrator"),
	translate("Leave empty to autodetect"))

ac.placeholder = translate("auto")


service = section:taboption("general", Value, "service",
	translate("Service Name"),
	translate("Leave empty to autodetect"))

service.placeholder = translate("auto")


