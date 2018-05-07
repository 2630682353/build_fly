module("luci.controller.admin.firewall", package.seeall)

function index()
 
	entry({"admin", "firewall"},
		alias("admin","firewall", "zones"),
		_("Firewall"), 70)

	entry({"admin","firewall", "zones"},
		arcombine(cbi("firewall/zones"), cbi("firewall/zone-details")),
		_("General Settings"), 10).leaf = true

	entry({"admin","firewall", "forwards"},
		arcombine(cbi("firewall/forwards"), cbi("firewall/forward-details")),
		_("Port Forwards"), 20).leaf = true
--[[
	entry({"admin", "firewall", "rules"},
		arcombine(cbi("firewall/rules"), cbi("firewall/rule-details")),
		_("Traffic Rules"), 30).leaf = true

	entry({"admin","firewall", "custom"},
		cbi("firewall/custom"),
		_("Custom Rules"), 40).leaf = true
]]--
end
