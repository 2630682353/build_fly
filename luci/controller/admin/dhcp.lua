module("luci.controller.admin.dhcp", package.seeall)

function index()
	local page
 
	page = node("admin", "dhcp")
	page.target = firstchild()
	page.title  = _("DHCP")
	page.order  = 52
	page.index  = true

	page = entry({"admin", "dhcp", "server"}, cbi("admin_dhcp/dhcp"),"DHCP Server",1)
	page.leaf = true  

	page = entry({"admin", "dhcp", "lan_lease"}, template("admin_dhcp/lan_lease"),"DHCP  Lease",2)
	page.leaf = true  
--[[
	page = entry({"admin", "dhcp", "wifi_lease"}, template("admin_dhcp/wifi_lease"),"WIFI Lease",3)
	page.leaf = true  
]]--
end
