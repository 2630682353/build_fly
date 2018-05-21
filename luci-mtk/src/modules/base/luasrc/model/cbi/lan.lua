

m = Map("network",translate("LAN"),translate("局域网配置参数"))
s = m:section(NamedSection,"lan","",translate("LAN")) 
s.addremove =  false
s.anonymous = true


ipaddr =  s:option(Value,"ipaddr", translate("IPv4 address"))
ipaddr.datatype = "ip4addr"
ipaddr.rmempty = false


netmask = s:option(ListValue, "netmask",
	translate("IPv4 netmask"))

netmask.datatype = "ip4addr"
netmask:value("255.255.255.0")
netmask:value("255.255.0.0")
netmask:value("255.0.0.0")


m2 = Map("dhcp",translate("LAN"),translate("局域网配置参数"))
s2 = m2:section(NamedSection,"lan","",translate("DHCP")) 
s2.addremove =  false
s2.anonymous = true

ignore = s2:option(Flag, "ignore",translate("Ignor"))

start = s2:option(Value, "start", "起始地址",
			translate("Lowest leased address as offset from the network address."))
		
		start.datatype = "or(uinteger,ip4addr)"
		start.default = "192.168.1.1"
		start.placeholder = "请输入起始ipv4地址"

limit = s2:option(Value, "limit", translate("Limit"),
			translate("Maximum number of leased addresses."))
	
		limit.datatype = "uinteger"
		limit.default = "150"
		limit.placeholder = "分配的ip数量"

ltime = s2:option(Value, "leasetime", translate("Leasetime"),
			translate("Expiry time of leased addresses, minimum is 2 minutes (<code>2m</code>)."))
		ltime.rmempty = true
		ltime.default = "12h"
		ltime.placeholder = "h(小时)m(分钟) 例:12h"

for i, n in ipairs(s2.children) do
		if n ~= ignore then
			n:depends("ignore", "")
		end
end


return m,m2
