

m = Map("network",translate("WAN"),translate("局域网配置参数"))
s = m:section(NamedSection,"wan","",translate("WAN")) 
s.addremove =  false
s.anonymous = true


wanprotocol =s:option(ListValue,"proto","协议")
wanprotocol.widget = "radio"

wanprotocol:value("dhcp")
wanprotocol:value("static")
wanprotocol:value("pppoe")
wanprotocol.orientation="horizontal"

username = s:option(Value, "username", translate("PAP/CHAP username"))
		username:depends("proto", "pppoe")

password = s:option(Value, "password", translate("PAP/CHAP password"))
password.password = true
password:depends("proto", "pppoe")


ipaddr = s:option(Value, "ipaddr", translate("IPv4 address"))
ipaddr.datatype = "ip4addr"
ipaddr:depends("proto", "static");


netmask = s:option(ListValue, "netmask",
	translate("IPv4 netmask"))

netmask.datatype = "ip4addr"
netmask:value("255.255.255.0")
netmask:value("255.255.0.0")
netmask:value("255.0.0.0")
netmask:depends("proto", "static")


gateway = s:option(Value, "gateway", translate("IPv4 gateway"))
gateway.datatype = "ip4addr"
gateway:depends("proto", "static")



return m
