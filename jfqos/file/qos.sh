#!/bin/sh /etc/rc.common
START=99

l3dev=eth0.2

qos_init(){
	l3dev=`ifstatus wan | grep l3_device | awk '{print $2}'`
	l3dev=${l3dev#*\"}
	l3dev=${l3dev%\"*}
	iptables -t mangle -N QOSDOWN
	iptables -t mangle -N QOSUP
	iptables -t mangle -I FORWARD -i ${l3dev} -j QOSDOWN
	iptables -t mangle -I FORWARD -o ${l3dev} -j QOSUP

#	ifconfig ifb0 up
	tc qdisc add dev eth0 root handle 1: htb default 999
#	tc qdisc add dev ifb0 root handle 1: htb default 999

#	tc class add dev ifb0 parent 1: classid 1:1 htb rate 1000kbps prio 1
	
	#tc class add dev ifb0 parent 1: classid 1:23 htb rate 150kbps ceil 150kbps prio 7

	#iptables -t mangle -A QOSDOWN -d 192.168.20.120 -j MARK --set-mark 6
	#iptables -t mangle -A QOSDOWN -d 192.168.20.120 -j RETURN
	#tc filter add dev ifb0 parent 1: protocol ip prio 1 handle 7 fw classid 1:23

#	tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match u32 0 0 action mirred egress redirect dev ifb0
}

stop(){
	iptables -t mangle -F QOSDOWN 
	iptables -t mangle -F QOSUP
	iptables -t mangle -D FORWARD -i pppoe-wan -j QOSDOWN
	iptables -t mangle -D FORWARD -o pppoe-wan -j QOSUP
	iptables -t mangle -D FORWARD -i eth0.2 -j QOSDOWN
	iptables -t mangle -D FORWARD -o eth0.2 -j QOSUP
	iptables -t mangle -X QOSDOWN
	iptables -t mangle -X QOSUP
	tc qdisc del dev eth0 root
#	tc qdisc del dev ifb0 root
}

tcclass_num=1

setup_eachip_qos() 
{
	local qos_ip
	local down_speed
	local up_speed
	config_get qos_ip "$1" ipaddr
	config_get down_speed "$1" download
	config_get up_speed "$1" upload

	local str_split="-"
	local range_result=$(echo $qos_ip | grep $str_split)



	if [ $down_speed ]; then
		
		if [ $range_result ]; then
			iptables -t mangle -A QOSDOWN -m iprange --dst-range ${qos_ip} -j MARK --set-mark ${tcclass_num}
			iptables -t mangle -A QOSDOWN -m iprange --dst-range ${qos_ip} -j RETURN
		else
			iptables -t mangle -A QOSDOWN -d ${qos_ip} -j MARK --set-mark ${tcclass_num}
			iptables -t mangle -A QOSDOWN -d ${qos_ip} -j RETURN
		fi
		tc class add dev eth0 parent 1: classid 1:2${tcclass_num} htb rate ${down_speed}kbps
		tc filter add dev eth0 parent 1: protocol ip prio 1 handle ${tcclass_num} fw classid 1:2${tcclass_num}
		tcclass_num=$(($tcclass_num + 1))
	fi

	if [ $up_speed ]; then
		if [ $range_result ]; then
			iptables -t mangle -A QOSUP -m iprange --src-range ${qos_ip} -j MARK --set-mark ${tcclass_num}
			iptables -t mangle -A QOSUP -m iprange --src-range ${qos_ip} -j RETURN
		else
			iptables -t mangle -A QOSUP -d ${qos_ip} -j MARK --set-mark ${tcclass_num}
			iptables -t mangle -A QOSUP -d ${qos_ip} -j RETURN
		fi
		tc class add dev eth0 parent 1: classid 1:2${tcclass_num} htb rate ${up_speed}kbps
		tc filter add dev eth0 parent 1: protocol ip prio 1 handle ${tcclass_num} fw classid 1:2${tcclass_num}
		tcclass_num=$(($tcclass_num + 1))
	fi
}


start()
{
	config_load bandwidth
	config_get enable qos_base enable
	if [ $enable == '1' ]; then
		qos_init
		config_foreach setup_eachip_qos client_ip
	fi
}
