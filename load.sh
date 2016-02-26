#!/bin/bash
#AUTHOR : zxj 787653759@qq.com
#VERSION : 1.0
#CREATED : 2015/6/25

#创建iptables链规则，将dns报文由内核态传入该程序
function create_chain()
{
	echo 'creating chain...'
	sudo iptables -t filter -N NF_QUEUE_CHAIN
	sudo iptables -t filter -A NF_QUEUE_CHAIN -p udp --sport 53 -j NFQUEUE --queue-num 0
	sudo iptables -t filter -I OUTPUT -j NF_QUEUE_CHAIN
	echo 'done'
}

#删除iptables链规则，程序结束时调用
function remove_chain()
{
	echo 'remove chain...'
	sudo iptables -t filter -D OUTPUT -j NF_QUEUE_CHAIN
	sudo iptables -t filter -F NF_QUEUE_CHAIN
	sudo iptables -t filter -X NF_QUEUE_CHAIN
	echo 'done'
}

create_chain
sudo LD_LIBRARY_PATH='/usr/local/lib' ./dnsfilter
remove_chain