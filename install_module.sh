#!/bin/bash
#AUTHOR : zxj 787653759@qq.com
#VERSION : 1.0
#CREATED : 2015/7/25

function install_module()
{
	cd $1
	./configure
	make
	sudo make install
	cd ..
}

install_module libmnl-20150623
install_module libnfnetlink-20150623
install_module libnetfilter_queue-20150623