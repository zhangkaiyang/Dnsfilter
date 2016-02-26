#include "udpcheck.h"


/************************************************************
  	@author: zxj
 	@date: 2015/10/27
  	@version: 1.0
  	@function: 传入ip数据包，将其中的udp报文的校验和设置为0
************************************************************/
void set_udp_checksum(struct iphdr* iphdrp){

    /*找到udp报文的首地址并赋值给udphdr结构*/
    struct udphdr *udphdrp =
        (struct udphdr*)((u_int8_t*)iphdrp + (iphdrp->ihl<<2));
    udphdrp->check = 0;
};
