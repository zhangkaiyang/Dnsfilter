#include "dns_analyze.h"


/************************************************************
    @author: zxj
    @date: 2015/10/26
    @version: 1.0
    @function: 传入ip数据包，返回其中dns响应报文中的域名和ip
************************************************************/
void analyze(struct iphdr* iphdrp,unsigned char *domain,unsigned char *ip){

    /*iphdrp为ip数据包入口地址;(iphdrp->ihl<<2)这部分是用来跳过ip数据包首部占的字节;
    8是用来跳过udp的报文首部，固定为8个字节;获得的地址dns即为dns报文的首地址*/
    unsigned char *dns = (unsigned char *)((u_int8_t*)iphdrp + (iphdrp->ihl<<2) + 8);

    /*dns报文中第6,7个字节为回答的数量，由于需要转化为short类型，首先将高8位他拓展为16位
    这时候低8位为原来数据，所以需左移8位再与原来的低8位相与*/
    short int answerRRs = ((short int)dns[6]<<8) | dns[7];

    /*dns报文的前12个字节*/
    int bitFlags = 12;

    /*dataLength为所CNAME占字节数;count为记录.之前数量的变量*/
    unsigned short dataLength,count = 0;

    int i = 0,j = 0,k = 0; /*一些控制循环的变量*/
    int index = 0; /*控制下标的变量*/

    //获得域名
    while(1)
    {
        /*count为记录.之前数量的变量,占一个字节*/
        count = dns[bitFlags];
        bitFlags += 1;
        for(k = 0;k < count;++ k)
        {
            domain[index ++] = dns[bitFlags ++];
        }

        /*当下一个字节为0x00时说明域名已结束*/
        if(dns[bitFlags] == 0x00)
            break;
        else
            domain[index ++] = '.';
    }
    domain[index] = 0; /*将最后一位置0,字符串结束标志*/
    index = 0;

    bitFlags += 1; /*0x00所占的一个字节*/
    bitFlags += 2; /*跳过类型2个字节*/
    bitFlags += 2; /*跳过class2个字节*/

    /*进入回答对应的地址*/
    while(i < answerRRs)
    {
        bitFlags += 2; /*指向域名的2个字节指针*/
        if (dns[bitFlags] == 0x00 && dns[bitFlags+1] == 0x05) //CNAME
        {
            bitFlags += 8; /*包括标志的2个字节，class的2个字节,ttl的4个字节*/

            /*dataLength为CNAME的长度，获取并跳过*/
            dataLength = ((short int)dns[bitFlags]<<8) | dns[bitFlags+1];
            bitFlags += dataLength;
        }else if(dns[bitFlags] == 0x00 && dns[bitFlags+1] == 0x01) //A
        {
            bitFlags += 10; /*包括标志的2个字节，class的2个字节,ttl的4个字节以及长度的两个字节*/

            /*需要将数字转化为char型，根据几位有不同的处理方法*/
            for(j = 0;j < 4;++ j)
            {
                if(dns[bitFlags] / 100)ip[index ++] = dns[bitFlags] / 100 + 48;
                if(dns[bitFlags] / 100 || dns[bitFlags] / 10 % 10)ip[index ++] = dns[bitFlags] / 10 % 10 + 48;
                ip[index ++] = dns[bitFlags ++] % 10 + 48;
                ip[index ++] = '.';
            }
            ip[index - 1] = 0;
        }
        i += 1;
    }
}