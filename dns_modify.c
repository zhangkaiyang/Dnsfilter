#include "dns_modify.h"


/************************************************************
  	@author: zxj
  	@date: 2015/10/27
  	@version: 1.0
  	@function: 传入ip数据包和一个ip，替换dns响应报文中的第一个ip回答
************************************************************/
void modify(struct iphdr* iphdrp,unsigned char *ip)
{

    /*iphdrp为ip数据包入口地址;(iphdrp->ihl<<2)这部分是用来跳过ip数据包首部占的字节;
    8是用来跳过udp的报文首部，固定为8个字节;获得的地址dns即为dns报文的首地址*/
    unsigned char *dns = (unsigned char *)((u_int8_t*)iphdrp + (iphdrp->ihl<<2) + 8);

    /*dns报文中第6,7个字节为回答的数量，由于需要转化为short类型，首先将高8位他拓展为16位
    这时候低8位为原来数据，所以需左移8位再与原来的低8位相与*/
    short int answerRRs = ((short int)dns[6]<<8) | dns[7];

    /*dns报文的前12个字节*/
    int bitFlags = 12;

    /*dataLength为所CNAME占字节数;count为记录.之前数量的变量;ans为每一部分的长度*/
    unsigned short dataLength,count = 0,ans = 0;

    /*i,j为循环控制变量，index为下标变量*/
    int i = 0,index = 0,j = 0,length = 0;
    short temp[16];

    /*在ip报文最后添加.用于添加到报文中*/
    length = strlen(ip);
    ip[length ++] = '.';
    ip[length] = 0;

    /*当下一个字节为0x00时说明域名已结束*/
    while(dns[bitFlags] != 0x00)
        bitFlags += 1;
 
    bitFlags += 1; /*跳过0x00的1个字节*/
    bitFlags += 2; /*跳过类型2个字节*/
    bitFlags += 2; /*跳过class2个字节*/

    while(i < answerRRs)
    {
        bitFlags += 2;//指向域名的2个字节指针
        if (dns[bitFlags] == 0x00 && dns[bitFlags+1] == 0x05)//CNAME
        {
            bitFlags += 8; /*包括标志的2个字节，class的2个字节,ttl的4个字节*/

            /*dataLength为CNAME的长度，获取并跳过*/
            dataLength = ((short int)dns[bitFlags]<<8) | dns[bitFlags+1];
            bitFlags += dataLength;
        }else if(dns[bitFlags] == 0x00 && dns[bitFlags+1] == 0x01)//A
        {
            bitFlags += 10; /*包括标志的2个字节，class的2个字节,ttl的4个字节以及长度的两个字节*/

            /*将字符串数组形式的ip地址转化为数字形式*/
            for(j = 0;j < length;++ j)
            {
                if(ip[j] != '.')
                {
                    temp[index ++] = ip[j] - 48;
                    count ++;
                }
                else
                {
                    switch(count)
                    {
                        case 1:ans = temp[index - 1];break;
                        case 2:ans = temp[index - 2] * 10 + temp[index - 1];break;
                        case 3:ans = temp[index - 3] * 100 + temp[index - 2] * 10 + temp[index - 1];break;
                    }
                    dns[bitFlags ++] = ans;
                    count = 0;
                }
            }
            break;
        }
        i += 1;
    }
}