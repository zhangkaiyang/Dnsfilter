#ifndef ____INCLUDE_A____
#define ____INCLUDE_A____
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <pthread.h>
#include <sys/types.h> 
#include <sys/ipc.h> 
#include <sys/msg.h>
#endif
#include "udpcheck.h"
#include "dns_analyze.h"
#include "dns_modify.h"

/*最长的文件系统返回的ip串的字节数*/
#define MAX_IP_LENGTH 2048

/************************************************************
    @author: zxj
    @date: 2015/10/26
    @version: 1.0
    @function: 开启多线程实时接受dns报文，对报文进行分析取出域名并与文件
    系统进行交互，执行相应的策略。
************************************************************/

/*线程锁，接受报文时多线程开启锁*/
pthread_mutex_t mut;

/*fpdata为文件指针，当接受到数据包时取出其中的域名和ip存放到该文件*/
FILE *fpdata;

/*用于和文件系统交互的结构体*/
struct my_msg_st
{
    long int my_msg_type;
    char some_text[MAX_IP_LENGTH];
};

/*用于接受和发送的结构体变量*/
struct my_msg_st some_data1, some_data2;
int msgid1, msgid2;

/*消息的发送和接收函数，传入域名，返回ip串*/
char *file_search(char *subdomain)
{
    char ip[MAX_IP_LENGTH];
    message_queue_init();
    some_data1.my_msg_type = 1;
    strcpy(some_data1.some_text, subdomain);
    msgsnd(msgid1, (void *)&some_data1, MAX_IP_LENGTH, 0);
    msgrcv(msgid2, (void *)&some_data2, MAX_IP_LENGTH, 0, 0);
    strcpy(ip, some_data2.some_text);
    message_queue_del();
    return ip;
}

/*消息队列初始化*/
void message_queue_init()
{
     msgid1 = msgget((key_t)1234, 0666|IPC_CREAT);
     msgid2 = msgget((key_t)1235, 0666|IPC_CREAT);
}

/*清空消息队列缓存*/
void message_queue_del()
{
    msgctl(msgid1, IPC_RMID, 0); 
    msgctl(msgid2, IPC_RMID, 0);
}

/*对dns报文中的ip与存储的ip进行匹配*/
int match_ip(unsigned char *ip, unsigned char *ip_file)
{
    int i;
    /*分隔符;*/
    const char *split = ";";
    unsigned char *p, *first_ip;

    first_ip = strtok(ip_file, split);

    /*未找到该域名对应ip时返回“0.0.0.0”*/
    if(strcmp(first_ip, "0.0.0.0") == 0) 
        return 0;
    /*匹配到该ip正确时*/
    while(p = strtok(NULL, split))
    {
        if(strcmp(p, ip) == 0)
            return 0;
    }

    /*修改ip为第一个查找到的ip值*/
    strcpy(ip, first_ip);
    return 1;
}


/*抓包的处理函数，提供给多线程进行调用*/
void *recv_packet(struct nfq_handle *h)
{
    int fd; /*文件标志符*/
    int rv; /*调用recv函数返回的接受到的字节数*/
    struct nfnl_handle *nh; 
    char buf[4096]; 
    nh = nfq_nfnlh(h);
    fd = nfnl_fd(nh);

    /*堵塞接受dns报文*/
    pthread_mutex_lock(&mut);
    rv = recv(fd, buf, sizeof(buf), 0);
    pthread_mutex_unlock(&mut);

    /*循环接受dns报文，并调用处理函数nfq_handle_packet，此函数默认调用cb函数*/
    while (rv >= 0) {
        nfq_handle_packet(h, buf, rv);
        pthread_mutex_lock(&mut);
        rv = recv(fd, buf, sizeof(buf), 0);
        pthread_mutex_unlock(&mut);
    }
} 
/*当使用nfq_handle_packet函数时会调用cb函数，对数据包进行解析及返回verdict*/
int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    int i;
    int flag; /*标记报文中的域名是否在文件系统中*/
    char *temp;
    (void)nfmsg;
    (void)data;
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct iphdr *iphdrp; /*ip数据包的结构*/
    unsigned char *pdata = NULL; 
    int pdata_len;
    unsigned char *domain; 
    unsigned char *ip;
    unsigned char *ip_file;

    flag = 0;

    /*获得ip数据包iphdrp*/
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph)
        id = ntohl(ph->packet_id);
    pdata_len = nfq_get_payload(nfa, (unsigned char**)&pdata);
    if (pdata_len == -1)
        pdata_len = 0;
    iphdrp = (struct iphdr *)pdata;

    domain = malloc(30);
    ip = malloc(16);
    ip_file = malloc(MAX_IP_LENGTH);
    //调用analyze获得dns响应报文中的域名和第一个ip
    analyze(iphdrp, domain, ip);
    fprintf(fpdata, "%s %s\n", domain, ip);
    printf("%s %s\n", domain, ip);
    fflush(fpdata);
    //与文件系统交互获得相应域名的ip信息
    ip_file = file_search(domain);
    //当未找到该域名，或该域名对应的ip不存在时
    flag = match_ip(ip, ip_file);
    if(flag)
    {
        //传入ip将响应报文中的第一个ip替换成该ip
        modify(iphdrp, ip);
        //计算修改后的udp校验和
        set_udp_checksum(iphdrp);
    }   
    return nfq_set_verdict(qh, id, NF_ACCEPT, pdata_len, pdata);
}

int main()
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    const int TNUM = 10; /*运行的线程数量*/
    pthread_t t[TNUM]; 
    int i;
    FILE *fp; /*错误文件的指针*/
    time_t nowtime;
    struct tm *timeinfo;

    fp = fopen("error.log", "a");
    fpdata = fopen("data.log", "a");
    if (!fpdata) {
        time(&nowtime);
        timeinfo = localtime(&nowtime);
        fprintf(fp, "%d-%d-%d %d:%d\terror during open file data.log\n", timeinfo->tm_year+1900
            ,timeinfo->tm_mon+1, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min);
        exit(1);
    }

    /*打开nfq，并绑定协议，捕获ip数据包*/
    h = nfq_open();
    if (!h) {
        time(&nowtime);
        timeinfo = localtime(&nowtime);
        fprintf(fp, "%d-%d-%d %d:%d\terror during nfq_open()\n", timeinfo->tm_year+1900
            ,timeinfo->tm_mon+1, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min);
        exit(1);
    }
    
    /*首先解绑协议簇*/
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        time(&nowtime);
        timeinfo = localtime(&nowtime);
        fprintf(fp, "%d-%d-%d %d:%d\terror during nfq_unbind_pf()\n", timeinfo->tm_year+1900
            ,timeinfo->tm_mon+1, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min);
        exit(1);
    }

    /*绑定AF_INET协议*/
    if (nfq_bind_pf(h, AF_INET) < 0) {
        time(&nowtime);
        timeinfo = localtime(&nowtime);
        fprintf(fp, "%d-%d-%d %d:%d\terror during nfq_bind_pf()\n", timeinfo->tm_year+1900
            ,timeinfo->tm_mon+1, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min);
        exit(1);
    }

    /*创建队列，序号为0,与iptables规则创建时指定的序号一致*/
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if(!qh) {
        time(&nowtime);
        timeinfo = localtime(&nowtime);
        fprintf(fp, "%d-%d-%d %d:%d\terror during nfq_create_queue\n", timeinfo->tm_year+1900
            ,timeinfo->tm_mon+1, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min);
        exit(1);
    }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0){
        time(&nowtime);
        timeinfo = localtime(&nowtime);
        fprintf(fp, "%d-%d-%d %d:%d\terror during nfq_set_mode\n", timeinfo->tm_year+1900
            ,timeinfo->tm_mon+1, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min);
        exit(1);
    }
    
    pthread_mutex_init(&mut,NULL);

    //开启tnum个线程，每个线程调用recv_packet函数，每次使用recv函数时上锁
    for(i = 0;i < TNUM;++ i)
        pthread_create(&t[i], NULL, recv_packet, h);

    for(i = 0;i < TNUM;++ i)
        pthread_join(t[i], NULL);

    /*销毁队列，关闭文件*/
    nfq_destroy_queue(qh);
    nfq_close(h);
    fclose(fp);
    fclose(fpdata);
    return 0;
}
