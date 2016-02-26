#ifndef ____INCLUDE_A____
#define ____INCLUDE_A____
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <linux/ip.h>
#endif

void analyze(struct iphdr* iphdrp,unsigned char *domain,unsigned char *ip);