#ifndef ____INCLUDE_A____
#define ____INCLUDE_A____
#include <unistd.h>
#include <netdb.h>
#include <linux/ip.h>
#include <stdio.h>
#endif
#ifndef ____INCLUDE_STR____
#define ____INCLUDE_STR____
#include <string.h>
#endif

void modify(struct iphdr* iphdrp,unsigned char *ip);