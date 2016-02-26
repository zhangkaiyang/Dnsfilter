#ifndef ____INCLUDE_A____
#define ____INCLUDE_A____
#include <unistd.h>
#include <netdb.h>
#include <linux/ip.h>
#endif
#ifndef ____INCLUDE_UDP____
#define ____INCLUDE_UDP____
#include <linux/udp.h>
#endif

void set_udp_checksum(struct iphdr* iphdrp);