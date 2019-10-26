#ifndef __INTERFACE__
#define __INTERFACE__

#include <string.h>   //strncpy
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>   //ifreq
#include <unistd.h>   //close

void get_mac(char *intf, unsigned char *mac);
void get_ip(char *intf, unsigned char *ip);

#endif 