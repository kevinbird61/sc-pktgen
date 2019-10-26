#ifndef __UTILS__
#define __UTILS__

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef unsigned char u8;

unsigned int ipv4str2hex(char *str);
void filled_eth(u8 *eth,
    u8 b0, u8 b1, u8 b2,
    u8 b3, u8 b4, u8 b5);

#endif 