#include "utils.h"

unsigned int ipv4str2hex(char *str)
{
    char ipstr[32]={0};
    int i=0;
    unsigned char ip[4];
    unsigned int ipv4=0;

    strcpy(ipstr, str);

    char *token=strtok(ipstr, ".");
    while(token!=NULL){
        ip[i++]=atoi(token);
        token=strtok(NULL, ".");
    }

    memcpy(&ipv4, ip, sizeof(unsigned int));
    return ipv4;
}

void filled_eth(u8 *eth,
    u8 b0, u8 b1, u8 b2,
    u8 b3, u8 b4, u8 b5)
{
    *(eth)=b0;
    *(eth+1)=b1;
    *(eth+2)=b2;
    *(eth+3)=b3;
    *(eth+4)=b4;
    *(eth+5)=b5;
}
