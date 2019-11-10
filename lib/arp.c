#include "arp.h"

int dirty_arp_update()
{
    // parse the information from /proc/net/arp
    FILE *arpcache=fopen("/proc/net/arp", "r");
    if(arpcache==NULL){
        perror("Failed to read /proc/net/arp");
        exit(1);
    }
    
    char buff[128];
    fgets(buff, 128, arpcache); // skip the first line
    while(fgets(buff, 128, arpcache)){
        /* Format: 
        IP address | HW type | Flags | HW address | Mask | Device
        */
        
        /* TODO: parsing the information, and store them into arp cache */
    }

    fclose(arpcache);
}

int dirty_get_mac_from_arp(unsigned char *target_ip)
{

}