/* using ARP mechanism to get information of peering device */
#ifndef __ARP__
#define __ARP__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#define ARP_TABLE_SIZE      16 
#define ARP_TIMEOUT         30000
#define ARP_RES_TIME	    250		/* 2.5 seconds			*/
#define ARP_MAX_TRIES	    3		/* max # of tries to send ARP	*/
#define ARP_QUEUE_MAGIC	    0x0432447A	/* magic # for queues		*/

/* ARP mapping table */
struct arp_table {
    struct arp_table        *next;
    volatile unsigned long  last_used;
    unsigned int            flags;
    // ip
    unsigned char           ip[4];      /* A.B.C.D */
    unsigned char           ip_len;
    unsigned char           ip_type;
    // MAC
    unsigned char           mac[6];     /* A.B.C.D.E.F */
    unsigned char           mac_len;
    unsigned char           mac_type;
};

/* ARP header */
typedef struct arp_header_t {
    u16     htype;              // hardware type
    u16     ptype;              // protocol type (IP)
    u8      h_addr_len;
    u8      p_addr_len;
    u16     opcode;
    u8      smac[6];
    u32     sip;
    u8      dmac[6];
    u32     dip;
} arp_t;


/* ARP table */
struct arp_table dirty_table[ARP_TABLE_SIZE];   // for dirty way
struct arp_table *arp_cache;                    // for hard way

/* 1) dirty way - parse the information from "/proc/net/arp".
    Using dirty_table to maintain the ARP cache
*/
int dirty_arp_update(); 
int dirty_get_mac_from_arp(unsigned char *target_ip);

/* 2) hard way - implement arp request/reply to fetch MAC address */

#endif