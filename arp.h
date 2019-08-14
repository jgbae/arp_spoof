#pragma once
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <pcap.h>

#define ARP_PACKET_SIZE 42
#define MAC_ADDR_LEN    6
#define IP_ADDR_LEN     4
#define ARP_REQUEST     0x01
#define ARP_REPLY       0x02
#define SENDER          0
#define TARGET          1

#define ETH_DST         eth_hdr.eth_dst
#define ETH_SRC         eth_hdr.eth_src
#define ETH_TYPE        eth_hdr.eth_type

#define HW_TYPE         arp_hdr.hardwareType
#define PROTOCOL_TYPE   arp_hdr.protocolType
#define HW_ADDR_LEN     arp_hdr.hardAddLen
#define PROTO_ADDR_LEN  arp_hdr.protoAddLen
#define OPCODE          arp_hdr.operationCode

#define DST_IP_ADDR     arp_hdr.dstProtocolAddr
#define SRC_IP_ADDR     arp_hdr.srcProtocolAddr
#define DST_MAC_ADDR    arp_hdr.dstMACAddr
#define SRC_MAC_ADDR    arp_hdr.srcMACAddr


typedef struct _Eth_header
{
    uint8_t eth_dst[6];
    uint8_t eth_src[6];
    uint16_t eth_type;
}Eth_header;


typedef struct _Arp_header
{
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t hardAddLen;
    uint8_t protoAddLen;
    uint16_t operationCode;
    uint8_t srcMACAddr[6];
    uint8_t srcProtocolAddr[4];
    uint8_t dstMACAddr[6];
    uint8_t dstProtocolAddr[4];
} Arp_header;

typedef struct _Ip_hdr
{
    uint8_t ihl:4;
    uint8_t ver:4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t fid;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_addr[4];
    uint8_t dst_addr[4];
}Ip_hdr;

typedef struct _IP_Packet
{
    Eth_header eth_hdr;
    Ip_hdr ip_hdr;
}IP_Packet;

typedef struct _ARP_Packet
{
    Eth_header eth_hdr;
    Arp_header arp_hdr;
}ARP_Packet;

typedef struct _Address_info
{
    char* interface;
    uint8_t senderIp[4];
    uint8_t senderMac[6];
    uint8_t targetIp[4];
    uint8_t targetMac[6];
    uint8_t hostIP[4];
    uint8_t hostMac[6];
} Address_info;

void usage();
int GetSvrMacAddress(Address_info *addressinfo);
void print_mac(const char *msg, uint8_t* mac);
int GetTargetMacAddress(Address_info *addressinfo);
void SetARPPacket(ARP_Packet *packet, uint16_t opcode, Address_info *addressinfo, int isTarget = 0);
void attack(Address_info *addressinfo);
