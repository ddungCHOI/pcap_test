#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    ether_header* eh;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    eh = (ether_header *) packet;

    printf("%u bytes captured\n", header->caplen);
    printf("Destination MAC : ");
    for (int i=0; i < 6; i++)
         printf("%02X%c", eh->ether_dhost[i], i<5?':':'\n');

    printf("Source MAC : ");
    for (int i=0; i < 6; i++)
         printf("%02X%c", eh->ether_shost[i], i<5?':':'\n');

    if(ntohs(eh->ether_type) == ETH_P_IP){
        iphdr* iph = (iphdr *)(packet + sizeof(ether_header));
        printf("IP\n");
        printf("Source address: %s\n", inet_ntoa(*(in_addr *)&iph->saddr));
        printf("Destination address: %s\n", inet_ntoa(*(in_addr *)&iph->daddr));

        if(iph->protocol == IPPROTO_TCP){
            tcphdr* tcph = (tcphdr *)(packet + sizeof(ether_header) + (iph->ihl << 2));
            printf("TCP\n");
            printf("Source port: %d\n", ntohs(tcph->th_sport));
            printf("Destination port: %d\n", ntohs(tcph->th_dport));
            const u_char* data = packet + ETH_HLEN + (iph->ihl << 2) + (tcph->doff << 2);
            int data_size = htons(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
            printf("Data size : %d\n", data_size);
            if(data_size > 0){
                printf("------ data contents -----\n");
                for(int i=0; i< 10; i++)
                    printf("%02x ", data[i-1]);
                printf("\n");
            }
        }
        else {
            printf("Not TCP (ICMP.... UDP....)\n");
        }
    }
    else{
      printf("Not IPv4 (IPv6....ARP....)\n");
    }
    printf("==================================================\n");
  }

  pcap_close(handle);
  return 0;
}
