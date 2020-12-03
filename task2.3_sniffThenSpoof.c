#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "myheader.h"

unsigned short in_cksum (unsigned short *buf, int length);
void send_raw_ip_packet(struct ipheader* ip);


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    if (ip->iph_protocol == IPPROTO_ICMP)
    {
      printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
      printf("         To: %s\n", inet_ntoa(ip->iph_destip));    

      
      char buffer[1500];
      memset(buffer, 0, 1500);

      /*********************************************************
          Step 1: Fill in the ICMP header.
        ********************************************************/
      struct icmpheader *icmp = (struct icmpheader *)
                                (buffer + sizeof(struct ipheader));
      icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.

      // Calculate the checksum for integrity
      icmp->icmp_chksum = 0;
      icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                    sizeof(struct icmpheader));

      /*********************************************************
          Step 2: Fill in the IP header.
        ********************************************************/
      struct ipheader *ip2 = (struct ipheader *) buffer;
      ip2->iph_ver = ip->iph_ver;
      ip2->iph_ihl = ip->iph_ihl;
      ip2->iph_ttl = ip->iph_ttl;
      ip2->iph_sourceip = (ip->iph_destip);
      ip2->iph_destip = (ip->iph_sourceip);
      ip2->iph_protocol = IPPROTO_ICMP;
      ip2->iph_len = htons(sizeof(struct ipheader) +
                          sizeof(struct icmpheader));
      /*********************************************************
          Step 3: Finally, send the spoofed packet
        ********************************************************/
      send_raw_ip_packet (ip);
    }
  }
}

/******************************************************************
  Sniff and then spoof
*******************************************************************/
int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip proto icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
