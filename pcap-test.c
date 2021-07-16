#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <libnet.h> // if <libnet.h> doesn't work, try "libnet-headers.h" located inside current directory
//#include "libnet-headers.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void read_pkt(pcap_t* pcap) {
	pcap_pkthdr* header;
	const u_char* packet;
	int res = pcap_next_ex(pcap, &header, &packet);
	if (res == 0) return;
	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
		exit(-1);
	}

	libnet_ethernet_hdr *eth_hdr = (libnet_ethernet_hdr*) packet;
	printf("src mac: %02x-%02x-%02x-%02x-%02x-%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
	printf("dst mac: %02x-%02x-%02x-%02x-%02x-%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
		libnet_ipv4_hdr *ipv4_hdr = (libnet_ipv4_hdr*) (packet + sizeof(libnet_ethernet_hdr));
		uint32_t src_ipv4 = ipv4_hdr->ip_src.s_addr;
		uint32_t dst_ipv4 = ipv4_hdr->ip_dst.s_addr;
		printf("src ip: %ld.%ld.%ld.%ld\n", (src_ipv4 & 0x00000000FFUL), (src_ipv4 & 0x0000ff00UL)>>8, (src_ipv4 & 0x00ff0000UL)>>16, (src_ipv4 & 0xff000000UL)>>24);
		printf("dst ip: %ld.%ld.%ld.%ld\n", (dst_ipv4 & 0x00000000FFUL), (dst_ipv4 & 0x0000ff00UL)>>8, (dst_ipv4 & 0x00ff0000UL)>>16, (dst_ipv4 & 0xff000000UL)>>24);


		if (ipv4_hdr->ip_p == IPPROTO_TCP) {
			libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr*) (packet + sizeof(libnet_ethernet_hdr) + sizeof(libnet_ipv4_hdr));
			printf("src port: %d\n", ntohs(tcp_hdr->th_sport));
			printf("dst port: %d\n", ntohs(tcp_hdr->th_dport));

			const u_char *payload = (u_char *)(packet + sizeof(libnet_ethernet_hdr) + sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr));
			printf("Payload: 0x");
			for (int i = 0; i<8; i++) {
				printf("%02x", *(payload+i));
			}
			printf("\n");		
			//printf("Payload: 0x%x%x\n", *payload, *(payload+1);
		}
		else
			printf("non-TCP packet\n");
	}
	else
		printf("non-IPv4 packet\n");
	
	printf("(%u bytes captured)\n", header->caplen);
	printf("=========================================\n");
	return;
}



int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		read_pkt(pcap);
	}
	pcap_close(pcap);
}