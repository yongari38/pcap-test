#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <libnet.h>

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

void print_mac(const char* str_hdr, uint8_t *ether_addr) {
	printf("%s%02x-%02x-%02x-%02x-%02x-%02x\n", str_hdr, ether_addr[0], ether_addr[1], ether_addr[2], ether_addr[3], ether_addr[4], ether_addr[5]);
}

void print_ip(const char* str_hdr, uint32_t ip_addr) {
	printf("%s%ld.%ld.%ld.%ld\n", str_hdr, (ip_addr & 0x00000000FFUL), (ip_addr & 0x0000ff00UL)>>8, (ip_addr & 0x00ff0000UL)>>16, (ip_addr & 0xff000000UL)>>24);
}

void print_payload(const u_char *payload, int len) {
	printf("Payload (len = %d): ", len);
	for (int i = 0; i<(len>8 ? 8 : len); i++)
		printf(" %02x", *(payload+i));
	printf("\n");
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

	printf("=========================================\n");
	printf("(%u bytes captured)\n", header->caplen);
	
	libnet_ethernet_hdr *eth_hdr = (libnet_ethernet_hdr*) packet;
	print_mac("src mac: ", eth_hdr->ether_shost);
	print_mac("dst mac: ", eth_hdr->ether_dhost);

	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
		libnet_ipv4_hdr *ipv4_hdr = (libnet_ipv4_hdr*) (packet + sizeof(libnet_ethernet_hdr));
		print_ip("src ip: ", ipv4_hdr->ip_src.s_addr);
		print_ip("dst ip: ", ipv4_hdr->ip_dst.s_addr);

		if (ipv4_hdr->ip_p == IPPROTO_TCP) {
			libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr*) (packet + sizeof(libnet_ethernet_hdr) + sizeof(libnet_ipv4_hdr));
			printf("src port: %d\n", ntohs(tcp_hdr->th_sport));
			printf("dst port: %d\n", ntohs(tcp_hdr->th_dport));

			const u_char *payload = (u_char *)(packet + sizeof(libnet_ethernet_hdr) + sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr));
			int len = ntohs(ipv4_hdr->ip_len) - ipv4_hdr->ip_hl * 4 - sizeof(libnet_tcp_hdr);
			print_payload(payload, len);
		}
		else
			printf(">> non-TCP packet!\n");
	}
	else
		printf(">> non-IPv4 packet!\n");
	
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
	return 0;
}
