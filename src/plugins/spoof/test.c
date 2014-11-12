#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/in.h>

void C(int status, const char *message) {
	if (status == -1) {
		fprintf(stderr, "%s: %s\n", message, strerror(errno));
		exit(1);
	}
}

struct pack {
	struct ethhdr hdr;
	struct iphdr iphdr;
	struct udp {
		uint16_t sport;
		uint16_t dport;
		uint16_t len;
		uint16_t check;
	} udp;
	uint32_t data;
} __attribute__((packed));

#define DEST_MAC { 0x28, 0x92, 0x4a, 0xca, 0xee, 0x35 }

int main(int argc, char *argv[]) {
	int sock = socket(AF_PACKET, SOCK_RAW, htons(0x0800));
	C(sock, "Bad socket");
	struct ifreq req;
	strcpy(req.ifr_name, "eth0");
	C(ioctl(sock, SIOCGIFINDEX, &req), "Get index");
	int ifindex = req.ifr_ifindex;
	printf("IF index is %d\n", ifindex);
	C(ioctl(sock, SIOCGIFHWADDR, &req), "Get MAC");
	uint8_t mac[ETH_ALEN];
	memcpy(mac, req.ifr_hwaddr.sa_data, ETH_ALEN);
	struct sockaddr_ll addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(0x0800),
		.sll_ifindex = ifindex
	};
	C(bind(sock, (struct sockaddr *)&addr, sizeof addr), "Bind");
	struct pack packet = {
		.hdr = {
			.h_dest = DEST_MAC,
			.h_proto = htons(0x0800)
		},
		.iphdr = {
			.version = 4,
			.ihl = 5,
			.ttl = 64,
			.protocol = IPPROTO_UDP,
			.saddr = htonl(0x01020304),
			.daddr = htonl(0x05060708)
		},
		.udp = {
			.sport = htons(5678),
			.dport = htons(5678),
			.len = htons(sizeof(struct udp) + 4)
		},
		.data = htonl(0x01020304)
	};
	memcpy(packet.hdr.h_source, mac, ETH_ALEN);
	C(sendto(sock, &packet, sizeof packet, MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof addr), "Sendto");
	return 0;
}
