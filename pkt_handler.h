#pragma once
#include <stdio.h>
#include <stdint.h>
#include <libnet.h>
#include <netinet/in.h>

#define ETHER_HDR_LEN 14 // sizeof(libnet_ethernet_hdr)
#define IPv4_HDR_LEN 20 // sizeof(libnet_ipv4_hdr)
#define TCP_HDR_LEN 20 // sizeof(libnet_tcp_hdr)
#define TOTAL_HDR_LEN 54 //ETHER_HDR_LEN + IPv4_HDR_LEN + TCP_HDR_LEN

void print_bytes(const uint8_t * p, int size);
int is_IP(const u_char* pkt);
int is_TCPIP(const u_char* pkt);
void print_packet_info(const u_char* pkt, int pkt_len);