#include <stdio.h>
#include <stdint.h>
#include <libnet.h>
#include <netinet/in.h>
#include "pkt_handler.h"

void print_bytes(const char* message, const uint8_t * p, int len, int print_type, const char* sep){
    // print_type : 0 for hex, 1 for decimal
    // sep : seperator between bytes
    printf("%s", message);
    if(print_type==0){
        for(int i=0;i<len;i++){
            printf("%02x", p[i]);
            if(i < len-1)
                printf("%s", sep);
        }
    }
    else if(print_type==1){
        for(int i=0;i<len;i++){
            printf("%3u", p[i]);
            if(i < len-1)
                printf("%s", sep);
        }
    }
    else{
        printf("invalid print type - 0 : hex, 1 : dec");
    }
    printf("\n");
}

int is_IP(const u_char* pkt){
    const struct libnet_ethernet_hdr* header = \
                (const struct libnet_ethernet_hdr*)pkt;
    if(htons(header->ether_type)==0x800)
        return 1;
    return 0;
}

int is_TCPIP(const u_char* pkt){
    if(is_IP(pkt)){
        const struct libnet_ipv4_hdr* header = \
            (const struct libnet_ipv4_hdr*)(pkt+sizeof(struct libnet_ethernet_hdr));
        if(header->ip_p==0x06)
            return 1;
    }
    return 0;
}

void print_packet_info(const u_char* pkt, int pkt_len){
    const struct libnet_ethernet_hdr* eth_header = \
        (const struct libnet_ethernet_hdr*)pkt;
    const struct libnet_ipv4_hdr* ipv4_header = \
        (const struct libnet_ipv4_hdr*)(pkt+ETHER_HDR_LEN);
    const struct libnet_tcp_hdr* tcp_header = \
        (const struct libnet_tcp_hdr*)(pkt+ETHER_HDR_LEN+IPv4_HDR_LEN);
    u_char* payload = (u_char*)(pkt+TOTAL_HDR_LEN);

    printf("------------\n");
    
    print_bytes("src mac : ", eth_header->ether_shost, 6, 0, ".");
    print_bytes("dst mac : ", eth_header->ether_dhost, 6, 0, ".");

    print_bytes("src ip : ", (uint8_t *)&(ipv4_header->ip_src), 4, 1, ".");
    print_bytes("dst ip : ", (uint8_t *)&(ipv4_header->ip_dst), 4, 1, ".");

    printf("src port : %hu\n", ntohs(tcp_header->th_sport));
    printf("dst port : %hu\n", ntohs(tcp_header->th_dport));

    int len = pkt_len-TOTAL_HDR_LEN;
    if(len==0){
        printf("Payload is empty\n");
        return;
    }
    if(len>16)
        len=16;
    print_bytes("payload : ", payload, len, 0, " ");
}