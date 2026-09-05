// WARNING!
// DON'T LAUNCH THIS CODE ON YOUR COMPUTER WITH VALORANT OR VANGUARD
// VANGUARD MAY CONSIDER THIS PROGRAM AS CHEAT
// AND YOU MAY BE BANNED


#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "windivert.h"

#define _htons(x) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))
#define _ntohl(x) ((((x) >> 24) & 0xff) | (((x) >> 8) & 0xff00) | (((x) & 0xff00) << 8) | (((x) & 0xff) << 24))
#define _htonl(x) _ntohl(x)

typedef struct {
    unsigned char  version_ihl;
    unsigned char  tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short check;
    unsigned int   saddr;
    unsigned int   daddr;
} IP_HDR;

typedef struct {
    unsigned short sport;
    unsigned short dport;
    unsigned int   seq;
    unsigned int   ack;
    unsigned char  off_res;
    unsigned char  flags;
    unsigned short win;
    unsigned short check;
    unsigned short urg_ptr;
} TCP_HDR;

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    
    const char *filter = "outbound and tcp and tcp.DstPort == 443 and tcp.PayloadLength > 150";

    HANDLE handle;
    INT16 priority = 0;
    
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, 1);
    if (handle == INVALID_HANDLE_VALUE) {
        printf("Failed to launch WinDivert. Try start as admin. Error: %d\n", GetLastError());
        return 1;
    }

    WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
    WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 8000); 
    WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_SIZE, 33554432); 

    printf("[WinDivert] Successfully started!\n");

    unsigned char packet[0xFFFF];
    unsigned char packet2[0xFFFF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;

    while (TRUE) {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr)) {
            continue; 
        }

        IP_HDR *ip = (IP_HDR *)packet;
        int ip_header_len = (ip->version_ihl & 0x0F) * 4;
        TCP_HDR *tcp = (TCP_HDR *)(packet + ip_header_len);
        int tcp_header_len = ((tcp->off_res & 0xF0) >> 4) * 4;

        int payload_len = packet_len - ip_header_len - tcp_header_len;

        if (payload_len <= 150) {
            WinDivertSend(handle, packet, packet_len, NULL, &addr);
            continue;
        }

        int split_pos = 1; 
        int payload2_len = payload_len - split_pos;

        memcpy(packet2, packet, ip_header_len + tcp_header_len);
        IP_HDR *ip2 = (IP_HDR *)packet2;
        TCP_HDR *tcp2 = (TCP_HDR *)(packet2 + ip_header_len);

        unsigned char *payload1_start = packet + ip_header_len + tcp_header_len;
        unsigned char *payload2_start = packet2 + ip_header_len + tcp_header_len;
        memcpy(payload2_start, payload1_start + split_pos, payload2_len);

        int packet2_len = ip_header_len + tcp_header_len + payload2_len;
        ip2->tot_len = _htons(packet2_len);
        tcp2->seq = _htonl(_ntohl(tcp->seq) + split_pos);
        tcp2->flags = tcp->flags; 

        int packet1_len = ip_header_len + tcp_header_len + split_pos;
        ip->tot_len = _htons(packet1_len);
        tcp->flags &= ~0x09; 

        WinDivertHelperCalcChecksums(packet, packet1_len, &addr, 0);
        WinDivertHelperCalcChecksums(packet2, packet2_len, &addr, 0);

        WinDivertSend(handle, packet, packet1_len, NULL, &addr);
        WinDivertSend(handle, packet2, packet2_len, NULL, &addr);
    }

    WinDivertClose(handle);
    return 0;
}
