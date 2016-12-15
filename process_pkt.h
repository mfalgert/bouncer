#include "bouncer.h"
#include "node.c"

#define SIZE_ETHERNET 14
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
#define IP_HL(ip)			(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)			(((ip)->ip_vhl) >> 4)
#define ICMP_HEADER_SIZE 40
#define ICMP_ECHO_REQUEST_TYPE 8
#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_ECHO_REQUEST_CODE 0
#define ICMP_ECHO_REPLY_CODE 0
#define TH_OFF(th)			(((th)->th_offx2 & 0xf0) >> 4)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

/* Ethernet header */
struct eth_hdr {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_hdr {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    u_int ip_src;
    u_int ip_dst;       /* source and dest address */
};

/* ICMP */
struct icmp_hdr{
    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
    u_int16_t id;
    u_int16_t seq;
};

/* TCP header */
typedef u_int tcp_seq;

struct tcp_hdr {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
    u_char th_flags;
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

/* Function that checks the validates the IP header
   Returns true if header OK, false otherwise */
bool check_ip_hdr(struct ip_hdr *ip, int size_ip_hdr);
bool check_icmp_hdr(struct icmp_hdr *icmp, int size_icmp);
bool check_tcp_hdr(struct tcp_hdr *tcp);
uint16_t ip_checksum(void* vdata,size_t length);
