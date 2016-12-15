/* Global definitions for the port bouncer
 * Packet headers and so on
 */

#define _BSD_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

/* PCAP declarations */
#include <pcap.h>

/* Standard networking declaration */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * The following system include files should provide you with the
 * necessary declarations for Ethernet, IP, and TCP headers
 */

#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

/* Add any other declarations you may need here... */
//#define SIZE_DOMAIN 253 // max size of domain name
//struct pcap_loop_args {
	//u_int sockfd;                       /* Socket file descriptor */
    //u_int server_port;                  /* Server port*/
	//char *listen_ip;                    /* Bouncer address */
	//char *server_ip;                    /* Server address */
//};

u_int sockfd;
u_int listen_port;
u_int server_port;
char *listen_ip;
char *server_ip;
