#include "process_pkt.h"
// http://www.binarytides.com/raw-sockets-c-code-linux/

void process_pkt(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet){

    /*********************** Define pointers for packet's attributes ***********************/
	struct ip_hdr *ip;                      /* The IP header */
	struct tcp_hdr *tcp;                    /* The TCP header */
	struct icmp_hdr *icmp;                    /* The TCP header */
	u_char *payload;                            /* Packet payload */

    int size_tcp;   // todo initialize in case of tcp
    int size_ip_hdr;
    int size_icmp;

	ip = (struct ip_hdr*)(packet + SIZE_ETHERNET);
    size_ip_hdr = IP_HL(ip)*4;

	/* Check IP header*/
    if (!check_ip_hdr(ip, size_ip_hdr)){
        return; // drop packet
    }

	/********************** Check type of packet and process **********************/
    /* Check ICMP header*/
    if(ip->ip_p == IPPROTO_ICMP){
        icmp = (struct icmp_hdr*)(packet + SIZE_ETHERNET + size_ip_hdr);
        size_icmp = ntohs(ip->ip_len) - size_ip_hdr;
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip_hdr);
        if (!check_icmp_hdr(icmp, size_icmp)){
            return; // drop packet
        }
        // add node
        if(icmp->type == ICMP_ECHO_REQUEST_TYPE){
            if(icmp->code == ICMP_ECHO_REQUEST_CODE){
                addNode(inet_ntoa(*(struct in_addr*)&ip->ip_src), icmp->id, icmp->seq);
            }
        }
    }
    /* Check TCP header*/
    else if(ip->ip_p == IPPROTO_TCP){
        tcp = (struct tcp_hdr*)(packet + SIZE_ETHERNET + size_ip_hdr);
        size_tcp = TH_OFF(tcp)*4;
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip_hdr + size_tcp);
        if (!check_tcp_hdr(tcp)){
            return; // drop packet
        }
    }
    /* Drop packet*/
    else{
		printf("Invalid protocol (no icmp/tcp)\n");
		return;
	}

	/********************** Send processed packet **********************/
    printf("List size: %d\n", getSize());

    char *dst_ip;
    char *src_ip = listen_ip;
	int reply = 0;

	if(ip->ip_p == IPPROTO_ICMP){
		if(icmp->type == ICMP_ECHO_REPLY_TYPE && icmp->code == ICMP_ECHO_REPLY_CODE){
			if(getSize() > 0){
				struct Node *client = getNode(icmp->id, icmp->seq);
				printf("after getnode\n");
				if(client == (struct Node*)-1){
					return;
				}
				dst_ip = client->ip;
				reply = 1;
			}
		}
		else if(icmp->type == ICMP_ECHO_REQUEST_TYPE && icmp->code == ICMP_ECHO_REQUEST_CODE){
			dst_ip = server_ip;
		}
		else{
			 printf("ICMP message is not an echo or a reply\n");
		}
	}

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr (dst_ip);

    char new_ip_packet[1500];
    struct ip_hdr *new_ip_header = (struct ip_hdr *) new_ip_packet;
    new_ip_header->ip_vhl = ip->ip_vhl;
    new_ip_header->ip_tos = ip->ip_tos;
    new_ip_header->ip_len = ip->ip_len;
    new_ip_header->ip_id = ip->ip_id;
    new_ip_header->ip_off = ip->ip_off;
    new_ip_header->ip_ttl = ip->ip_ttl;
    new_ip_header->ip_p = ip->ip_p;
    new_ip_header->ip_sum = 0; // checksum should be 0 when calculating the new one
    new_ip_header->ip_src = inet_addr(src_ip);
    new_ip_header->ip_dst = inet_addr(dst_ip);
    new_ip_header->ip_sum = (u_short) ip_checksum(new_ip_header, size_ip_hdr);

    size_t packet_size = ntohs(new_ip_header->ip_len);
    size_t payload_size = packet_size - size_ip_hdr;
    char *new_packet = malloc(packet_size);
    memcpy(new_packet, new_ip_header, size_ip_hdr); // copy header
    memcpy(new_packet + size_ip_hdr, payload, payload_size); // copy payload
	
	printf("srcip: %s\n", src_ip);
	printf("dstip: %s\n", dst_ip);

    errno = 0;
    if (sendto(sockfd, new_packet, packet_size, 0, (struct sockaddr *) &addr, sizeof(addr))==-1) {
        printf("Failed to send message: %s\n",strerror(errno));
        return;
    }
	if(reply == 1){
		printf("ECHO REPLY\n");
		removeNode(icmp->id, icmp->seq);
	}
	else{
		printf("ECHO REQUEST\n");
	}
	printf("-----\n");
}

bool check_ip_hdr(struct ip_hdr *ip, int size_ip_hdr){
	if (size_ip_hdr < 20) {
		printf("Invalid IP header length: %u bytes\n", size_ip_hdr);
		return false;
	}
	/* Check IP version*/
    if(IP_V(ip) != 4){
		printf("Invalid IP Version\n");
        return false;
	}
    /* Check if tot len is shorter than hdr length*/
    if(ntohs(ip->ip_len) < size_ip_hdr){
		printf("Total length is shorter than header length\n");
        return false;
	}
    /* Check TTL - 0 < TTL < 255*/
    if(ip->ip_ttl < 1 || ip->ip_ttl > 255){
		printf("Invalid TTL value\n");
        return false;
	}
    /* Check protocol*/
    if(ip->ip_p != IPPROTO_ICMP && ip->ip_p != IPPROTO_TCP){
		printf("Invalid protocol (no icmp/tcp)\n");
        return false;
	}
	/* Check for evil bit */
	u_short mask = 32768;
	if((ntohs(ip->ip_off) & mask) > 0){
		printf("Evil bit is set\n");
		return false;
	}

	// TODO what if hl field >= 20 but packet is not?

    // Validate Checksum
	//printf("ip chksum(input): %d\n", ip->ip_sum);
	u_short chksum1 = ip->ip_sum;
	ip->ip_sum = 0;
	u_short chksum2 = (u_short) ip_checksum(ip, size_ip_hdr);
	//printf("ip chksum(calculated): %d\n", chksum2);
	if(chksum1 != chksum2){
		printf("Invalid IP checksum\n");
		return false;
	}
	ip->ip_sum = chksum1;

    return true;
}

bool check_icmp_hdr(struct icmp_hdr *icmp, int size_icmp){
    /* Check ICMP type and code*/
    if(icmp->type == ICMP_ECHO_REQUEST_TYPE){
        if(icmp->code != ICMP_ECHO_REQUEST_CODE){
			printf("Echo request type and code do not match\n");
			return false;
		}
    }
    else if(icmp->type == ICMP_ECHO_REPLY_TYPE){
        if(icmp->code != ICMP_ECHO_REPLY_CODE){
			printf("Echo reply type and code to not match\n");
			return false;
		}
    }
    else{
		printf("ICMP message is not an echo or a reply\n");
		return false;
	}

    // Validate Checksum
	//printf("icmp chksum(input): %d\n", icmp->checksum);
    u_int16_t chksum1 = icmp->checksum;
	icmp->checksum = 0;
	u_int16_t chksum2 = (u_int16_t) ip_checksum(icmp, size_icmp);
	//printf("icmp chksum(calculated): %d\n", chksum2);
	if(chksum1 != chksum2){
		printf("Invalid ICMP checksum\n");
		return false;
	}
	icmp->checksum = chksum1;

    return true;
}

bool check_tcp_hdr(struct tcp_hdr *tcp){
    int size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("Invalid TCP header length: %u bytes\n", size_tcp);
        return false;
    }

    // TODO validate fields/checksum

    return true;
}

// checksum method is taken from: 
// http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html
uint16_t ip_checksum(void* vdata, size_t length){
    // Cast the data pointer to one that can be indexed.
    char* data = (char*)vdata;

    // Initialise the accumulator.
    uint32_t acc = 0xffff;
    size_t i;
    // Handle complete 16-bit blocks.
    for (i=0; i+1<length; i+=2){
        uint16_t word;
        memcpy(&word, data+i, 2);
        acc += ntohs(word);
        if(acc > 0xffff){
            acc -= 0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if(length & 1){
        uint16_t word = 0;
        memcpy(&word, data+length-1, 1);
        acc += ntohs(word);
        if(acc > 0xffff){
            acc -= 0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}
