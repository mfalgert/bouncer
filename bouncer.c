/* Port Bouncer
* To be called as nbouncer local_ip local_port remote_ip remote_port
*/

#include "bouncer.h"

void process_pkt(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet);

int main(int argc, char *argv[])
{
    char * interface;
    /* parse input parameters*/
    if (argc == 6){
        interface = argv[1];
        listen_ip = argv[2];
        listen_port = strtoul(argv[3], NULL, 0);
        server_ip = argv[4];
        server_port = strtoul(argv[5], NULL, 0);
    }else{
        printf("Error parsing input:");
        int i;
        for(i = 0; i < argc; i++){
            printf(" %s",argv[i]);
        }
        printf("\nSyntax: <interface> <listen_ip> <listen_port> <server_ip> <server_port>\n");
    }
    /* todo check that the input are correct (e.g. valid ip address)*/

    /* Include here your code to initialize the PCAP capturing process */
    pcap_t *handle;		            /* Session handle */
    char *dev = interface;		    /* Device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		    /* The compiled filter expression */
    bpf_u_int32 mask;		        /* The netmask of our sniffing device */
    bpf_u_int32 net;		        /* The IP of our sniffing device */
    char filter_exp[512];           /* The filter expression - Filter out packets destined to bouncer*/
    snprintf(filter_exp, sizeof filter_exp, "%s %s %s %d %s", "dst net",
             listen_ip, "and (tcp dst port", listen_port,
             "or (icmp[icmptype] == icmp-echo or icmp[icmptype] == icmp-echoreply))");  //only request/reply

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 0/*(no prom.mode) change this?*/, 0/*(no delay) change this?*/, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    if (pcap_datalink(handle) != DLT_EN10MB/*only Ethernet*/) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return(2);
	}
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s\n: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
	 if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	 }

    /* Open RAW socket to send on */
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        printf("%s då då\n",strerror(errno));
        return (1);
    }
    /* Set socket options*/
    int hdrincl=1;
    if (setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,&hdrincl,sizeof(hdrincl))==-1) {
        printf("%s hej hej\n",strerror(errno));
        return (1);
    }

	printf("\n--- Bouncer is now running ---\n\n");
	
    /*Start PCAP loop*/
    pcap_loop(handle, -1, process_pkt, NULL);

    pcap_freecode(&fp);
	pcap_close(handle);

    printf("Exiting\n");
    return 0;
}//End of the bouncer
