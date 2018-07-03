#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include<netinet/ip_icmp.h>   
#include<netinet/udp.h> 
#include <pcap/pcap.h>

#define ETHER_ADDR_LEN 6
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct Ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


struct Ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

typedef u_int tcp_seq;

struct Tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
void printHexAsciiValueOfPayload(const u_char *payload, int len,FILE *f)
{
	const u_char *temp;
  	temp = payload;
	int i;
	int j =0;
	for(i =0; i < len ; i++){
		printf("%02x" , *temp);
		temp++;
		printf(" ");
		
		fprintf(f,"%02x" ,*temp);
		fprintf(f," ");
	}

	printf("     ");
	fprintf(f,"      ");
	temp=payload;
	/*for( i =0;i<len;i++){
	 	printf("%c",*temp);
		fprintf(f,"%c",*temp);
		temp++;

	}*/
	 for(j=0 ; j<len ; j++)
            {
                if(temp[j]>=32 && temp[j]<=128) 
			fprintf(f,"%c",(unsigned char)temp[j]);
                else 
			fprintf(f,".");
            }
	printf("\n");
	fprintf(f,"\n");
	
return;
}
void print_IP(const struct Ip *ip,FILE *f,char *protocol){
	printf("IP Header Details\n");
	printf("Protocol                        :%s\n",protocol);
	printf("Source Address                  :%s\n",inet_ntoa(ip->ip_src));
	printf("Destination Address             :%s\n",inet_ntoa(ip->ip_dst));
	printf("IP version                      :%d\n",(unsigned int)ip->ip_vhl);
	printf("IP total length                 :%d\n",(unsigned int)ip->ip_len);
	fprintf(f,"\n");

	fprintf(f,"IP Header Details\n");
	fprintf(f,"Protocol                     :%s\n",protocol);	
	fprintf(f,"Source Address               :%s\n",inet_ntoa(ip->ip_src));
	fprintf(f,"Destination Address          :%s\n",inet_ntoa(ip->ip_dst));
	fprintf(f,"Ip Version                   :%d\n",(unsigned int )ip->ip_vhl);
	fprintf(f,"IP header length             :%d\n",IP_HL(ip)*4);
	
}
/*void printToTextFile(char * sourceAdd,char *destAdd,char *protocol, const char *payload,int sizeOfpayload,const struct Ethernet *ethHdr){
	static int i=0;
	FILE * f;
	const u_char *temp;
  	temp = payload;
	//printf("here we got output");
	if(i==0)
		
		f = fopen("output.txt", "w");
	else
		f=fopen("output.txt", "a");
	if (f == NULL)
	{
	 	printf("Error opening file!\n");	
    		exit(1);
	}
	fprintf(f, "%s", protocol);
	fprintf(f, "~%s", sourceAdd);
	fprintf(f, ">%s\n", destAdd);
	fprintf(f, "Payload~");
	if(sizeOfpayload<=0){
			fprintf(f,"There are no payload in the packet\n");
			
	}
	else{
		int j;
		int lineWidth = 16;			/* number of bytes per line 
		int size=sizeOfpayload;
		int currentLineLength;                   //The current length of the line left to be printed out.
		if(size<=lineWidth){
			j=0;
			for(j=0;j<currentLineLength;j++){
				fprintf(f,"%02x" , *temp);
				temp++;
				fprintf(f," ");
			}
			fprintf(f,"\n");
		}
		else{
			j=0;
			while(1){
				currentLineLength=lineWidth%size;						//find the length of the line of the packet we are processing
				size=size-currentLineLength;							//find the remaining size of the payload we have to process
				printf("Current line length is :%d\n",currentLineLength);
				printf("Current size is :%d\n",size);
				for(j=0;j<currentLineLength;j++){
					fprintf(f,"%02x" , *temp);
					temp++;
					fprintf(f," ");
				}
				fprintf(f,"\n");
				payload=payload+currentLineLength;						//shift the pointer to the next line of 16 byte or remaining byte to process
				if(size<=lineWidth){								//if the packet is at its last line 
						for(j=0;j<size;j++){
							fprintf(f,"%02x" , *temp);
							temp++;
							fprintf(f," ");
						}
						
						fprintf(f,"\n");				//print the last line and break from the infinite loop
						break;
				}

			}

		}
	}
	
	fclose(f);
	i++;
}*/
void print_tcp(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet,char * protocol,const struct Ip *ip,FILE *f){
	const struct Ethernet *ethernet;  /* The ethernet header [1] */
	
	const struct Tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int sizeOfip;
	int sizeOftcp;
	int sizeOfpayload;
	static int i=0;
	
	const u_char *temp;
  	temp = payload;
	//printf("here we got output");
	
	
	
	
	ethernet = (struct Ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct Ip*)(packet + SIZE_ETHERNET);
	sizeOfip = IP_HL(ip)*4;
	tcp = (struct Tcp*)(packet + SIZE_ETHERNET + sizeOfip);
	sizeOftcp = TH_OFF(tcp)*4;
	print_IP(ip,f,protocol);
	payload = (u_char *)(packet + SIZE_ETHERNET + sizeOfip + sizeOftcp);
	printf("The size of tcpsize = %d\n",sizeof tcp);
	/* compute tcp payload (segment) size */
	sizeOfpayload = ntohs(ip->ip_len) - (sizeOfip + sizeOftcp);
	
	//printToTextFile(sourceAdd,destAdd,protocol,payload,sizeOfpayload,ethernet);
	printf("\n");
	printf("TCP Header detail\n");
	printf("\n");
	printf("Source Port                  :%d\n",ntohs(tcp->th_sport));
	printf("Destination Port             :%d\n",ntohs(tcp->th_dport));
	printf("TCP Header length            :%d\n",sizeOftcp);
	printf("\n");
	fprintf(f,"\n");
	fprintf(f,"TCP Header detail\n");
	fprintf(f,"\n");
	fprintf(f,"Source Port                  :%d\n",ntohs(tcp->th_sport));
	fprintf(f,"Destination Port             :%d\n",ntohs(tcp->th_dport));
	fprintf(f,"TCP Header length            :%d\n",sizeOftcp);
	fprintf(f,"\n");
	//fprintf(f,"Payload\n");
	
	if(sizeOfpayload<=0){
			printf("There no payload in the packet\n");
			fprintf(f,"There no payload in the packet\n");
			fprintf(f,"End of packet\n");
	}
	
	else if (sizeOfpayload > 0) {
		printf("   Payload (%d bytes):\n", sizeOfpayload);
		fprintf(f,"Payload (%d bytes):\n", sizeOfpayload);
		int lineWidth = 16;			/* number of bytes per line */	
		int size=sizeOfpayload;
		int currentLineLength;                   //The current length of the line left to be printed out.
		
	
			if(sizeOfpayload<=lineWidth){									//if the size of the payload is less thant 16 bytes we can just print it out.
				printHexAsciiValueOfPayload(payload,sizeOfpayload,f);			
			}
			else{
				while(1){
					currentLineLength=lineWidth%size;						//find the length of the line of the packet we are processing
					size=size-currentLineLength;							//find the remaining size of the payload we have to process
					printHexAsciiValueOfPayload(payload,currentLineLength,f);				//print the line of packet
					payload=payload+currentLineLength;						//shift the pointer to the next line of 16 byte or remaining byte to process
					if(size<=lineWidth){								//if the packet is at its last line 
						printHexAsciiValueOfPayload(payload,size,f);				//print the last line and break from the infinite loop
						fprintf(f,"End of packet\n");						
						break;
					}
				}
			}	
	
		}
	
	
	i++;
return;	

	
}
void print_udp(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet,char * protocol,const struct Ip *ip,FILE *f){
	struct udphdr *udph = (struct udphdr*)(packet+SIZE_ETHERNET+IP_HL(ip));
	int sizeOfip = IP_HL(ip)*4;
	
	print_IP(ip,f,protocol);
	int sizeOfUdp=8;
	int sizeOfpayload = ntohs(ip->ip_len) - (sizeOfip + sizeOfUdp);
	const char * payload = (u_char *)(packet + SIZE_ETHERNET + sizeOfip + sizeOfUdp);
	printf("UDP Header Details");
	printf("\n");
	printf("\nUDP Header\n");
  	printf("Source Port                  :%d\n", ntohs(udph->source));
        printf("Destination Port             : %d\n" , ntohs(udph->dest));
  	printf("UDP Length                   : %d\n" , ntohs(udph->len));
    	printf("UDP Checksum                 : %d\n" , ntohs(udph->check));
	printf("UDP Header Length            :%d Bytes\n",sizeOfUdp);
	fprintf(f,"UDP Header Details");
	fprintf(f,"\n");
	fprintf(f,"\nUDP Header\n");
  	fprintf(f,"Source Port                  :%d\n", ntohs(udph->source));
        fprintf(f,"Destination Port             : %d\n" , ntohs(udph->dest));
  	fprintf(f,"UDP Length                   : %d\n" , ntohs(udph->len));
    	fprintf(f,"UDP Checksum                 : %d\n" , ntohs(udph->check));
	fprintf(f,"UDP Header Length            :%d Bytes\n",sizeOfUdp);
	if(sizeOfpayload<=0){
			printf("There no payload in the packet\n");
			fprintf(f,"There no payload in the packet\n");
			fprintf(f,"End of packet\n");
	}
	
	else if (sizeOfpayload > 0) {
		printf("   Payload (%d bytes):\n", sizeOfpayload);
		fprintf(f,"Payload (%d bytes):\n", sizeOfpayload);
		int lineWidth = 16;			/* number of bytes per line */	
		int size=sizeOfpayload;
		int currentLineLength;                   //The current length of the line left to be printed out.
		
	
			if(sizeOfpayload<=lineWidth){									//if the size of the payload is less thant 16 bytes we can just print it out.
				printHexAsciiValueOfPayload(payload,sizeOfpayload,f);			
			}
			else{
				while(1){
					currentLineLength=lineWidth%size;						//find the length of the line of the packet we are processing
					size=size-currentLineLength;							//find the remaining size of the payload we have to process
					printHexAsciiValueOfPayload(payload,currentLineLength,f);				//print the line of packet
					payload=payload+currentLineLength;						//shift the pointer to the next line of 16 byte or remaining byte to process
					if(size<=lineWidth){								//if the packet is at its last line 
						printHexAsciiValueOfPayload(payload,size,f);				//print the last line and break from the infinite loop
						fprintf(f,"End of packet\n");						
						break;
					}
				}
			}	
	
		}
	
	
	
}
void getPacket(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet){
	static int count = 1;   
 	static int i =0;              
	FILE *f;
	if(i==0)
		
		f = fopen("output.txt", "w");
	else
		f=fopen("output.txt", "a");
	if (f == NULL)
	{
	 	printf("Error opening file!\n");	
    		exit(1);
	}
	const struct Ethernet *ethernet;  /* The ethernet header [1] */
	const struct Ip *ip;              /* The IP header */
	const struct Tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int sizeOfip;
	int sizeOftcp;
	int sizeOfpayload;
	
	//unsigned char *packet = (unsigned char *)malloc(65536);
	
	
	/* define ethernet header */
	ethernet = (struct Ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct Ip*)(packet + SIZE_ETHERNET);
	//sizeOfip = IP_HL(ip)*4;
	//tcp = (struct Tcp*)(packet + SIZE_ETHERNET + sizeOfip);
	//sizeOftcp = TH_OFF(tcp)*4;
	/*if (sizeOfip < 20||sizeOftcp<20) {
		if(sizeOfip<20)	{	
			//printf("   * Invalid IP header length: %u bytes\n", sizeOfip);
		}
		else if(sizeOftcp<20){
			//printf("   * Invalid TCP header length: %u bytes\n", sizeOftcp);
		}
		return;
	}*/
	printf("\nPacket number %d:\n", count);
	fprintf(f,"\nPacket number %d:\n", count);
	count++;
	
	
	
	char *protocol;
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			protocol="TCP";
			//printf(" Protocol :%s\n",protocol);	
			print_tcp(args,hdr,packet,protocol,ip,f);		
			break;
		case IPPROTO_UDP:
			protocol="UDP";
			//printf("   Protocol: %s\n",protocol);
			print_udp(args,hdr,packet,protocol,ip,f);
			break;
		case IPPROTO_ICMP:
			//printf("   Protocol: ICMP\n");
			break;
		case IPPROTO_IP:
			//printf("   Protocol: IP\n");
			break;
		default:
			printf("   Protocol: unknown\n");
			break;
	}
	
	
	
	
	fclose(f);	
	
	//printf("   Src port: %d\n", ntohs(tcp->th_sport));
	//printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
	/* compute tcp payload  offset */
	i++;	
	
}
void sniffPacket(){
	int i =10;
  char *dev; 
  char *net; 
  char *mask;
  int ret;  
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netAdd; 
  bpf_u_int32 maskAdd;
  struct in_addr addr;
  pcap_t *handler;
  const u_char *packet;
  struct pcap_pkthdr hdr;
  struct ether_header *eptr;
  char filter_exp[] = "ip";
struct bpf_program filter;
  printf("Start this program\n"); 
  
  dev=pcap_lookupdev(errbuf);
  printf("Sniffing on interface :%s\n",dev);
  
  //open the sniffing session
  //handler= pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    handler=pcap_create(dev,errbuf);
    pcap_set_promisc(handler,1);
    pcap_activate(handler);
   if(handler == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }
 	if (pcap_datalink(handler) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}
	if (pcap_lookupnet(dev, &netAdd, &maskAdd,errbuf) == -1) {
		printf("Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		netAdd = 0;
		maskAdd = 0;
	}
if (pcap_compile(handler, &filter, filter_exp, 0, netAdd) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handler));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handler, &filter) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handler));
		exit(EXIT_FAILURE);
	}

 
  pcap_loop(handler,0,getPacket,NULL);
	pcap_freecode(&filter);
	pcap_close(handler);


}


int main(int argc, char **argv)
{ 
	int i ;
	//printf("this is : %d\n ",argc);
	/*for( i =0;i<argc;i++){
		if(i!=0){
			printf( "%s",argv[1]);
		}
		
	}*/
	char interface[10];
	if(strcmp(argv[1],"-i")==0){
		strcpy(interface,argv[2]);

	}
	else{
		strcpy(interface,"eth0");

	}
	printf("interface : %s",interface);	
	sniffPacket();
  
}
