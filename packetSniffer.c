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
#define ARP_ETHERNET    0x0001
#define ARP_IPV4        0x0800
#define ARP_REQUEST     0x0001
#define ARP_REPLY       0x0002

//-------------------------- PACKET STRUCTURES --------------------------------

// IP Packet Structure
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

// ARP Packet Structure
struct Arphdr { 
    unsigned short htype;    /* Hardware Type           */ 
    unsigned short ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    unsigned short opc;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
};


/*struct Ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address 
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address 
        u_short ether_type;                     /* IP? ARP? RARP? etc 
};*/


// TCP Packet Structure
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

// DNS Packet Structure
// Ethernet >> IP >> UDP >> DNS
// 
// Usually uses UDP, unless TCP required or exceed UDP max size of 512 octets(256 bytes)
//
// DNS request & DNS response more of less the same except
// Response has : Answers, Authoritative Name Servers, Additional Records

// Fields for Question 
struct Question {	
	u_short qtype;				/*  */
	u_short qclass;				/*  */
};

// Define Structure for Query
typedef struct {
	u_char *name;				/*  */
	struct Question *question;	/*  */
} Query;

// Fields for Records 
struct RecordData {
	u_short rtype;				/* Type */
	u_short rclass;				/* Class */
	u_int rttl;					/* Time to Live */
	u_short data_len;			/* Data Length */
};

// Resource Record Content
struct ResourceRecord{
	u_char *rdata				/* Resource Data */
	u_char *dname;				/* Domain Name */
	RecordData *resource;		/* Record Data */
};

// Each Response has a "Answer, Authoritative Namesever, Additional Record"
// They all comprise of a ResourceRecord structure
// 
struct Dns {
	u_short dns_id; 	/* (16 bits) Identifier, generated by device that creates DNS query */
	u_char dns_qr 		/* (1 bit) Query Response Flag, differentiate between queries and responses */
	
	// define Opcode flags
	u_char dns_opcode;	/* (4 bits) Operation Code,  	*/
	#define DNS_SQ		/* Standard Query 			*/  
	#define DNS_IQ 		/* Inverse Query, 	(now obsolete, lookp name from ip addr)			*/ 
	#define DNS_SR		/* Status request,	(server status request)		*/
	#define DNS_NOT		/* Notify, (primary server tell secondary servers for zone transfer)	*/
	#define DNS_UPT		/* Update, (Allow implement Dynamic DNS, add & delete of records selected) */
	
	u_char dns_aa;		/* (1 bit) Authoritative Answer Flag, show if server that created response is authoritative for the zone */
	u_char dns_tr;  	/* (1 bit) Truncation Flag, show that msg was truncated due to being too long */
	u_char dns_rd; 		/* (1 bit) Recursion Desired, server to attempt recursion */
	u_char dns_ra; 		/* (1 bit) Recursion Available, whether server supports recursion*/
	u_char dns_z;		/* (3 bits) Zero, three reserved bits set to '0' */
	
	// define Rcode flags
	u_char dns_rcode;	/* (4 bits) Response Code, Set to '0' in queries */
	#define DNS_NOERR	/* No Error, no error occ */
	#define DNS_FERR	/* Format Error, server unable to respond to query due to how query was constructed */
	#define DNS_SFAIL	/* Server Failure, server unable to respond due to server itself */
	#define DNS_NERR	/* Name Error, name specified does not exist in domain */
	#define DNS_NIMPL	/* Not Implemented, type of query received not supported */
	#define DNS_REF		/* Refused, server refused query process due to policy or technical reasons */
	#define DNS_YXDOM	/* YX Domain, name exists where it should not */
	#define DNS_YXRRS	/* YX RR Set, resource record exists where it should not */
	#define DNS_NXRRS	/* NX RR Set, resource record that should exist does not */
	#define DNS NAUTH	/* Not Auth, server receiving query is not authoritative for zone specified */
	#define DNS_NZ		/* Not Zone, name speicified is not within the zone specified in msg */
	
	u_short dns_qdcount; /* (16 bits) Question Count, specifies number of questions */
	u_short dns_ancount; /* (16 bits) Answer Record Count, specifies number of records in 'Answer Section' */
	u_short dns_nscount; /* (16 bits) Authority Record Count, Specify number of records in 'Authority Section' */
	u_short dns_arcount; /* (16 bits) Additional Record Count, Specifies number of records in 'Additional Section' */
}







//---------------------------------- Print Functions -------------------------------

void printHexAsciiValueOfPayload(const u_char *payload, int len,FILE *f)
{
	const u_char *temp;
  	temp = payload;
	int i;
	int j =0;
	for(i =0; i < len ; i++){
		printf("%02x" , *temp);
		
		fprintf(f,"%02x" ,*temp);
		fprintf(f," ");
		temp++;
		printf(" ");
		
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
                if(temp[j]>=32 && temp[j]<=128) {
			fprintf(f,"%c",(unsigned char)temp[j]);
			printf("%c",(unsigned char) temp[j]);
		}
                else {
			fprintf(f,".");
			printf(".");
		}
            }
	printf("\n");
	fprintf(f,"\n");
	
return;
}
void print_IP(const struct Ip *ip,FILE *f,char *protocol){
	//printf("IP Header Details\n");
	printf("Protocol=%s ",protocol);
	printf("%s>",inet_ntoa(ip->ip_src));
	printf("%s ",inet_ntoa(ip->ip_dst));
	//printf("IPFlag=%d ",ip->ip_off);
	//printf("IP total length                 :%d\n",(unsigned int)ip->ip_len);
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
	int j=0;
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
	
	/* compute tcp payload (segment) size */
	sizeOfpayload = ntohs(ip->ip_len) - (sizeOfip + sizeOftcp);
	unsigned int sequence =tcp->th_seq;
	int bin =tcp->th_flags;
	
	int binaryArr[6];
	for(j=0;j<=5;j++){
		binaryArr[j]=0;
	
	}
	for(j=5;bin>0;j--)     //because flag are just decimal  number convert to binary 010010 this means ack and syn.
	{    
		binaryArr[j]=bin%2;    
		bin=bin/2;    
	}                                                               
	
	// Therefore to know which flag is in the packet we would need to convert decimal to binary and see which bit is not 0.
	printf("Flags:[");
	for(j=5;j>=0;j--){
	  
	  switch(j){
		case 0: 
			//printf("binary= %d",binaryArr[0]);
			if(binaryArr[0]==1){
				printf("U");
			}
			break;
		case 1://printf("binary= %d",binaryArr[1]);
			if(binaryArr[1]==1){
				printf(".");
			}
			break;
		case 2:if(binaryArr[2]==1){
				printf("P");
			}
			break;
		case 3:if(binaryArr[3]==1){
				printf("R");
			}
			break;
		case 4:if(binaryArr[4]==1){
				printf("S");
			}
			break;
		case 5:if(binaryArr[5]==1){
				printf("E");
			}
			break;
			
	}
	}
	printf("] ");
	
	
	printf("seq:%d",sequence);
	printf(" ack:%d",tcp->th_ack);
	printf(" win:%d",tcp->th_win);
	printf(" cs:%d",tcp->th_sum);
	printf(" Length:%d",sizeOfpayload);
	printf("\n");
	
	
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
  	printf("SPort=%d ", ntohs(udph->source));
    printf("DPort=%d " , ntohs(udph->dest));
  	printf("Length=%d " , ntohs(udph->len));
    printf("Checksum=%d " , ntohs(udph->check));
	printf("HLength=%d ",sizeOfUdp);
	
	printf("\n");
	
	
	
}
void printARP(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet,FILE *f,const struct ether_header *ethernet,const struct Arphdr *arp){
	
	
	printf("Protocol=ARP ");
	//printf("SAdd%s ",ether_ntoa((const struct ether_addr *)&ethernet->ether_shost));
	//printf("dAdd%s ",ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost));
	

	//foramt is shown in this manner for request..... destination address(daDD) pls send to senderAddress(sadd)
	//format is shown in this manner for reply....... destination address(dAdd) can be found at destination mac address(dMAdd)
	//example protocol=ARP Request dAdd=192.168.136.2. sAdd=192.168.136.128.
	//ARP Reply dAdd=192.168.136.128. dMAdd=00:0c:29:5d:c1:ce:

	switch(ntohs(arp->opc)){
		case 1:printf("Request ");
			int i=0;
			printf("dAdd=");			
			for(i=0;i<4;i++){
				if(i!=3)
					printf("%d.",arp->tpa[i]);
				else
					printf("%d",arp->tpa[i]);
					
			}
			printf(" sAdd=");
			for(i=0;i<4;i++){
				if(i!=3)
					printf("%d.",arp->spa[i]);	
				else
					printf("%d",arp->spa[i]);	
			}
			printf("\n");
			break;	
		case 2:printf("Reply ");
			
			printf("dAdd=");			
			for(i=0;i<4;i++){
				if(i!=3)
					printf("%d.",arp->tpa[i]);
				else
					printf("%d",arp->tpa[i]);		
			}
			printf(" dMAdd=");
			for(i=0;i<6;i++){
				if(i!=5)
					printf("%02x:",arp->tha[i]);	
				else
					printf("%02x",arp->tha[i]);		
			}
			printf("\n");
			break;	
		       

	}
	printf("\n");
}


void print_dns(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet,char * protocol,const struct Ip *ip,FILE *f, const struct Dns *dns){
	
	printf("Protocol=DNS ");
	// Dns protocol :
	// Ethernet >> IP >> UDP/TCP >> DNS
	// If port = UDP 53 or TCP 53
	// 
	
	
}



//------------------------------------ OTHER IMPORTANT FUNCTION -------------------------------

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
	const struct ether_header *ethernet;  	/* The ethernet header [1] */
	const struct Ip *ip;              		/* The IP header */
	const struct Tcp *tcp;            		/* The TCP header */
	const struct Arphdr *arp;	 			/* The ARP header */
	const struct udphdr *udph;				/* The UDP header */
	const struct Dns *dns;					/* The DNS header */
	const char *payload;                    /* Packet payload */

	int sizeOfip;
	int sizeOftcp;
	int sizeOfpayload;
	
	//unsigned char *packet = (unsigned char *)malloc(65536);
	
	
	/* define ethernet header */
	ethernet = (struct ether_header*)(packet);
	
	
	/* define/compute ip header offset */
	ip = (struct Ip*)(packet + SIZE_ETHERNET);
	
	count++;
	
	
	
	char *protocol;
	//determine if a packet is of type ARP or IP
	if (ntohs (ethernet->ether_type) == ETHERTYPE_ARP){
		arp =(struct Arphdr *)(packet+14);
		printARP(args,hdr,packet,f,ethernet,arp);
	}
	
	else if (ntohs (ethernet->ether_type) == ETHERTYPE_IP){
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			protocol="TCP ";
			//printf(" Protocol :%s\n",protocol);
			// If Source/Destination port == 53, then it is a DNS packet
			// th_sport, th_dport (tcp port variable names)
			
			
			
			
			// Else
			print_tcp(args,hdr,packet,protocol,ip,f);		
			break;
		case IPPROTO_UDP:
			protocol="UDP ";
			//printf("   Protocol: %s\n",protocol);
			
			struct udphdr *udph = (struct udphdr*)(packet+SIZE_ETHERNET+IP_HL(ip));
			int sizeOfip = IP_HL(ip)*4;
			int sizeOfUdp=8;
			int sizeOfpayload = ntohs(ip->ip_len) - (sizeOfip + sizeOfUdp);
			const char * payload = (u_char *)(packet + SIZE_ETHERNET + sizeOfip + sizeOfUdp);
			
			// If Source/Destination port == 53, then it is a DNS packet
			// source, dest (udp port variable names)
			// print_dns()
			if(ntohs(udph->source) == 53){
				
				print_dns(args,hdr,packet,protocol,ip,f,dns);
			}else{// else print_udp
				
				print_udp(args,hdr,packet,protocol,ip,f);
			}
			
			
			
			break;
		case IPPROTO_ICMP:
			//printf("   Protocol: ICMP\n");
			break;
		case IPPROTO_IP:
			//printf("   Protocol: IP\n");
			break;
		default:
			printf("   Protocol: unknown\n");
			fprintf(f,"Protocol unknown\n");
			break;
	}
	
	}
	
	
	fclose(f);	
	
	//printf("   Src port: %d\n", ntohs(tcp->th_sport));
	//printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
	/* compute tcp payload  offset */
	i++;	
	
}
void sniffPacket(char * interface){
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
  
  
struct bpf_program filter;
  printf("Start this program\n"); 
  
  //dev=pcap_lookupdev(errbuf);
  dev=interface;
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
/*if (pcap_compile(handler, &filter, filter_exp, 0, netAdd) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handler));
		exit(EXIT_FAILURE);
	}
	/* apply the compiled filter 
	if (pcap_setfilter(handler, &filter) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handler));
		exit(EXIT_FAILURE);
	}
*/
 
  pcap_loop(handler,0,getPacket,NULL);
	pcap_freecode(&filter);
	pcap_close(handler);


}

//-------------------------------------- MAIN FUNCTION ----------------------------------

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
	sniffPacket(interface);
  
}
