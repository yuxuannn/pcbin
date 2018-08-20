#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ip_icmp.h>   
#include <netinet/udp.h> 
#include <pcap/pcap.h>
#include <endian.h>
#include <stdint.h>


#define ETHER_ADDR_LEN 6
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define SIZE_UDP 8
#define SIZE_DNS 12
#define SIZE_QNSIZE 4
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
typedef u_long tcp_seq;

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

// Define Structure for Query, contains an incomplete Resource Record. [DNSname, TYPE, CLASS]
typedef struct Query{
	u_char *name;				/*  */
	struct Question *question;	/*  */
}query;

// Fields for Records 
struct RecordData {
	u_short rtype;				/* Type */
	u_short rclass;				/* Class */
	u_int rttl;					/* Time to Live */
	u_short data_len;			/* Data Length */
};

// Resource Record Structure, complete record 
struct ResourceRecord{
	u_char *rdata;				/* Resource Data */
	u_char *dname;				/* Domain Name */
	struct RecordData *resource;		/* Record Data */
};

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server
#define T_TXT	= 16
#define T_AAAA	= 28
#define T_SRV	= 33
#define T_OPT	= 41
#define T_SSHFP	= 44
#define T_SPF	= 99
#define T_AXFR      = 252

#define T_ALL	= 255

/* DNS QCLASS */
#define DNS_QCLASS_RESERVED	0
#define DNS_QCLASS_IN		1
#define DNS_QCLASS_CH		3
#define DNS_QCLASS_HS		4
#define DNS_QCLASS_NONE		254
#define DNS_QCLASS_ANY		255


// Each DnsRequest has a "Query", the rest are left blank
// Each DnsReply has a "Query, Answer, Authoritative Namesever, Additional Record"
// They all comprise of a ResourceRecord structure
// 
struct Dns {

	
	
	// define Opcode flags
	
	#define DNS_SQ	0	/* Standard Query 			*/  
	#define DNS_IQ 	1	/* Inverse Query, 	(now obsolete, lookp name from ip addr)			*/ 
	#define DNS_SR	2	/* Status request,	(server status request)		*/
	#define DNS_NOT	4	/* Notify, (primary server tell secondary servers for zone transfer)	*/
	#define DNS_UPT	5	/* Update, (Allow implement Dynamic DNS, add & delete of records selected) */
	uint16_t dns_id;	/* (16 bits) Identifier, generated by device that creates DNS query */
# if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t dns_qr:1;	/* (1 bit) Query Response Flag, differentiate between queries and responses [0=Query] [1=Response] */
	uint16_t dns_opcode:4;	/* (4 bits) Operation Code,  any other number = Unassigned	*/
	uint16_t dns_aa:1;	/* (1 bit) Authoritative Answer Flag, show if server that created response is authoritative for the zone */
	uint16_t dns_tc:1;	/* (1 bit) Truncation Flag, show that msg was truncated due to being too long */
	uint16_t dns_rd:1;	/* (1 bit) Recursion Desired, server to attempt recursion */
	uint16_t dns_ra:1;	/* (1 bit) Recursion Available, whether server supports recursion*/
	uint16_t dns_z:3;	/* (1 bits) Zero, 1 reserved bit set to '0' */
	uint16_t dns_rcode:4;	/* (4 bits) Response Code, Set to '0' in queries */
# elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t dns_rd:1;
	uint16_t dns_tc:1;
	uint16_t dns_aa:1;
	uint16_t dns_opcode:4;
	uint16_t dns_qr:1;
	uint16_t dns_rcode:4;
	uint16_t dns_z:3;
	uint16_t dns_ra:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif

	//u_char dns_ad;		/* (1 bit) Authenticated Data, used by DNSSEC */
	//u_char dns_cd;		/* (1 bit) Checking Disabled, used by DNSSEC */ 
	
	// define Rcode flags
	
	#define DNS_NOERR 0	/* No Error, no error occ */
	#define DNS_FERR  1	/* Format Error, server unable to respond to query due to how query was constructed */
	#define DNS_SFAIL 2	/* Server Failure, server unable to respond due to server itself */
	#define DNS_NERR  3	/* Name Error, name specified does not exist in domain */
	#define DNS_NIMPL 4	/* Not Implemented, type of query received not supported */
	#define DNS_REF	  5	/* Refused, server refused query process due to policy or technical reasons */
	#define DNS_YXDOM 6	/* YX Domain, name exists where it should not */
	#define DNS_YXRRS 7	/* YX RR Set, resource record exists where it should not */
	#define DNS_NXRRS 8	/* NX RR Set, resource record that should exist does not */
	#define DNS NAUTH 9	/* Not Auth, server receiving query is not authoritative for zone specified */
	#define DNS_NZ	 10	/* Not Zone, name speicified is not within the zone specified in msg */
	
	u_short dns_qdcount; /* (16 bits) Question Count, specifies number of questions */
	u_short dns_ancount; /* (16 bits) Answer Record Count, specifies number of records in 'Answer Section' */
	u_short dns_nscount; /* (16 bits) Authority Record Count, Specify number of records in 'Authority Section' */
	u_short dns_arcount; /* (16 bits) Additional Record Count, Specifies number of records in 'Additional Section' */
};






//---------------------------------- Print Functions -------------------------------

void printHexAsciiValueOfPayload(const u_char *payload, int len)
{
	const u_char *temp;
  	temp = payload;
	int i;
	int j =0;
	for(i =0; i < len ; i++){
		printf("%02x" , *temp);
		
		
		temp++;
		printf(" ");
		
	}

	printf("     ");
	
	temp=payload;
	
	 for(j=0 ; j<len ; j++)
            {
                if(temp[j]>=32 && temp[j]<=128) {
		
			printf("%c",(unsigned char) temp[j]);
		}
                else {
			
			printf(".");
		}
            }
	printf("\n");
	
return;
}//testing function to print out all the raw data in a packet
void print_IP(const struct Ip *ip,char *protocol){
		
		
	printf("IP ");
	printf("%s ",protocol);
	printf("Src:%s ",inet_ntoa(ip->ip_src));
	printf("Dst:%s ",inet_ntoa(ip->ip_dst));
	


	
}

void print_tcp(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet,char * protocol,const struct Ip *ip){
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
	
	payload = (u_char *)(packet + SIZE_ETHERNET + sizeOfip + sizeOftcp);
	
	/* compute tcp payload (segment) size */
	sizeOfpayload = ntohs(ip->ip_len) - (sizeOfip + sizeOftcp);
		
	unsigned long sequence =tcp->th_seq;
	
	print_IP(ip,protocol);
	// tcp->th_flag are in decimal number  of the flags	
	int bin =tcp->th_flags;
	
	int binaryArr[6];

	//printing the source port and destination port
	printf("sPort:%d ",tcp->th_sport);
	printf("dPort:%d ",tcp->th_dport);
	for(j=0;j<=5;j++){
		binaryArr[j]=0;
	
	}
	for(j=5;bin>0;j--)     //because flag are just decimal  number convert to binary 010010 this means ack and syn.
	{    
		binaryArr[j]=bin%2;    
		bin=bin/2;    
	}                                                               
	
	// Therefore to know which flag is in the packet we would need to convert decimal to binary and see which bit is not 0.
	printf("[");
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
	
	
	printf("seq:%lu ",sequence);
	printf("ack:%lu ",tcp->th_ack);
	
	printf("chk:%d ",tcp->th_sum);
	printf("len:%d ",sizeOfpayload);
	printf("\n");
	//printf("\n");
	
	i++;
return;	

	
}
void print_udp(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet,char * protocol,const struct Ip *ip){
	struct udphdr *udph = (struct udphdr*)(packet+SIZE_ETHERNET+IP_HL(ip));
	int sizeOfip = IP_HL(ip)*4;
	int sizeOfUdp=8;
	print_IP(ip,protocol);
	
	int sizeOfpayload = ntohs(ip->ip_len) - (sizeOfip + sizeOfUdp);
	const char * payload = (u_char *)(packet + SIZE_ETHERNET + sizeOfip + sizeOfUdp);
  	printf("Src:%d ", ntohs(udph->source));
        printf("Dst:%d " , ntohs(udph->dest));
    	printf("chk:%d " , ntohs(udph->check));
	printf("len:%d " , ntohs(udph->len));
	
	
	printf("\n");
	//printf("\n");
	
	
}
void printARP(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet,const struct ether_header *ethernet,const struct Arphdr *arp){
	
	
	printf("ARP ");
	//printf("SAdd%s ",ether_ntoa((const struct ether_addr *)&ethernet->ether_shost));
	//printf("dAdd%s ",ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost));
	

	//foramt is shown in this manner for request..... destination address(daDD) pls send to senderAddress(sadd)
	//format is shown in this manner for reply....... destination address(dAdd) can be found at destination mac address(dMAdd)
	//example protocol=ARP|1|192.168.136.2|92.168.136.128
	//ARP reply ARP|2|192.168.136.128|00:0c:29:5d:c1:ce|192.168.136.128

	switch(ntohs(arp->opc)){
		case 1:printf("opc:%d ",ntohs(arp->opc));
			int i=0;
			printf("Dst:");			
			for(i=0;i<4;i++){
				if(i!=3)
					printf("%d.",arp->tpa[i]);
				else
					printf("%d ",arp->tpa[i]);
					
			}
			printf(" Src:");
			for(i=0;i<4;i++){
				if(i!=3)
					printf("%d.",arp->spa[i]);	
				else
					printf("%d",arp->spa[i]);	
			}
			printf("\n");
			break;	
		case 2:printf("opc:%d ",ntohs(arp->opc));
			
			printf("Src:");			
			for(i=0;i<4;i++){
				if(i!=3)
					printf("%d.",arp->tpa[i]);
				else
					printf("%d",arp->tpa[i]);		
			}
			printf(" SMac:");
			for(i=0;i<6;i++){
				if(i!=5)
					printf("%02x:",arp->tha[i]);	
				else
					printf("%02x",arp->tha[i]);		
			}
			printf(" Dst:");
			for(i=0;i<4;i++){
				if(i!=3)
					printf("%d.",arp->spa[i]);	
				else
					printf("%d",arp->spa[i]);	
			}
			printf("\n");
			break;	
		       

	}
	//printf("\n");
}



void print_dns(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet,char * protocol,const struct Ip *ip,const struct Dns *dns){
	
	// Dns protocol :
	// Ethernet >> IP >> UDP >> DNS
	// If port = UDP 53
	// 
	struct in_addr addr;
	int j=0;
	int sizeOfPayload;
	const u_char *payload;                    /* Packet payload */
	struct Query *qinfo;
	const struct Tcp *tcp; 
	int sizeOfip = IP_HL(ip)*4;
	const u_char *temp;
	struct ResourceRecord *rr;
	
	if(strcmp(protocol,"UDP")==0){
		/* compute UDP payload  offset */
		payload= (u_char *)(packet + SIZE_ETHERNET + sizeOfip + SIZE_UDP+SIZE_DNS);
		sizeOfPayload= ntohs(ip->ip_len)-(sizeOfip+SIZE_UDP+SIZE_DNS);
		//printHexAsciiValueOfPayload(payload,sizeOfPayload);   // <--------------------------uncomment here to read the packet payload
		temp=payload;
		
	}
	else{
		tcp = (struct Tcp*)(packet + SIZE_ETHERNET + sizeOfip);
		int sizeOftcp = TH_OFF(tcp)*4;
		payload= (u_char *)(packet + SIZE_ETHERNET + sizeOfip + SIZE_UDP+sizeOftcp);
		sizeOfPayload= ntohs(ip->ip_len)-(sizeOfip+sizeOftcp+SIZE_DNS);
		temp=payload;

	}
	//printf("DNs ANs record =%d\n",dns->dns_ancount);
	// print DNS items
	printf("IP ");
	printf("DNS ");
	printf("Src:%s ",inet_ntoa(ip->ip_src));
	printf("Dst:%s ",inet_ntoa(ip->ip_dst));
	
	
	if(dns->dns_qr==1){
		/*We see the byte 0xc0, which corresponds to a decimal value
of 192. This is clearly larger than the max label length (MAXLABEL =
63), so we know that we have a DNS pointer on our hands. We know that
the pointer references the absolute offset of 'xc00c' We know that
the first 2 bits of the first byte must be ignored, because this is
the signature of a compressed label. So we get rid of these 2 bits by
bitmasking them out. */
		int offset =1;    //0 for false 1 for true	
		int l=0;
		unsigned char buffer[sizeOfPayload*2+1];
		switch(dns->dns_opcode){
			case DNS_SQ: printf("[Standard Query Response]");
				     	
				     
				break;
			case DNS_IQ: printf("[Inverse Query Response]");
				break;
			case DNS_SR: printf("[Status Request Response]");
				break;	
			case DNS_NOT: printf("[Notify]");
				break;
			case DNS_UPT: printf("[Update]");
				break;
			default: printf("[Opcode]"); /* If doesnt match anything */
		}
		printf(" ");
		printf("id:%02x ",dns->dns_id);
		int z=0,i=0;
		//print of the question send to dns server , the website name and question type eg 			A=IPV4 
		//find the payload by add all the header together and print the payload out.
		printf("Ans:");
		while(*temp!=0){
			z=*temp	;
			for(i=0;i<z;i++){
				temp++;
				if(isprint(*temp)){
					printf("%c",*temp);			
				}			

			}
			if(*(temp+1)!=0)
				printf(".");
			temp++;	

		}
		printf(" ");		
		//this function is to point the pointer to the end of the name section of dns replies. Name are like www.google.com . Name are of variable size like www.youtube.com and www.google.come
		//have different sizes this will make sure the pointer point to the end of the name section.
		while(offset!=0){
			if(*temp ==12){
				offset=0;
				temp++;
			}
			else {				
				temp++;
				l++;
			}

		}
		
		
		int ll=0;     //just for while loop only not impt
		/*u_short dnsAncount;
		dnsAncount=dns->dns_ancount;
		dnsAncount/=256;
		while(dnsAncount!=0){*/ //still work in progress on need to make sure all type of dns packets are done before adding in while loop based on AnCount or else program will be mess up.
		//basically temp is a pointer pointing to the packet payload. 
		//uncomment the hexasccivalue function above to understand the code.
		// the below code is to jump to the section of the payload that contains the DNS type .
		while(*temp==0){
			temp++;

		}
		//once there we will use a switch case to determine what type  is it, A for IPV4 AAAA for IPV6
		//once we got the flag we will want to get the answer ip address . Therefore we will need to skip to that section.
		// other than the name the other section of dns replies are of fixed size
		// Type 2byte class 2 bytes TTL 4 bytes , RLength 2 bytes
		// since the temp below is around after type segment after temp ++ we only need to add 2 +4+2 to reach the resource data.
		switch(*temp){
			case 1: printf(" [IPV4] ");
				temp++;
				temp=temp+2+4+2;
				

					for(ll=0;ll<4;ll++){
						if(ll!=3){
							printf("%d.",*temp);
					
						}
						else
							printf("%d",*temp);	
					    
					temp++;
					
					}
					temp++;
					

				
				
				
			
				break;
			
			case 5:printf("[CNAME]");
				temp=temp+9;
				
				while(*temp!=192){
					z=*temp	;
					temp++;
					if(isprint(*temp)){
						printf("%c",*temp);			
					}			

					

				}
				while(*temp!=0){
					temp++;

				}
				temp++;
				printf(" ");
				if(*temp==1){
					printf("[IPV4]");
					temp=temp+9;
					for(ll=0;ll<4;ll++){
						if(ll!=3){
							printf("%d.",*temp);
					
						}
						else
							printf("%d",*temp);	
					    
					temp++;
					
					}
					
				}
				else if (*temp==28){

					printf("[IPV6]");
					temp=temp+9;
					int o=0;
					for(ll=0;ll<16;ll++){
					if(o!=2){
						printf("%02x",*temp);
						o++;
					}
					else{
											
							printf(":");
						o=1;
						printf("%02x",*temp);
					}	

					
					temp++;

				}
				}	
				break;
			
			case 28:printf("[IPV6]");
				temp++;
				
				temp=temp+8;
				int o=0;
				for(ll=0;ll<16;ll++){
					if(o!=2){
						printf("%02x",*temp);
						o++;
					}
					else{
											
							printf(":");
						o=1;
						printf("%02x",*temp);
					}	

					
					temp++;

				}
				break;
		

		}
			//dnsAncount--;
		//}
		//temp++;
		//because the above only points the pointer to 2 byte type  so to reach the resource len  we would need to bypass 2 byte class and 4 byte ttl.
		//temp=temp+2+4;

		
		
		
	}
	else{
		switch(dns->dns_opcode){
			case DNS_SQ: printf("[Standard Query]");
				     	
				     
				break;
			case DNS_IQ: printf("[Inverse Query]");
				break;
			case DNS_SR: printf("[Status Request]");
				break;	
			case DNS_NOT: printf("[Notify]");
				break;
			case DNS_UPT: printf("[Update]");
				break;
			default: printf("[Opcode]"); /* If doesnt match anything */
		}
		printf(" ");
		printf("id:%02x ",dns->dns_id);
		int offset=0;
		int z=0,i=0;
		//print of the question send to dns server , the website name and question type eg A=IPV4 
		//find the payload by add all the header together and print the payload out.
		printf("Qn:");
		while(*temp!=0){
			z=*temp	;
			for(i=0;i<z;i++){
				temp++;
				if(isprint(*temp)){
					printf("%c",*temp);			
				}			

			}
			if(*(temp+1)!=0)
				printf(".");
			temp++;	

		}
		printf(" ");

		while(*temp==0)
			temp++;
		switch(*temp){
			case 1: printf("[IPV4]");
				break;
			case 2: printf("[NS]");
				break;
			case 5:printf("[CNAME]");
				break;
			case 6:printf("[SOA]");
				break;
			case 12:printf("[PTR|]");
				break;
			case 15:printf("[MX]");
				break;
			case 16:printf("[TXT]");
				break;
			case 28:printf("[IPV6]");
				break;
			case 33:printf("[SRV]");
				break;
			case 41:printf("[OPT]");
				break;
			case 44:printf("[SSHFP]");
				break;
			case 99:printf("[SPF]");
				break;
			case 252:printf("[AXFR]");
				break;
			case 255:printf("[ALL]");
				break;

		}
		
		
	}
	
	
	printf("\n");
	//printf("\n");
	
	
}






//------------------------------------ OTHER IMPORTANT FUNCTION -------------------------------

void getPacket(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet){
	static int count = 1;   
 	static int i =0;              
	
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
		printARP(args,hdr,packet,ethernet,arp);
	}
	
	else if (ntohs (ethernet->ether_type) == ETHERTYPE_IP){
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			protocol="TCP";
			//printf(" Protocol :%s\n",protocol);
			
			sizeOfip = IP_HL(ip)*4;
			tcp = (struct Tcp*)(packet + SIZE_ETHERNET + sizeOfip);
			sizeOftcp = TH_OFF(tcp)*4;
			
			// If Source/Destination port == 53, then it is a DNS packet
			// th_sport, th_dport (tcp port variable names)
			if(ntohs(tcp->th_sport) == 53 || ntohs(tcp->th_dport) == 53){
				dns = (struct Dns*)(packet + SIZE_ETHERNET + sizeOfip + sizeOftcp);
				print_dns(args,hdr,packet,protocol,ip,dns);
			}else{// Else
				print_tcp(args,hdr,packet,protocol,ip);
			}
			break;
		case IPPROTO_UDP:
			protocol="UDP";
			//printf("   Protocol: %s\n",protocol);
			sizeOfip = IP_HL(ip)*4;
			udph = (struct udphdr*)(packet + SIZE_ETHERNET + sizeOfip);
			
			// If Source/Destination port == 53, then it is a DNS packet
			// source, dest (udp port variable names)
			// print_dns()
			if(ntohs(udph->source) == 53 || ntohs(udph->dest) == 53){
				dns = (struct Dns*)(packet + SIZE_ETHERNET + sizeOfip + SIZE_UDP);
				print_dns(args,hdr,packet,protocol,ip,dns);
			}else{// else print_udp
				print_udp(args,hdr,packet,protocol,ip);
			}
			
			break;
		case IPPROTO_ICMP:
			//printf("   Protocol: ICMP\n");
			break;
		case IPPROTO_IP:
			//printf("   Protocol: IP\n");
			break;
		default:
			
			break;
	}
	
	}
	
	
	
	

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
 
  
  dev=interface;
  printf("Sniffing on interface :%s\n",dev);
  handler=pcap_create(dev,errbuf);
  pcap_set_promisc(handler,1);
  pcap_activate(handler);
  if(handler == NULL)
  {
       printf("pcap_open_live(): %s\n",errbuf);
       exit(1);
  }
  if (pcap_datalink(handler) != DLT_EN10MB) {
		
	exit(EXIT_FAILURE);
  }
  if (pcap_lookupnet(dev, &netAdd, &maskAdd,errbuf) == -1) {
		
	netAdd = 0;
	maskAdd = 0;
  }

 
  pcap_loop(handler,0,getPacket,NULL);
  pcap_freecode(&filter);
  pcap_close(handler);


}

void writeToPcapFile(char *interface ,  char * filename){
		
  char *dev; 
  
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_dumper_t *pcapfile;
 

  pcap_t *handler;
  dev=interface;
  handler=pcap_create(dev,errbuf);
  pcap_set_promisc(handler,1);
  pcap_activate(handler);

    //pcap_dump_open is a libpcap function that open a file to which to write packets
  if ((pcapfile = pcap_dump_open(handler, filename)) == NULL) {
  	  printf("Error from pcap_dump_open() Please enter the correct interface\n"); 
    	  exit(1);
  }

  if ((pcap_loop(handler, 0, pcap_dump, (u_char *)pcapfile)) != 0) {
    	   fprintf(stderr, "Error from pcap_loop(): %s\n", pcap_geterr(handler)); 
    	   exit(1);
  }
  
  //close a savefile being written to
   pcap_dump_close(pcapfile); 
   pcap_close(handler);


}
//-------------------------------------- MAIN FUNCTION ----------------------------------

int main(int argc, char **argv)
{ 
	
	char *filename;
	
	char *dev;
	if(argc>=2){
	if(strcmp(argv[1],"-i")==0){
		if(argc<=4){
			printf("Starts Sniffing Packets\n");
			dev = argv[2];
			sniffPacket(dev);
		}
		else{

			if(strcmp(argv[3],"-w")==0){
				printf("Writing to Pcap File\n");
				if(argv[4]==NULL){

					printf("Please enter a filename\n");
					exit(1);

				}
				else{
					filename=argv[4];
					dev =argv[2];
		
					writeToPcapFile(dev,filename);
				}
			}	

		}
		

	}
	// -w meaning write to pcap file
	else if(strcmp(argv[1],"-w")==0) { 
		printf("Writing to Pcap File\n");
		
		if(argv[2]==NULL||strcmp(argv[2],"-i")==0||argc<=4){
			printf("Either the filename or the interface is missing . \n");
		        exit(1);

	
		}
		else{
			
			dev=argv[4];
			filename=argv[2];
			writeToPcapFile(dev,filename);

		}
	

	}
	else if( strcmp(argv[1],"man")==0){
		printf("Welcome to PCBIN man page\n");
		printf("==========================================================================\n");
		printf("[-i] interface(eth0/wlan0)  to sniff packet \n");
		printf("[-w] filname.pcap   [-i] interface(eth0/wlan0) to write to pcap\n");
		printf("[-i] interface(eth0/wlan0) [-w] filename.pcap to write to pcap\n");
		printf("Thats all please enjoy using PCBIN and have a nice day\n");


	}
	}
	else{
		printf("Please enter ./pcbin man for help\n");

	}
	
	
  
}
