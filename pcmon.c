#ifndef LINUX_IEEE80211_H
#define LINUX_IEEE80211_H

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/types.h>
#include <stdint.h>
#include <math.h>
#include <string.h>




//------------------------------------------------------ FRAME HEADERS ----------------------------------------------------





//--------------------------------- 802.11 frame header
struct ieee80211_hdr {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
    uint8_t addr4[6];
} __attribute__ ((packed));

//--------------------------------- 802.11 radiotap header
// radiotap header is added by the adapter or fakeioctl
struct radiotap_hdr {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__ ((packed));



void printHexAsciiValueOfPayload(const u_char *payload) // function to see the full 802.11 packet in hexdecimal value
{
	const u_char *temp;
  	temp = payload;
	int i;
	int j =0;
	for(i =0; i < 56 ; i++){
		printf("%02x" , *temp);
		
		
		temp++;
		printf(" ");
		
	}

	printf("     ");
	
	temp=payload;
	
	 for(j=0 ; j<56 ; j++)
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
}

//---------------------------------------------------------- MAIN ------------------------------------------------------
void writeToPcapFile(char *interface ,  char * filename){
		
  char *dev; 
  
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_dumper_t *pcapfile;
 

  pcap_t *handler;
  

	


  dev=interface;
  
    printf("Start writing to pcap file\n");
    handler=pcap_create(dev,errbuf);
   
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

void pcapHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void printAddress(const u_char *packet);
void handleFrames(const u_char *packet,int type);
void handleControlFrames(const u_char *packet);

int main(int argc, char ** argv){ // main function

	int offset = 0;
	char *erbuf; // for errors (required)
	char *dev; // place to store device name
        char *filename;
	if(argc>=2){
	if(strcmp(argv[1],"-i")==0){
		
		
		if(argc<=4){
			printf("Starts Sniffing Packets\n");
			dev = argv[2]; // get wlan device from command line		
			pcap_t *handle;
			
			handle = pcap_open_live(dev, BUFSIZ, 0, 3000, erbuf);
			if(handle==NULL){ 
				printf("ERROR the interface is wrong or not entered\n");
				exit(1); 
			} 	

			pcap_loop(handle, 0, pcapHandler, NULL); 
		}
		else{
			if(strcmp(argv[3],"-w")==0){
				
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
	else if(strcmp(argv[1],"-w")==0){
		printf("Writing to Pcap File\n");
		if(argv[2]==NULL ||strcmp(argv[2],"-i")==0||argc<=4){
			printf("Either the filename or the interface is missing . \n");
		        exit(1);
		}
		else{
			char *filename=argv[2];
			dev =argv[4];
			writeToPcapFile(dev,filename);

		}
		


	}
	else if( strcmp(argv[1],"man")==0){
		printf("Welcome to PCMON man page\n");
		printf("==========================================================================\n");
		printf("[-i] interface(eth0/wlan0)  to sniff packet in monitor mode\n");
		printf("[-w] filname.pcap   [-i] interface(eth0/wlan0) to write to pcap\n");
		printf("[-i] interface(eth0/wlan0) [-w] filename.pcap to write to pcap\n");
		printf("Thats all please enjoy using PCMON and have a nice day\n");


	}
	}	
	else{
		printf("Please enter ./pcmon man for help\n");

	}
	
	return 0; 
	
}

void printAddress(const u_char *temp){
	
int i =0;	
	for(i=0;i<6;i++){
		if(i<5)		
			printf("%02x:",*temp);
		else
			printf("%02x",*temp);
		temp++;

	}
}

void handleFrames(const u_char *temp,int type){    //function to print out the different frame eg: management frame-0,data frame -1 
		
		temp++;
		int i;
		for(i=0;i<3;i++){
			temp++;
		}
		if(type==0)
			printf("Dst:");
		else if(type==1)
			printf("BSSID:");
		i =0;	
		for(i=0;i<6;i++){
			if(i<5)		
				printf("%02x:",*temp);
			else
				printf("%02x",*temp);
			temp++;	

		}
		printf(" ");
		if(type==0)
			printf("Src:");
		else if(type==1)
			printf("STA:");
			
		for(i=0;i<6;i++){
			if(i<5)		
				printf("%02x:",*temp);
			else
				printf("%02x",*temp);
			temp++;

		}
		printf(" ");
		if(type==0)
			printf("BSSID:");
		else if (type==1)
			printf("Dst:");
			
		for(i=0;i<6;i++){
			if(i<5)		
				printf("%02x:",*temp);
			else
				printf("%02x",*temp);
			temp++;

		}
				
		printf(" ");
		const u_char *temp1;
		temp1=temp;
		temp++;
		const u_char *temp2;
		temp2=temp;
		uint8_t array[2];
		array[0]=*temp1;
		array[1]=*temp2;
	 
  		uint16_t val=array[1] << 8| array[0] ;
	
	
		int max =15;
		int binaryArr[max];
		int j =0;
		for(j=0;j<15;j++){
			binaryArr[j]=0;
	
		}
		 i =0;
		for(j=max;j>=0;j--)     //because flag are just decimal  number convert to binary 010010 this means ack and syn.
		{    
			binaryArr[j]=val%2;    
			val=val/2;   
		
		//i++;
		}   
		
		int dec=0;
		 j=0;
		for(i=11;i>=0;i--){
			dec+= binaryArr[i]*pow(2,j);
			j++;
		
		}
		printf("SN:%d",dec);
		

}
void handleControlFrames(const u_char  *temp){
	temp++;                                        //use pointers to go to the specific point that has the information that we required
	int i ;
	for(i=0;i<3;i++){
		temp++;
	}
	printf("RAdd:");
	for(i=0;i<6;i++){
		if(i<5)		
			printf("%02x:",*temp);
		else
			printf("%02x",*temp);
		temp++;	

	}
	printf(" ");
	printf("TAdd:");
	for(i=0;i<6;i++){
		if(i<5)		
			printf("%02x:",*temp);
		else
			printf("%02x",*temp);
		temp++;	

	}
	
	temp++;
	temp++;
	printf(" ");
		const u_char *temp1;
		temp1=temp;
		temp++;
		const u_char *temp2;
		temp2=temp;
		uint8_t array[2];
		array[0]=*temp1;
		array[1]=*temp2;
	 
  		uint16_t val=array[1] << 8| array[0] ;
	
	
		int max =15;
		int binaryArr[max];
		int j =0;
		for(j=0;j<15;j++){
			binaryArr[j]=0;
	
		}
		 i =0;
		for(j=max;j>=0;j--)     //because flag are just decimal  number convert to binary 010010 this means ack and syn.
		{    
			binaryArr[j]=val%2;    
			val=val/2;   
		
		//i++;
		}   
		
		int dec=0;
		 j=0;
		for(i=11;i>=0;i--){
			dec+= binaryArr[i]*pow(2,j);
			j++;
		
		}
		printf("SN:%d",dec);
	
	



}
void pcapHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	

	const u_char *channel; // the frequency (in Mhz) of the AP Radio
	const u_char *rss; // received signal strength
	
	//right now the hardware of nexus 5 cause the radiotap header to be length 40  if the length of  radiotap header is not length 40, The signal strength,signal noise , and Cfreq(channel frequency ) 		  might be wrong.
	int offset = 0;
	struct radiotap_hdr *rtaphdr;
	rtaphdr = (struct radiotap_hdr *) packet;
	offset = rtaphdr->it_len;
	int i =0;
	const u_char *temp=packet;
	
	printf("Protocol=802.11 ");
	channel=packet+18;
	int cFreq=channel[1]*256+channel[0];
	printf("CFreq>%dMHZ ",cFreq);
	rss=packet+22;
	
	int Rss=rss[0]-256;                              //Antenna signal strength
	int Rsn=rss[1]-256;				 //Antenna signal noise
	printf("Rss>%d ",Rss);
	printf("Rsn>%d ",Rsn);
	for(i =0; i<offset;i++){
		temp++;

	}
	
	
	
	//printf("\n");

	
	
	if(*temp==180){
		printf("RTS ");
		temp++;
		for(i=0;i<3;i++){
			temp++;
		}
		printf("RAdd:");
		printAddress(temp);
		//printf(" \n");

	}
	else if (*temp==196){
		printf("CTS ");
		temp++;
		for(i=0;i<3;i++){
			temp++;
		}
		printf("RAdd:");
		printAddress(temp);
		//printf(" \n");



	}
	else if (*temp==212){
		printf("Ack ");
		temp++;
		int i =0;
		for(i=0;i<3;i++){
			temp++;
		}
		printf("RAdd:");
		printAddress(temp);
		//printf(" \n");
		
	

	}
	else if (*temp==72){
		printf("Null ");
		handleFrames(temp,1);
	}
	else if (*temp==148){
		printf ("BlkAck ");
		handleControlFrames(temp);
	}
	else if (*temp==132){
		printf("BlkAckReq ");
		handleControlFrames(temp);


	}
	else if (*temp==128){
		printf("BeaconFrame ");
		handleFrames(temp,0);
		
		
	}
	else if(*temp==136){
		printf("DataFrame ");
		handleFrames(temp,1);
	}
	else if (*temp==64){// probe request is a subtype of management frames
		printf("ProbeRequest ");
		handleFrames(temp,0);
	}
	else if(*temp==80){//probe response is a subtype of management frames
		printf("ProbeResponse ");
		handleFrames(temp,0);

	}
	else if(*temp==0){
		printf("AssoRequest ");
		handleFrames(temp,0);

	}
	else if(*temp==16){
		printf("AssoResponse ");
		handleFrames(temp,0);
	}
	else if (*temp==32){
		printf("ReAssoRequest ");
		handleFrames(temp,0);

	}
	else if(*temp==48){
		printf("ReAssoResponse ");
		handleFrames(temp,0);
	}
	else if(*temp==160){
		printf("Disassociation ");
		handleFrames(temp,0);
	
	}
	else if(*temp==176){
		printf("Authentication ");
		handleFrames(temp,0);

	}
	else if (*temp==192){
		printf("Deauthentication ");
		handleFrames(temp,0);

	}
	else if (*temp==208){

		printf("Action ");
		handleFrames(temp,0);
	}
	else if (*temp==224){
		printf("ActionNoAck ");
		handleFrames(temp,0);


	}



	printf("\n");
	
	
	

	return;
}
#endif /* LINUX_IEEE80211_H */
