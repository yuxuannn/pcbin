"# pcbin" 
-pc is used on linux to sniff packets. Current problem is writing to textfile has a bug where it print alot of extra bits
-
-pack is compiled on ARM architecture. No problems known because havent been tested yet.
-
-To compile pc
-gcc packetSniffer.c -o pc -lpcap
-sudo ./pc sniff

recently updated packetSniffer.c  has the following features
1)output.txt is more organized  
2) able to sniff UDP and TCP /IP packet 

future updates
1) working on command line  so program will act like tcpdump.

