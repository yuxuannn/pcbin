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

Download libpcap-1.8.1  using the following steps
-wget http://www.tcpdump.org/release/libpcap-1.8.1.tar.gz
tar xvf libpcap-1.8.1.tar.gz
cd libpcap-1.8.1

Configuring the libpcap file
 ./configure --prefix=/usr --host=arm-linux-gnueabi --with-pcap=linux
 make 
 sudo make install
 arm-linux-gnueabi-gcc EdittedpacketSniffer.c -o pcbin -lpcap -L/home/vmw_ubuntu/Desktop/libpcap-1.8.1
  

