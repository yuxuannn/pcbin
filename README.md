"# pcbin/pcmon" 
-
-pcbin and pcmon is compiled on ARM architecture. Tested and no problems was found
-
-To compile pcbin for linux
-gcc pcbin.c -o pcbin -lpcap
-sudo ./pcbin -i interface to sniff packet 
-sudo  ./pcbin -w filename.pcap -i interface(eth0/wlan0) to write to pcap
-pcbin work for all rooted phones
-pcmon only works for NIC card that supports monitor mode and must be rooted

pcbin capabilities
- able to sniff UDP and TCP /IP packet 
-DNS packet
-ARP packet

pcmon capabilities
- sniff in monitor mode using radiotap header
-If the radiotap header length is not 40 , The signal strength signal noise and channel noise might be wrong 



Download libpcap-1.8.1  using the following steps/

-wget http://www.tcpdump.org/release/libpcap-1.8.1.tar.gz     /
tar xvf libpcap-1.8.1.tar.gz    /
cd libpcap-1.8.1   /

Configuring the libpcap file   /
 ./configure --prefix=/usr --host=arm-linux-gnueabi --with-pcap=linux   /
 make   /
 sudo make install  /
 arm-linux-gnueabi-gcc pcbin.c -static -s -o pcbin -lpcap -L/home/vmw_ubuntu/Desktop/libpcap-1.8.1
 /to compile for pcmon >> arm-linux-gnueabi-gcc pcmon.c -static -s -o pcmon -lpcap -lm -L/home/vmw_ubuntu/Desktop/libpcap-1.8.1
 added new function  writeToPcapFile(). Able to write raw packet in to pcap file
 To compile type sudo ./pcbin -w filename

  
# Credits
TCPDump (Tcpdump, Libpcap)
TCPDUMP and LIBPCAP are under a 3-clause BSD license (https://opensource.org/licenses/BSD-3-Clause)
http://www.tcpdump.org/ 
