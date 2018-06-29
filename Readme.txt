pc is used on linux to sniff packets. Current problem is writing to textfile has a bug where it print alot of extra bits

pack is compiled on ARM architecture. No problems known because havent been tested yet.

To compile pc
gcc packetSniffer.c -o pc -lpcap
sudo ./pc sniff

