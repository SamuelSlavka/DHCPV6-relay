

#include <netinet/ether.h>		//Provides declarations for ethrrenet header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <net/if.h>
#include <netdb.h>

#include <errno.h>
#include <iostream>
#include <vector>
#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>      
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <string.h> 
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>

#include <bitset>        

#include "Headers.h"

#define INET6LEN 128

struct input
{
	std::string server;
	bool logFlag;
	bool debugFlag;
	std::string interface;
	std::string lastAddress;
};

class Callback {
	private:
		const char *payload; /* Packet payload */
		const struct ethernetHeader *ethernet; /* The ethernet header */
		const struct ip *ip; /* The IP header */
		const struct udpHeader *udp; /* The TCP header */
    	
		int len = 0;	/* length of data in dhcp msg */

		

    	const struct ether_header* ethernetHeader;
		u_int size_ip;
		u_int size_udp;
		void addOption(dhcpRelayOption* option, dhcpOptions code, int optionLen, uint8_t value[], int allocBuffer);
		char* findAndDisectOption(dhcpOptions option, uint8_t* dhcpMsg, int length);
   	public:
  	    int resolvehelper(const char* hostname, int family, const char* service, sockaddr_storage* pAddr);
		static void callbackFunction(u_char* args, const struct pcap_pkthdr *header, const u_char* packet);
		void parsePacket(const struct pcap_pkthdr *header, const u_char *packet);

};