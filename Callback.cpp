#include "Callback.h"

char* Callback::findAndDisectOption(dhcpOptions option, uint8_t* dhcpMsg, int length)
{

	dhcpRelayOption* opt= (dhcpRelayOption*)(dhcpMsg);

	int curPos = 0;
	do {
		if(ntohs(opt->code) == option){
			if (option == OPTION_RELAY_MSG)
				this->len = ntohs(opt->length);
			return (char*)opt;
		}

		curPos +=  ntohs(opt->length) + sizeof(dhcpRelayOption);
		opt = (dhcpRelayOption*) (opt->value + ntohs(opt->length));
	} while( length > curPos);
	return NULL;
}

bool getMacFromIP(uint8_t* ip, uint8_t* macAddress)
{
	// 0  1   2  3  4  5  6  7   8   9  10  11 12  13 14 15 
	//{fe 80}:00 00:00 00:00 00:[50] 74:f2 |ff:fe| b1:a8 7f
	std::fill( (char*)ip , (char*) ip+7 , 0);

	//mac not part of ip
	
	if(ip[11] != 0xFF && ip[12] != 0xFE)
		return false;
	
	ip[8] ^= 1UL << 1;
	
	macAddress[0] = 0x00;
	macAddress[1] = 0x01;
	macAddress[2] = ip[8];
	macAddress[3] = ip[9];
	macAddress[4] = ip[10];
	macAddress[5] = ip[13];
	macAddress[6] = ip[14];
	macAddress[7] = ip[15];

return true;
}
void Callback::addOption(dhcpRelayOption* option, dhcpOptions code, int optionLen, uint8_t value[], int allocBuffer)
{
	option->code = htons(code);
	option->length = htons(optionLen);
	memcpy(option->value, value, optionLen);
	//change msg length to exact size
	this->len = len - allocBuffer + optionLen;
}


void Callback::callbackFunction(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{	
	Callback clb;
	input* in = (input*)args;
	//dest
	sockaddr_in6 sockAddr = {}; 
	//src
	sockaddr_in6 srcaddr = {};

	//getting Global ip
	struct ifaddrs * ifAddrStruct=NULL;
	struct ifaddrs * ifa=NULL;
	void * tmpAddrPtr=NULL;

	//interface any does not have offset of 2b
	int offset = 2;
	if( in->interface != "any" ) 
		offset = 0;

	//header structures
	const struct ether_header* ethernetHeader;
    const struct ipv6_header* ipHeader;
    const struct udphdr* udpHeader;
    struct dhcpMessage* dhcpMsg;
	struct dhcpRelayMessage* dhcpRelayMsg;
	dhcpRelayOption* option;
	dhcpMessage* replyMsg;
	
	//additional info
	int optionLen = 0; /*length of value of current option */
	//flag confirming everithing went right
	bool  sendFlag = true;
	//interface ID
	char* intID = NULL;


	//length of current dhcp segment
	int lenDhcp = 0;
	
	//addresses
	char serverIP[INET6LEN];
	strcpy(serverIP, in->server.c_str());
	
	//char linkAddress[] =  "2001:db8:15a::1";
	//contains peer address 
	uint16_t sourceAddr[16] = {};
	//any address 
	uint32_t anyAddr[] = {0x00000000};
	//assigned mac address 
	uint8_t  macAddress[8]= {0x00,0x01,0x1a,0xb0,0x08,0x40,0xce,0x5d} ;


	//for searching for ipv6 adddress
	char* IAA;
	
	//reset variables
	memset(&ethernetHeader, 0, sizeof(ethernetHeader));
	memset(&ipHeader, 0, sizeof(ipHeader));
	memset(&udpHeader, 0, sizeof(udpHeader));
	memset(&dhcpMsg, 0, sizeof(dhcpMsg));
	memset(&dhcpRelayMsg, 0, sizeof(dhcpRelayMsg));

	//cast packet to haeaders
    ethernetHeader = (ether_header*)(packet);
	ipHeader = (ipv6_header*)(packet + sizeof(struct ether_header) + offset);
	udpHeader = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ipv6_header) + offset);
	dhcpMsg = (dhcpMessage*)(packet + sizeof(struct ether_header) + sizeof(struct ipv6_header) + sizeof(struct udphdr) + offset);
	
	lenDhcp = ntohs(udpHeader->len) - sizeof(uint16_t)*2 - sizeof(dhcpMessage);

	char addressBuffer2[INET6LEN];
	uint16_t asignedAddress[8];
	std::string output;
	uint8_t prefixLength = 0;


	switch(unsigned(dhcpMsg->msgType))
	{
	//Ignoring: ADVERTISE, REPLY, RECONFIGURE and RELAY-REPL types
	case TYPE_SOLICIT:	
	case TYPE_REQUEST:
	case TYPE_CONFIRM:	
	case TYPE_RENEW:	
	case TYPE_REBIND:	
	case TYPE_RELEASE:	
	case TYPE_DECLINE:	
	case TYPE_INFO_REQUEST:		
		//std::cout << "client"<< std::endl;	

		sendFlag = true;

		clb.len = ntohs(udpHeader->len) - sizeof(uint16_t)*2 - sizeof(dhcpMessage) + sizeof(dhcpRelayMessage)
				+ 2 * sizeof(dhcpRelayOption) + 8 + INTERFACE_ID_LEN;

		dhcpRelayMsg = (dhcpRelayMessage*)calloc(1, clb.len);
		if (dhcpRelayMsg == NULL){
			perror("calloc fail"); 
			exit(EXIT_FAILURE); 
		}

		dhcpRelayMsg->msgType = TYPE_RELAY_FORW;
		
		//start hop count
		dhcpRelayMsg->hopCount = 0;

		//setting link and peer address
		//https://tools.ietf.org/html/rfc8415#section-19.1.1			
		//get global address for link
		getifaddrs(&ifAddrStruct);
		
		//https://stackoverflow.com/questions/212528/get-the-ip-address-of-the-machine		
		for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
			if (!ifa->ifa_addr) {
				continue;
			}
			if (ifa->ifa_addr->sa_family == AF_INET6) { // check it is IP6
				tmpAddrPtr=&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
				char addressBuffer[INET6_ADDRSTRLEN];
				//select just prefix
				std::fill( (char*)tmpAddrPtr+8 , (char*) tmpAddrPtr+16 , 0 );
				inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);

				if(strncmp((char*)addressBuffer, "2001", 4) == 0){
					inet_pton(AF_INET6, addressBuffer, dhcpRelayMsg->linkAddress.begin());
				}
			} 
		}
		if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);
		
		// Copy the source address from the header
		// of the IP datagram peer-address
		//https://tools.ietf.org/html/rfc8415#section-19.1
		std::copy(std::begin(ipHeader->src.__in6_u.__u6_addr16), std::end(ipHeader->src.__in6_u.__u6_addr16), std::begin(dhcpRelayMsg->peerAddress));

		dhcpRelayMsg->code = htons(OPTION_RELAY_MSG);
		dhcpRelayMsg->length = htons(lenDhcp);
		//copy dhcp packet to relay msg option
		memcpy ( dhcpRelayMsg->value, (uint8_t*)dhcpMsg, lenDhcp +1);
		
		//https://tools.ietf.org/html/rfc6939
		//add option Client link-layer address
		option = (dhcpRelayOption*)(dhcpRelayMsg->value + lenDhcp);
		optionLen = sizeof(ethernetHeader->ether_shost)/sizeof(uint8_t)+2;


		//gets mac addr form link-local if avalible	if not gets mac from ethernet header
		if(getMacFromIP( (uint8_t*)ipHeader->src.__in6_u.__u6_addr8, macAddress))
			clb.addOption(option, OPTION_CLIENT_LINKLAYER_ADDR, optionLen,  macAddress, 8);
		else{ 	
			std::copy(std::begin(ethernetHeader->ether_shost), std::end(ethernetHeader->ether_shost), (macAddress)+2);
			clb.addOption(option, OPTION_CLIENT_LINKLAYER_ADDR, optionLen,  macAddress, 8);
		}

		//https://tools.ietf.org/html/rfc3315#section-22.18
		//add option Interface ID with interface name as ID
		option = (dhcpRelayOption*)(option->value + optionLen);
		optionLen = strlen(in->interface.c_str())*sizeof(char);
		clb.addOption(option, OPTION_INTERFACE_ID, optionLen, (uint8_t*)in->interface.c_str(), INTERFACE_ID_LEN);

		//https://tools.ietf.org/html/rfc4649
		//add option remote ID
		break;


	//Message received from another relay agent
	case TYPE_RELAY_FORW:
		return;
		// not required
		//std::cout << "relay agent" << std::endl;
		dhcpRelayMsg = (dhcpRelayMessage*)dhcpMsg;

		//https://tools.ietf.org/html/rfc3315#section-20
		std::copy(std::begin(ipHeader->src.__in6_u.__u6_addr32), std::end(ipHeader->src.__in6_u.__u6_addr32), std::begin(dhcpRelayMsg->peerAddress));

		//If the message received by the relay agent is a Relay-Forward message
		//and the hop-count in the message is greater than or equal to 32, the
		//relay agent discards the received message
		if(dhcpRelayMsg->hopCount >= HOP_COUNT_LIMIT) { 
			perror("hop count limit"); 
			sendFlag = false;
		} 
		//increment hop count
		dhcpRelayMsg->hopCount++;
		//https://tools.ietf.org/html/rfc3315#section-22.10
		//add option interface id
		break;


	//https://tools.ietf.org/html/rfc8415#section-19.2
	//Reply message 
	case TYPE_RELAY_REPL: 
		//std::cout << "reply" << std::endl;

		sendFlag = true;

		//length of dhcp msg
		clb.len = ntohs(udpHeader->len) - sizeof(uint16_t)*2 + sizeof(dhcpMessage);
		
		dhcpRelayMsg = (dhcpRelayMessage*)dhcpMsg;
		
		//coppy peeraddress
		std::copy(std::begin(dhcpRelayMsg->peerAddress), std::end(dhcpRelayMsg->peerAddress), std::begin(sourceAddr));

		//get pointer to interface-ID option
		intID = clb.findAndDisectOption(OPTION_INTERFACE_ID, ((dhcpRelayMessageWithoutOption*)dhcpRelayMsg)->value, clb.len );
		if (intID != NULL)
			intID = (char*)(((dhcpRelayOption*)intID)->value);

		//get pointer to msg option
		dhcpRelayMsg = (dhcpRelayMessage*)clb.findAndDisectOption(OPTION_RELAY_MSG, ((dhcpRelayMessageWithoutOption*)dhcpRelayMsg)->value, clb.len );
		if (dhcpRelayMsg == NULL){ 
			perror("could not find relay msg"); 
			exit(EXIT_FAILURE); 
		};

		//find assigned IP addr
		if( (IAA = clb.findAndDisectOption(OPTION_IA_NA, ((dhcpMessage*)((dhcpRelayOption*)(dhcpRelayMsg))->value)->options, (ntohs(((dhcpRelayOption*)(dhcpRelayMsg))->length)-4))) != NULL)
		{
			std::copy( std::begin(((IANAOption*) IAA)->options.ipv6Address), std::end(((IANAOption*) IAA)->options.ipv6Address), std::begin(asignedAddress));
			
		}
		else if( (IAA = clb.findAndDisectOption(OPTION_IA_TA, ((dhcpMessage*)((dhcpRelayOption*)(dhcpRelayMsg))->value)->options, (ntohs(((dhcpRelayOption*)(dhcpRelayMsg))->length)-4))) != NULL)
		{
			std::copy( std::begin(((IATAOption*) IAA)->options.ipv6Address), std::end(((IATAOption*) IAA)->options.ipv6Address), std::begin(asignedAddress));
		}
		else if( (IAA = clb.findAndDisectOption(OPTION_IA_PD, ((dhcpMessage*)((dhcpRelayOption*)(dhcpRelayMsg))->value)->options, (ntohs(((dhcpRelayOption*)(dhcpRelayMsg))->length)-4))) != NULL)
		{
			std::copy( std::begin(((IAPDOption*) IAA)->options.ipv6Prefix), std::end(((IAPDOption*) IAA)->options.ipv6Prefix), std::begin(asignedAddress));
			prefixLength = ((IAPDOption*) IAA)->options.prefixLength;
		}
		

		//debug and logging
		if(IAA != NULL) {
			if(inet_ntop(AF_INET6, asignedAddress, addressBuffer2, INET6_ADDRSTRLEN) == NULL) {
				return;
			}
			
			if( in->lastAddress == addressBuffer2 ){
				in->lastAddress.erase();
			}
			else
			{
		
				in->lastAddress = addressBuffer2;

				output  = addressBuffer2;
				if(prefixLength > 0) {
					output += "/";
					output += prefixLength;
				}
				output += ",";

				char* buffer = (char*)calloc(4, sizeof(char));
				for (int i = 3; i < 9; i++)
				{
					sprintf(buffer, "%02x", ((char*)(macAddress))[i] & 0xff);
					output += buffer;
					if(i!=8) {
						output += ":";
					}
				};
				free(buffer);

				if(in->debugFlag && ((dhcpMessage*)((dhcpRelayOption*)(dhcpRelayMsg))->value)->msgType == TYPE_REPLY) {
					std::cout << output << std::endl;
				}
				if(in->logFlag && ((dhcpMessage*)((dhcpRelayOption*)(dhcpRelayMsg))->value)->msgType == TYPE_REPLY) {
					openlog(NULL, 0, LOG_USER);
					syslog(LOG_INFO, "%s",output.c_str());
					closelog();
				}
			}
		};

		if( (replyMsg = (dhcpMessage*)calloc(1, clb.len +1)) == NULL ){
			perror("Calloc failiure");
			return;
		};
		
		//coppy msh without relay part
		memcpy(replyMsg, ((dhcpRelayOption*)dhcpRelayMsg)->value, clb.len );
		dhcpRelayMsg = (dhcpRelayMessage*) replyMsg;	
		break;
	default:
		//ignoring other types
		return;
	}

	// Creating socket file descriptor 
	int sockfd = 0; 
	if (( sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0 ) { 
		perror("socket creation failed"); 
		exit(EXIT_FAILURE); 
	} 
	//enable reuse of addresses
	int enable = 1;	
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    	perror("setsockopt(SO_REUSEADDR) failed");
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0)
    	perror("setsockopt(SO_REUSEPORT) failed");

    memset(&sockAddr, 0, sizeof(sockAddr));
    memset(&srcaddr, 0, sizeof(srcaddr));

	std::copy(std::begin(anyAddr), std::end(anyAddr), std::begin(srcaddr.sin6_addr.__in6_u.__u6_addr32));	

	//set reciever ip address if REPLY
	if ( unsigned(dhcpMsg->msgType) == TYPE_RELAY_REPL )
	{	
		std::copy(std::begin(sourceAddr), std::end(sourceAddr), std::begin(sockAddr.sin6_addr.__in6_u.__u6_addr16));		
	
		//set interface name
		int rc = 0;
		if( !in->interface.empty() && (in->interface != "any")) {
			std::cout << in->interface << " 1" << std::endl;
			rc = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (void*)(in->interface.c_str()), strlen(in->interface.c_str())*sizeof(char) );
		}
		else if(intID != NULL && strcmp((char*)intID,"any")) {
			std::cout << intID << std::endl;
			rc = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, intID, strlen(intID)*sizeof(char) );
		}
		if (rc) {
			perror("setsockopt error"); 
		}

		//DEST PORT
		sockAddr.sin6_port = htons(546); 
    	//SRC PORT
		srcaddr.sin6_port = htons(547);	
		
	}
	//set ip if FORW
	else 
	{
		if( inet_pton(AF_INET6, serverIP , &sockAddr.sin6_addr) != 1 )
		{
			perror("inet_pton failed"); 
			exit(EXIT_FAILURE); 
		}
		//DEST PORT	
		sockAddr.sin6_port = htons(547); 
    	//SRC PORT
		srcaddr.sin6_port = htons(546);		
	};

	sockAddr.sin6_family = AF_INET6; 
	srcaddr.sin6_family = AF_INET6;	

	//bind socket to source	for specific port	
	if (bind(sockfd, (struct sockaddr *) &srcaddr, sizeof(sockaddr_in6)) < 0) {
		perror("bind");
		exit(1);
	}

	if (sendFlag)
	{
		int resl = sendto(sockfd, (char *)(dhcpRelayMsg), clb.len, 0, (struct sockaddr *)&sockAddr, sizeof(struct sockaddr_in6));
		if (resl != -1) {
		//	std::cout << "packet sent" << std::endl;
		}
		else {
			perror("send error"); 
		}
	}

	//celanup
	free(dhcpRelayMsg);
	close(sockfd);
}