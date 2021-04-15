#include "Sniffer.h"



void Sniffer::configure() {

	char errbuf[PCAP_ERRBUF_SIZE];
	
	//check for active devices

	if(!in->interface.empty())
	{
		if (pcap_findalldevs(&dev, errbuf) != 0)
		{
			printf("%s\n", errbuf);
			return;
		}

		while ( dev != NULL )
		{
			if (dev->name == in->interface){
				break;
			}
			dev = dev->next;
			if (dev->next == NULL) {
				std::cerr << "Couldn't find interface: " << in->interface << ", opening: any";
				in->interface = "any";	
				break;
			}
		}
	}
	else
	{
		//No or wrong interface given, opening: any
		in->interface = "any";	
	}
	
	//open device for sniffing
	if ((handle = pcap_open_live(in->interface.c_str(), BUFSIZ, 1, 1000, errbuf)) == NULL ){
		 std::cerr << "Couldn't open device " << in->interface << std::endl;
		 return;
	}
 
	//compile and set filter for broadcast 
	if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
		 std::cerr << "Couldn't parse filter " << filter << " " << pcap_geterr(handle);
		 return;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		std::cerr << "Couldn't install filter " << filter << " " << pcap_geterr(handle);
		return;
	}
}

void Sniffer::startSniffing() {
	Callback callb;
	pid = fork();
	
	if (pid == 0)
	{
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

		sockaddr_in6 sockAddr = {}; 

		if( inet_pton(AF_INET6, in->server.c_str() , &sockAddr.sin6_addr.__in6_u) != 1)
		{
			perror("inet_pton failed"); 
			exit(EXIT_FAILURE); 
		}
		
		sockAddr.sin6_family = AF_INET6; 
		sockAddr.sin6_addr=in6addr_any;
		sockAddr.sin6_port = htons(547);

		socklen_t len = sizeof(sockAddr);

		if (bind(sockfd, (struct sockaddr *)&sockAddr,  sizeof(sockAddr))==-1) {
    		perror("bind failed"); 
			exit(EXIT_FAILURE); 
		}

		char recvline[1000];
		while(1) {
			fflush(stdout);
   			recvfrom(sockfd, recvline, 10000, 0, (struct sockaddr *)&sockAddr, &len);
		}
	}
	//sniffing calls callback functiuon
	if (pcap_loop(handle, -1, callb.callbackFunction, (u_char*)(in)) == -1) {
		std::cerr << "could not start pcap_loop";
		return;
	}
	
}

void Sniffer::freeResources() {
    kill(pid, SIGKILL);
	pcap_freecode(&fp);
	pcap_freealldevs(dev);
	pcap_close(handle);
}