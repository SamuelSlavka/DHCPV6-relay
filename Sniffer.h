#ifndef SNIFFER_H
#define SNIFFER_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>

#include <errno.h>
#include <sys/socket.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "Callback.h"

class Sniffer
{
private:
	int pid;		//receive process
	pcap_t *handle; // open device
	struct input *in;
	pcap_if_t *dev;		   // list of interfaces
	struct bpf_program fp; // The compiled filter
	std::string filter;	   // Filter expression
public:
	Sniffer(struct input &inp)
		: in(&inp), filter("port 546 or port 547") {}

	~Sniffer() = default;
	void configure();
	static void callbackFunction(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
	void startSniffing();
	void freeResources();
	static void my_handler(int s);
};

#endif