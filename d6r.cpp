/*
    -s: DHCPv6 server, na který je zaslán upravený DHCPv6 paket.
    -l: Zapnutí logování pomocí syslog zpráv
    -i: Rozhraní, na kterém relay naslouchá, všechna síťová rozhraní, pokud parametr není definován.
    -d: Zapnutí debug výpisu na standardní výstup
*/
#include "Sniffer.h"
#include <iostream>
#include <string>
#include <vector>

//d6r -s server [-l] [-d] [-i interface]

#define USAGE "Usage: d6r -s server [-l] [-d] [-i interface]"


#define BUF_SIZE 500
/*

    -s: DHCPv6 server, na který je zaslán upravený DHCPv6 paket.
    -l: Zapnutí logování pomocí syslog zpráv
    -i: Rozhraní, na kterém relay naslouchá, všechna síťová rozhraní, pokud parametr není definován.
    -d: Zapnutí debug výpisu na standardní výstup

*/
//https://stackoverflow.com/questions/1641182/how-can-i-catch-a-ctrl-c-event#1641223


Sniffer* sniffer;//(in);

void my_handler(int s){
    sniffer->freeResources();
    exit(1); 
};

int main(int argc, char *argv[])
{
    unsigned char buf[sizeof(struct in6_addr)];
	struct input in;


    if (getuid()){ 
        std::cerr << "Needs to be run as root" << std::endl;
        std::cerr << USAGE << std::endl;
        return 1;
    }

    if (argc < 2 || argc > 7) {
        std::cout << USAGE << std::endl;
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
		if (arg == "-s") {
            if (i + 1 < argc) { 
                if (inet_pton(AF_INET6, argv[i+1], buf) == 1)
    				in.server = argv[++i];    
                else {
                    std::cerr << "-s requires valid ipv6 address" << std::endl;
                    return 1;
                }
            } else { 
                std::cerr << "-s requires one argument" << std::endl;
                return 1;
            }  
        }
		else if (arg == "-l") {
            in.logFlag = true;
		}
		else if (arg == "-i") {
            if (i + 1 < argc) { 
                in.interface = argv[++i]; 
        	} else {
                std::cerr << "-i requires one argument." << std::endl;
                return 1;
        	}
		} else if (arg == "-d") {
            in.debugFlag = true;
        }
		else {
            std::cout << USAGE << std::endl;
        	return 1;
        }
    }
    




    
    sniffer = new Sniffer(in);
    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = my_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);

	sniffer->configure();
	sniffer->startSniffing();
	

	return 0;
}