# DHCPv6 relay agent

#### Dependencies:
  g++
  
  make

#### Compilation:
    make all
  
#### Execution:
    d6r -s server [-l] [-d] [-i interface]
   
   -s: DHCPv6 server IPv6 address.
   
   -l: Turn on logging with syslog.
   
   -i: Interface on which relay listens if not defined listens on any.
   
   -d: Turn on debug output to stdout
