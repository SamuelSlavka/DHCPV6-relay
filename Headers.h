#ifndef HEADERFILE_H
#define HEADERFILE_H

#include <net/if.h>
#include <pcap.h>
#include <array>
#include <iostream>
#include <string.h>

// ethernet headers are always exactly 14 bytes
#define SIZE_ETHERNET 14

// max hop of msg is 32 after msg is discated
#define HOP_COUNT_LIMIT 32

#define CLIENT_PORT 546

#define SERVER_PORT 547

//interface-id max len
#define INTERFACE_ID_LEN 48

struct ipv6_header
{
   uint32_t version : 4;
   uint32_t trafficClass : 8;
   uint32_t flowLabel : 20;
   uint16_t length;
   uint8_t nextHeader;
   uint8_t hopLimit;
   struct in6_addr src;
   struct in6_addr dst;
};

struct dhcpMessage
{
   uint8_t msgType;
   uint32_t transactionID : 24;
   uint8_t options[];
};

struct dhcpRelayMessage
{
   uint8_t msgType;
   uint8_t hopCount;
   std::array<uint16_t, 8> linkAddress;
   std::array<uint16_t, 8> peerAddress;
   uint16_t code;
   uint16_t length;
   uint8_t value[];
};

struct dhcpRelayMessageWithoutOption
{
   uint8_t msgType;
   uint8_t hopCount;
   std::array<uint16_t, 8> linkAddress;
   std::array<uint16_t, 8> peerAddress;
   uint8_t value[];
};

struct dhcpRelayOption
{
   uint16_t code;
   uint16_t length;
   uint8_t value[];
};

struct IAPREFIX
{
   uint16_t code;
   uint16_t length;
   uint32_t prefLifetime;
   uint32_t valiLifetime;
   uint8_t prefixLength;
   uint16_t ipv6Prefix[8];
   uint8_t options[];
};

struct IAADDR
{
   uint16_t code;
   uint16_t length;
   uint16_t ipv6Address[8];
   uint32_t prefLifetime;
   uint32_t valiLifetime;
   uint8_t options[];
};

struct IANAOption
{
   uint16_t code;
   uint16_t length;
   uint32_t IAID;
   uint32_t T1;
   uint32_t T2;
   IAADDR options;
};

struct IAPDOption
{
   uint16_t code;
   uint16_t length;
   uint32_t IAID;
   uint32_t T1;
   uint32_t T2;
   IAPREFIX options;
};

struct IATAOption
{
   uint16_t code;
   uint16_t length;
   uint32_t IAID;
   IAADDR options;
};

struct ClientLinkLayerAddress
{
   uint16_t code;
   uint16_t length;
   uint16_t linkLayerType;
   uint8_t value[];
};

typedef enum
{
   TYPE_SOLICIT = 1,
   TYPE_ADVERTISE = 2,
   TYPE_REQUEST = 3,
   TYPE_CONFIRM = 4,
   TYPE_RENEW = 5,
   TYPE_REBIND = 6,
   TYPE_REPLY = 7,
   TYPE_RELEASE = 8,
   TYPE_DECLINE = 9,
   TYPE_RECONFIGURE = 10,
   TYPE_INFO_REQUEST = 11,
   TYPE_RELAY_FORW = 12,
   TYPE_RELAY_REPL = 13
} messageType;

typedef enum
{
   OPTION_CLIENTID = 1,
   OPTION_SERVERID = 2,
   OPTION_IA_NA = 3,
   OPTION_IA_TA = 4,
   OPTION_IAADDR = 5,
   OPTION_ORO = 6,
   OPTION_PREFERENCE = 7,
   OPTION_ELAPSED_TIME = 8,
   OPTION_RELAY_MSG = 9,
   OPTION_AUTH = 11,
   OPTION_UNICAST = 12,
   OPTION_STATUS_CODE = 13,
   OPTION_RAPID_COMMIT = 14,
   OPTION_USER_CLASS = 15,
   OPTION_VENDOR_CLASS = 16,
   OPTION_VENDOR_OPTS = 17,
   OPTION_INTERFACE_ID = 18,
   OPTION_RECONF_MSG = 19,
   OPTION_RECONF_ACCEPT = 20,
   OPTION_IA_PD = 25,
   OPTION_IAPREFIX = 26,
   OPTION_CLIENT_LINKLAYER_ADDR = 79
} dhcpOptions;

#endif