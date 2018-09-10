/*
 * AIEngine a new generation network intrusion detection system.
 *
 * Copyright (C) 2013-2018  Luis Campo Giralte
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Ryadnology Team; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Ryadnology Team, 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <me@ryadpasha.com> 
 *
 */
#ifndef SRC_IPADDRESS_H_
#define SRC_IPADDRESS_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(__FREEBSD__) || defined(__OPENBSD__) || defined(__DARWIN__)
#include <sys/socket.h>
#define s6_addr32 __u6_addr.__u6_addr32
#else
#define s6_addr32 __in6_u.__u6_addr32
#endif

#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <cstring>

namespace aiengine {


class IPAddress {
public:
	struct v6_addrs {
		struct in6_addr src;
		struct in6_addr dst;
	};

	struct v4_addrs {
		struct in_addr src;
		struct in_addr dst;
	};

	typedef union {
    		struct v4_addrs v4;
    		struct v6_addrs v6;
	} in46_addr_t;

    	IPAddress() { reset(); }
    	virtual ~IPAddress() {}

	void reset(); 

	void setType(short type) { type_ = type; }
	short getType() const { return type_; } // 4 and 6 values

	unsigned long getHash(uint16_t srcport, uint16_t protocol, uint16_t dstport); 

	uint32_t getSourceAddress() const { return addrs.v4.src.s_addr; }
	uint32_t getDestinationAddress() const { return addrs.v4.dst.s_addr; }
	void setSourceAddress(uint32_t address) { addrs.v4.src.s_addr = address; type_ = IPPROTO_IP; }
	void setDestinationAddress(uint32_t address) { addrs.v4.dst.s_addr = address; type_ = IPPROTO_IP; }
	
	void setSourceAddress6(struct in6_addr *address);
	void setDestinationAddress6(struct in6_addr *address); 
	
	struct in6_addr *getSourceAddress6() const { return const_cast<struct in6_addr*>(&addrs.v6.src); }
	struct in6_addr *getDestinationAddress6() const { return const_cast<struct in6_addr*>(&addrs.v6.dst); }

	char* getSrcAddrDotNotation() const; 
        char* getDstAddrDotNotation() const; 
 
private:
	in46_addr_t addrs;
	short type_;
};

typedef std::shared_ptr<IPAddress> IPAddressPtr;

} // namespace aiengine

#endif  // SRC_IPADDRESS_H_
