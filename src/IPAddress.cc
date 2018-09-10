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
#include "IPAddress.h"

namespace aiengine {

void IPAddress::reset() {
	type_ = IPPROTO_IP; 
	addrs = { 0 };
}

unsigned long IPAddress::getHash(uint16_t srcport, uint16_t protocol, uint16_t dstport) {
	unsigned long h;

	if (type_ == IPPROTO_IP) {
		h = addrs.v4.src.s_addr ^ (srcport * 7) ^ protocol ^ addrs.v4.dst.s_addr ^ dstport;
		// Other hash h = (ip4_src_ * 59 ) ^ (srcport << 16) ^ protocol ^ (ip4_dst_) ^ (dstport);
	} else {
		unsigned long sh1 = addrs.v6.src.s6_addr32[0];
		unsigned long sh2 = addrs.v6.src.s6_addr32[1];
		unsigned long sh3 = addrs.v6.src.s6_addr32[2];
		unsigned long sh4 = addrs.v6.src.s6_addr32[3];
		unsigned long dh1 = addrs.v6.dst.s6_addr32[0];
		unsigned long dh2 = addrs.v6.dst.s6_addr32[1];
		unsigned long dh3 = addrs.v6.dst.s6_addr32[2];
		unsigned long dh4 = addrs.v6.dst.s6_addr32[3];

		h = sh1 ^ sh2 ^ sh3 ^ sh4 ^ srcport ^ protocol ^ dh1 ^ dh2 ^ dh3 ^ dh4 ^ dstport; 
	} 
	return h;
}

void IPAddress::setSourceAddress6(struct in6_addr *address) {

	type_ = IPPROTO_IPV6;
	addrs.v6.src.s6_addr32[0] = address->s6_addr32[0];
	addrs.v6.src.s6_addr32[1] = address->s6_addr32[1];
	addrs.v6.src.s6_addr32[2] = address->s6_addr32[2];
	addrs.v6.src.s6_addr32[3] = address->s6_addr32[3];
}

void IPAddress::setDestinationAddress6(struct in6_addr *address) {

	type_ = IPPROTO_IPV6;
	addrs.v6.dst.s6_addr32[0] = address->s6_addr32[0];
	addrs.v6.dst.s6_addr32[1] = address->s6_addr32[1];
	addrs.v6.dst.s6_addr32[2] = address->s6_addr32[2];
	addrs.v6.dst.s6_addr32[3] = address->s6_addr32[3];
}
	
char* IPAddress::getSrcAddrDotNotation() const { 

	if (type_ == IPPROTO_IP) {
		in_addr a; 

		a.s_addr = addrs.v4.src.s_addr;
		return inet_ntoa(a); 
	} else {
		static char src_address_6_[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &addrs.v6.src, src_address_6_, INET6_ADDRSTRLEN);

		return src_address_6_;
	}
}

char* IPAddress::getDstAddrDotNotation() const {

	if (type_ == IPPROTO_IP) {
		in_addr a;

		a.s_addr = addrs.v4.dst.s_addr;
		return inet_ntoa(a);
	} else {
		static char dst_address_6_[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &addrs.v6.dst, dst_address_6_, INET6_ADDRSTRLEN);

		return dst_address_6_;
        }
}
 
} // namespace aiengine
