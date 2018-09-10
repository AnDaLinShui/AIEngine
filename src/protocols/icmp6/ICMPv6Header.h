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
#ifndef SRC_PROTOCOLS_ICMP_ICMPV6HEADER_H_
#define SRC_PROTOCOLS_ICMP_ICMPV6HEADER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <istream>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <cstring> // for std::memcpy

namespace aiengine {

/* LCOV_EXCL_START */

class ICMPv6Header {
public:
	ICMPv6Header(uint8_t type, uint8_t code):icmphdr_{type, code, 0} {}
	ICMPv6Header():ICMPv6Header(0, 0) {}
    	
	virtual ~ICMPv6Header() {}

        uint8_t getType() const { return icmphdr_.icmp6_type; }
        uint8_t getCode() const { return icmphdr_.icmp6_code; }
        uint16_t getSequence() const { return ntohs(icmphdr_.icmp6_seq); }

	void setId(uint16_t id) { icmphdr_.icmp6_id = id; }
	uint16_t getId() const { return ntohs(icmphdr_.icmp6_id); }
	
	void setChecksum(uint16_t check) { icmphdr_.icmp6_cksum = check; }
	uint16_t getChecksum() const { return ntohs(icmphdr_.icmp6_cksum); }

	friend std::ostream& operator<<(std::ostream &os, ICMPv6Header &hdr) {

		char *raw = reinterpret_cast<char*>(&hdr.icmphdr_);

		return os.write(raw,sizeof(hdr.icmphdr_));
	}

        friend std::istream& operator>>(std::istream &is, ICMPv6Header &hdr) {

                char *raw = reinterpret_cast<char*>(&hdr.icmphdr_);

                return is.read(raw,sizeof(hdr.icmphdr_));
        }

	struct icmp6_hdr *getHeader() { return &icmphdr_; }

	std::size_t size() const { return sizeof(struct icmp6_hdr); }

	void computeChecksum(struct ip6_hdr *iphdr, const uint8_t *payload, int payloadlen);

private:

	uint16_t checksum (uint16_t *addr, int len); 

        struct icmp6_hdr icmphdr_;
};

/* LCOV_EXCL_STOP */

} // namespace aiengine

#endif  // SRC_PROTOCOLS_ICMP_ICMPV6HEADER_H_
