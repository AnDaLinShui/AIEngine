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
#ifndef SRC_PROTOCOLS_ICMP6_ICMPV6PROTOCOL_H_
#define SRC_PROTOCOLS_ICMP6_ICMPV6PROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace aiengine {

class ICMPv6Protocol: public Protocol {
public:
    	explicit ICMPv6Protocol();
    	virtual ~ICMPv6Protocol() {}

	static const uint16_t id = IPPROTO_ICMP;
	static const int header_size = 8;

	int getHeaderSize() const { return header_size; }

	void processFlow(Flow *flow) override { /* No flow to manage */ } 
	bool processPacket(Packet &packet) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override {} // No need to free cache

        void setHeader(const uint8_t *raw_packet) override { 
               
		 header_ = reinterpret_cast <const icmp6_hdr*> (raw_packet);
        }

	// Condition for say that a packet is icmp 
	bool icmp6Checker(Packet &packet); 
	
        uint8_t getType() const { return header_->icmp6_type; }
        uint8_t getCode() const { return header_->icmp6_code; }
        uint16_t getId() const { return ntohs(header_->icmp6_id); }
        uint16_t getSequence() const { return ntohs(header_->icmp6_seq); }

	int64_t getCurrentUseMemory() const override { return sizeof(ICMPv6Protocol); }
	int64_t getAllocatedMemory() const override { return sizeof(ICMPv6Protocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(ICMPv6Protocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	CounterMap getCounters() const override;

private:
	const icmp6_hdr *header_;
        int32_t total_echo_request_;
        int32_t total_echo_replay_;
        int32_t total_destination_unreachable_;
        int32_t total_redirect_;
        int32_t total_router_advertisment_;
        int32_t total_router_solicitation_;
        int32_t total_ttl_exceeded_;
};

typedef std::shared_ptr<ICMPv6Protocol> ICMPv6ProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_ICMP6_ICMPV6PROTOCOL_H_
