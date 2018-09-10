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
#ifndef SRC_PROTOCOLS_IP6_IPV6PROTOCOL_H_
#define SRC_PROTOCOLS_IP6_IPV6PROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

// Dont change the order of the headers here
#include "Protocol.h"
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <iostream>

namespace aiengine {

class IPv6Protocol: public Protocol {
public:
    	explicit IPv6Protocol();
    	virtual ~IPv6Protocol();

	static const uint16_t id = ETHERTYPE_IPV6;
	static const int header_size = 40;

	int getHeaderSize() const { return header_size; }

	void processFlow(Flow *flow) override {}; // This protocol dont generate any flow 
        bool processPacket(Packet &packet) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

        void releaseCache() override {} // No need to free cache

        void setHeader(const uint8_t *raw_packet) override {
        
                header_ = reinterpret_cast <const ip6_hdr*> (raw_packet);
        }

        // Condition for say that a packet is IPv6
        bool ip6Checker(Packet &packet); 

	bool isIPver6() const { return (header_->ip6_vfc >> 4) == 6 ; }
	uint8_t getProtocol() const { return header_->ip6_nxt; }
	uint8_t getL7Protocol() const { return l7_next_protocol_; }
    	uint16_t getPayloadLength() const { return ntohs(header_->ip6_plen); }
    	char* getSrcAddrDotNotation() const ; 
    	char* getDstAddrDotNotation() const ; 
	struct in6_addr *getSourceAddress() const { return (struct in6_addr*)&(header_->ip6_src); }
	struct in6_addr *getDestinationAddress() const { return (struct in6_addr*)&(header_->ip6_dst); }
	uint8_t *getPayload() const { return (uint8_t*)header_ + 40; }

	int64_t getCurrentUseMemory() const override { return sizeof(IPv6Protocol); }
	int64_t getAllocatedMemory() const override { return sizeof(IPv6Protocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(IPv6Protocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	int32_t getTotalEvents() const override { return total_events_; }

	CounterMap getCounters() const override; 

	void setAnomalyManager(SharedPointer<AnomalyManager> amng) override { anomaly_ = amng; }

#if defined(STAND_ALONE_TEST) || defined(TESTING)
        int32_t getTotalFragPackets() const { return total_frag_packets_; }
        int32_t getTotalNoHeaderPackets() const { return total_no_header_packets_; }
        int32_t getTotalExtensionHeaderPackets() const { return total_extension_header_packets_; }
        int32_t getTotalOtherExtensionHeaderPackets() const { return total_other_extension_header_packets_; }
#endif

private:
	const ip6_hdr *header_;
	uint8_t l7_next_protocol_;
	int32_t total_frag_packets_;
	int32_t total_no_header_packets_;
	int32_t total_extension_header_packets_;
	int32_t total_other_extension_header_packets_;
	int32_t total_events_;
	SharedPointer<AnomalyManager> anomaly_;
};

typedef std::shared_ptr<IPv6Protocol> IPv6ProtocolPtr;

} // namespace aiengine

#endif // SRC_PROTOCOLS_IP6_IPV6PROTOCOL_H_
