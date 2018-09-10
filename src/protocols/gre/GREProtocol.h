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
#ifndef SRC_PROTOCOLS_GRE_GREPROTOCOL_H_
#define SRC_PROTOCOLS_GRE_GREPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

#ifndef ETH_P_TEB
#define ETH_P_TEB	0x6558
#endif

struct gre_header {
        uint8_t		flags;   
        uint8_t		version;   
	uint16_t	protocol;	
} __attribute__((packed));


// This class implements the Generic Routing Encapsulation
// At the moment we just cover the Transparent ethernet bridging
// that is wide spread on Cloud environments

class GREProtocol: public Protocol {
public:
    	explicit GREProtocol();
    	virtual ~GREProtocol() {}

	static const uint16_t id = IPPROTO_GRE;	
	static const int header_size = sizeof(gre_header);

	int getHeaderSize() const { return header_size; }

        void processFlow(Flow *flow) override { /* No flow to manage */ }
        bool processPacket(Packet &packet) override; 

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override {} // No need to free cache

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const gre_header*> (raw_packet);
	}

	// Condition for say that a packet is gre
	bool greChecker(Packet &packet); 

	uint16_t getProtocol() const { return ntohs(header_->protocol); }

	int64_t getCurrentUseMemory() const override { return sizeof(GREProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(GREProtocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(GREProtocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	CounterMap getCounters() const override; 

private:
	const gre_header *header_;
};

typedef std::shared_ptr<GREProtocol> GREProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_GRE_GREPROTOCOL_H_
