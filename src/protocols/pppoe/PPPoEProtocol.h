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
#ifndef SRC_PROTOCOLS_PPPOE_PPPOEPROTOCOL_H_
#define SRC_PROTOCOLS_PPPOE_PPPOEPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

struct pppoe_header {
        uint8_t       	version_type;
        uint8_t       	code;
	uint16_t	session_id;
	uint16_t	length;
	uint16_t	protocol;
} __attribute__((packed));

#define ETHERTYPE_PPPOE		0x8864

#define PPP_DLL_IPV4 		0x0021
#define PPP_DLL_IPV6 		0x0057

class PPPoEProtocol: public Protocol {
public:
    	explicit PPPoEProtocol();
    	virtual ~PPPoEProtocol() {}

	static const uint16_t id = ETHERTYPE_PPPOE;	
	static const int header_size = sizeof(struct pppoe_header); 

	int getHeaderSize() const { return header_size;}

       	void processFlow(Flow *flow) override {} // This protocol dont generate any flow 
	bool processPacket(Packet &packet) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override {} // No need to free cache

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const pppoe_header*> (raw_packet);
	}

	// Condition for say that a packet is pppoe
	bool pppoeChecker(Packet &packet); 
	
	uint16_t getPayloadLength() const { return ntohs(header_->length); }
	uint16_t getProtocol() const { return ntohs(header_->protocol); }

	int64_t getCurrentUseMemory() const override { return sizeof(PPPoEProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(PPPoEProtocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(PPPoEProtocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	CounterMap getCounters() const override; 

private:
	const pppoe_header *header_;
};

typedef std::shared_ptr<PPPoEProtocol> PPPoEProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_PPPOE_PPPOEPROTOCOL_H_
