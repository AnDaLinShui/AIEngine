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
#ifndef SRC_PROTOCOLS_QUIC_QUICPROTOCOL_H_
#define SRC_PROTOCOLS_QUIC_QUICPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

struct quic_header {
	uint8_t 	flags;
	uint64_t 	cid;
	uint32_t 	version;
	uint8_t 	pkt_number;
	uint8_t 	data[0];
} __attribute__((packed));

class QuicProtocol: public Protocol {
public:
    	explicit QuicProtocol();
    	virtual ~QuicProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(quic_header);

	int getHeaderSize() const { return header_size;}

        void processFlow(Flow *flow) override;
        bool processPacket(Packet &packet) override { return true; } 

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override {} // No need to free cache

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const quic_header*> (raw_packet);
	}

	// Condition for say that a packet is quic
	bool quicChecker(Packet &packet);
	
	int64_t getCurrentUseMemory() const override { return sizeof(QuicProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(QuicProtocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(QuicProtocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	CounterMap getCounters() const override; 

private:
	const quic_header *header_;
};

typedef std::shared_ptr<QuicProtocol> QuicProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_QUIC_QUICPROTOCOL_H_
