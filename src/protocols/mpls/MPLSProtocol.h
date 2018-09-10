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
#ifndef SRC_PROTOCOLS_MPLS_MPLSPROTOCOL_H_
#define SRC_PROTOCOLS_MPLS_MPLSPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

#ifndef ETHERTYPE_MPLS
#  ifndef ETH_P_MPLS_UC
#    define ETHERTYPE_MPLS 0x8847
#  else
#    define ETHERTYPE_MPLS ETH_P_MPLS_UC 
#  endif
#endif

namespace aiengine {

// A minimum MPLS Header
#define MPLS_HEADER_LEN    4

// MPLS header
// 20 bits for the label tag
// 3 bits experimental
// 1 bit for botom of label stack
// 8 bits for ttl  

class MPLSProtocol: public Protocol {
public:
    	explicit MPLSProtocol();
    	virtual ~MPLSProtocol() {}
	
	static const uint16_t id = ETHERTYPE_MPLS;		// MPLS Unicast traffic	
	static const int header_size = MPLS_HEADER_LEN; 	// one header 

	int getHeaderSize() const { return header_size; }

	void processFlow(Flow *flow) override {} // No flow to process
	bool processPacket(Packet &packet) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override {} // No need to free cache

        void setHeader(const uint8_t *raw_packet) override {
        
		header_ = raw_packet;
        }

	// Condition for say that a packet is MPLS 
	bool mplsChecker(Packet &packet); 

	int64_t getCurrentUseMemory() const override { return sizeof(MPLSProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(MPLSProtocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(MPLSProtocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	CounterMap getCounters() const override; 

private:
	const uint8_t *header_;
};

typedef std::shared_ptr<MPLSProtocol> MPLSProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_MPLS_MPLSPROTOCOL_H_
