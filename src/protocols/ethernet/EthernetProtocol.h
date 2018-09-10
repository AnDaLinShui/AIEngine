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
#ifndef SRC_PROTOCOLS_ETHERNET_ETHERNETPROTOCOL_H_
#define SRC_PROTOCOLS_ETHERNET_ETHERNETPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/socket.h>
#include "Multiplexer.h"
#include "Packet.h" 
#include "Protocol.h"
#include <arpa/inet.h>

#if defined(__OPENBSD__)
#include <net/if.h>
#include <netinet/if_ether.h>
#endif

namespace aiengine {

/// ETHER_MAX_LEN and ETHER_MIN_LEN are the limits for a ethernet header
/// Dont use the macro Check on the ETHER_IS_VALID_LEN macro

class EthernetProtocol: public Protocol {
public:
    	explicit EthernetProtocol(const std::string &name, const std::string &short_name);
	explicit EthernetProtocol():EthernetProtocol("EthernetProtocol", "ethernet") {}
    	virtual ~EthernetProtocol() {}

	static const uint16_t id = 0x0000; //Ethernet dont need a id
	static const int header_size = 14;

	int getHeaderSize() const { return header_size; }

	void processFlow(Flow *flow) override {} // This protocol dont generate any flow 
	bool processPacket(Packet &packet) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override {} // No need to free cache

	void setHeader(const uint8_t *raw_packet) override { 

		eth_header_ = reinterpret_cast <const struct ether_header*> (raw_packet);
	} 

	void setMaxEthernetLength(int value) { max_ethernet_len_ = value; }

	// Condition for say that a packet is ethernet 
	bool ethernetChecker(Packet &packet); 

	uint16_t getEthernetType() const { return ntohs(eth_header_->ether_type); }
	const struct ether_header *getEthernetHeader() const { return eth_header_; }

	int64_t getCurrentUseMemory() const override { return sizeof(EthernetProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(EthernetProtocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(EthernetProtocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	CounterMap getCounters() const override; 

private:
	int max_ethernet_len_;
	const struct ether_header *eth_header_;
};

typedef std::shared_ptr<EthernetProtocol> EthernetProtocolPtr;

} // namespace aiengine 

#endif  // SRC_PROTOCOLS_ETHERNET_ETHERNETPROTOCOL_H_
