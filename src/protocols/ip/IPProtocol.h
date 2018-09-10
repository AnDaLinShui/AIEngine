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
#ifndef SRC_PROTOCOLS_IP_IPPROTOCOL_H_
#define SRC_PROTOCOLS_IP_IPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

namespace aiengine {

class IPProtocol: public Protocol {
public:
    	explicit IPProtocol(const std::string &name, const std::string &short_name);
    	explicit IPProtocol():IPProtocol("IPProtocol", "ip") {}
    	virtual ~IPProtocol(); 

	static const uint16_t id = ETHERTYPE_IP;
	static const int header_size = 20;

	int getHeaderSize() const { return header_size; }

       	void processFlow(Flow *flow) override; 
	bool processPacket(Packet &packet) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

        void releaseCache() override {} // No need to free cache

        void setHeader(const uint8_t *raw_packet) override {
        
                header_ = reinterpret_cast <const struct ip*> (raw_packet);
        }

	// Condition for say that a packet is IP 
	bool ipChecker(Packet &packet); 
	
	/* Fields from IP headers */
	uint8_t getTOS() const { return header_->ip_tos; }
    	uint8_t getTTL() const { return header_->ip_ttl; }
    	uint16_t getPacketLength() const { return ntohs(header_->ip_len); }
    	uint16_t getIPHeaderLength() const { return header_->ip_hl * 4; }
    	bool isIP() const { return header_ ? true : false ; }
    	bool isIPver4() const { return header_->ip_v == 4; }
    	bool isFragment() const { return (header_->ip_off & IP_MF); }
    	uint16_t getID() const { return ntohs(header_->ip_id); }
    	int getVersion() const { return header_->ip_v; }
    	uint16_t getProtocol () const { return header_->ip_p; }
    	uint32_t getSrcAddr() const { return header_->ip_src.s_addr; }
    	uint32_t getDstAddr() const { return header_->ip_dst.s_addr; }
    	const char* getSrcAddrDotNotation() const { return inet_ntoa(header_->ip_src); }
    	const char* getDstAddrDotNotation() const { return inet_ntoa(header_->ip_dst); }
    	uint32_t getIPPayloadLength() const { return getPacketLength() - getIPHeaderLength(); }

	int64_t getCurrentUseMemory() const override { return sizeof(IPProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(IPProtocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(IPProtocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	int32_t getTotalEvents() const override { return total_events_; }

	CounterMap getCounters() const override ; 

	void setAnomalyManager(SharedPointer<AnomalyManager> amng) override { anomaly_ = amng; }
private:
	const struct ip *header_;
	int32_t total_frag_packets_;
	int32_t total_events_;
	SharedPointer<AnomalyManager> anomaly_;
};

typedef std::shared_ptr<IPProtocol> IPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_IP_IPPROTOCOL_H_
