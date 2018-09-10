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
#pragma GCC diagnostic ignored "-Wwrite-strings"
#ifndef SRC_PROTOCOLS_UDP_UDPPROTOCOL_H_
#define SRC_PROTOCOLS_UDP_UDPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Multiplexer.h"
#include "Protocol.h"
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "flow/FlowManager.h"
#include "flow/FlowCache.h"
#include "FlowForwarder.h"
#include "DatabaseAdaptor.h"

namespace aiengine {

class UDPProtocol: public Protocol {
public:
    	explicit UDPProtocol(const std::string &name, const std::string &short_name);
	explicit UDPProtocol():UDPProtocol(UDPProtocol::default_name, UDPProtocol::default_short_name) {}
    	virtual ~UDPProtocol();

        static constexpr char *default_name = "UDPProtocol";
        static constexpr char *default_short_name = "udp";
	static const uint16_t id = IPPROTO_UDP;
	static const int header_size = 8;

	int getHeaderSize() const { return header_size; }

	void processFlow(Flow *flow) override {} // This protocol generates flows but not for destination.
	bool processPacket(Packet &packet) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

        void releaseCache() override {} // No need to free cache

        void setHeader(const uint8_t *raw_packet) override {
        
                header_ = reinterpret_cast <const udphdr*> (raw_packet);
        }

	// Condition for say that a packet is UDP 
	bool udpChecker(Packet &packet); 
	
#if defined(__FREEBSD__) || defined(__OPENBSD__) || defined(__DARWIN__)
	uint16_t getSourcePort() const { return ntohs(header_->uh_sport); }
    	uint16_t getDestinationPort() const { return ntohs(header_->uh_dport); }
    	uint16_t getLength() const { return ntohs(header_->uh_ulen); }
    	unsigned int getPayloadLength() const { return ntohs(header_->uh_ulen) - sizeof(struct udphdr); }
#else
	uint16_t getSourcePort() const { return ntohs(header_->source); }
    	uint16_t getDestinationPort() const { return ntohs(header_->dest); }
    	uint16_t getLength() const { return ntohs(header_->len); }
    	unsigned int getPayloadLength() const { return ntohs(header_->len) - sizeof(udphdr); }
#endif
    	unsigned int getHeaderLength() const { return sizeof(struct udphdr); }
	uint8_t* getPayload() const { return (uint8_t*)header_ +getHeaderLength(); }

	void setFlowManager(FlowManagerPtr flow_mng) { flow_table_ = flow_mng;}
	FlowManagerPtr getFlowManager() { return flow_table_; }
	void setFlowCache(FlowCachePtr flow_cache) { flow_cache_ = flow_cache;}
	FlowCachePtr getFlowCache() { return flow_cache_;}

#ifdef HAVE_REJECT_FUNCTION
	void addRejectFunction(std::function <void (Flow*)> reject) { reject_func_ = reject; }
#endif

	void setRegexManager(const SharedPointer<RegexManager> &rm) { rm_ = rm;}

	Flow *getCurrentFlow() { return current_flow_;} // used just for testing pourposes

        void increaseAllocatedMemory(int value) override;
        void decreaseAllocatedMemory(int value) override;

	int64_t getCurrentUseMemory() const override; 
	int64_t getAllocatedMemory() const override;
	int64_t getTotalAllocatedMemory() const override;

        void setDynamicAllocatedMemory(bool value) override; 
        bool isDynamicAllocatedMemory() const override;

	int32_t getTotalCacheMisses() const override;
	int32_t getTotalEvents() const override { return total_events_; }

	CounterMap getCounters() const override; 

	void setAnomalyManager(SharedPointer<AnomalyManager> amng) override { anomaly_ = amng; }

private:
	SharedPointer<Flow> getFlow(const Packet &packet); 

	FlowManagerPtr flow_table_;
	FlowCachePtr flow_cache_;
	SharedPointer<RegexManager> rm_;
	Flow *current_flow_;
	const udphdr *header_;
	int32_t total_events_;
	time_t last_timeout_;
	time_t packet_time_;

#ifdef HAVE_REJECT_FUNCTION
	std::function <void (Flow*)> reject_func_;
#endif
	SharedPointer<AnomalyManager> anomaly_;
};

typedef std::shared_ptr<UDPProtocol> UDPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_UDP_UDPPROTOCOL_H_
