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
#ifndef SRC_PROTOCOLS_TCP_TCPPROTOCOL_H_
#define SRC_PROTOCOLS_TCP_TCPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "Protocol.h"
#include "flow/FlowManager.h"
#include "flow/FlowCache.h"
#include "FlowForwarder.h"
#include "Cache.h"
#include "TCPStates.h"
#include "TCPInfo.h"

namespace aiengine {

class TCPProtocol: public Protocol {
public:
    	explicit TCPProtocol(const std::string &name, const std::string &short_name);
    	explicit TCPProtocol():TCPProtocol(TCPProtocol::default_name, TCPProtocol::default_short_name) {}
    	virtual ~TCPProtocol(); 

	static constexpr char *default_name = "TCPProtocol";
	static constexpr char *default_short_name = "tcp";
	static const uint16_t id = IPPROTO_TCP;
	static const int header_size = 20;

	int getHeaderSize() const { return header_size; }

	void processFlow(Flow *flow) override {}; // This protocol generates flows but not for destination.
	bool processPacket(Packet &packet) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

        void releaseCache() override {} // No need to free cache

        void setHeader(const uint8_t *raw_packet) override {
        
                header_ = reinterpret_cast <const struct tcphdr*> (raw_packet);
        }

	// Condition for say that a packet is tcp 
	bool tcpChecker(Packet &packet); 
	
#if defined(__FREEBSD__) || (__OPENBSD__) || defined(__DARWIN__)
    	uint16_t getSourcePort() const { return ntohs(header_->th_sport); }
    	uint16_t getDestinationPort() const { return ntohs(header_->th_dport); }
    	uint32_t getSequence() const  { return ntohl(header_->th_seq); }
    	uint32_t getAckSequence() const  { return ntohl(header_->th_ack); }
    	bool isSyn() const { return (header_->th_flags & TH_SYN) == TH_SYN; }
    	bool isFin() const { return (header_->th_flags & TH_FIN) == TH_FIN; }
    	bool isAck() const { return (header_->th_flags & TH_ACK) == TH_ACK; }
    	bool isRst() const { return (header_->th_flags & TH_RST) == TH_RST; }
    	bool isPushSet() const { return (header_->th_flags & TH_PUSH) == TH_PUSH; }
    	uint16_t getTcpHdrLength() const { return header_->th_off * 4; }
#else
    	bool isSyn() const { return header_->syn == 1; }
    	bool isFin() const { return header_->fin == 1; }
    	bool isAck() const { return header_->ack == 1; }
    	bool isRst() const { return header_->rst == 1; }
    	bool isPushSet() const { return header_->psh == 1; }
    	uint32_t getSequence() const  { return ntohl(header_->seq); }
    	uint32_t getAckSequence() const  { return ntohl(header_->ack_seq); }
    	uint16_t getSourcePort() const { return ntohs(header_->source); }
    	uint16_t getDestinationPort() const { return ntohs(header_->dest); }
    	uint16_t getTcpHdrLength() const { return header_->doff * 4; }
#endif
    	uint8_t *getPayload() const { return (uint8_t*)header_ + getTcpHdrLength(); }

        void setFlowManager(FlowManagerPtr flow_mng) { flow_table_ = flow_mng; flow_table_->setTCPInfoCache(tcp_info_cache_); }
        FlowManagerPtr getFlowManager() { return flow_table_; }

        void setFlowCache(FlowCachePtr flow_cache) { flow_cache_ = flow_cache; } 
        FlowCachePtr getFlowCache() { return flow_cache_;}

	void setRegexManager(const SharedPointer<RegexManager>& rm) { rm_ = rm; }

        void createTCPInfos(int number) { tcp_info_cache_->create(number); }
        void destroyTCPInfos(int number) { tcp_info_cache_->destroy(number); }
#ifdef HAVE_REJECT_FUNCTION
	void addRejectFunction(std::function <void (Flow*)> reject) { reject_func_ = reject; } 
#endif
	Flow *getCurrentFlow() { return current_flow_; } // used just for testing pourposes

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
	void compute_tcp_state(TCPInfo *info, int32_t bytes);

	FlowManagerPtr flow_table_;
	FlowCachePtr flow_cache_;
	SharedPointer<RegexManager> rm_;
	Cache<TCPInfo>::CachePtr tcp_info_cache_;
	Flow *current_flow_;
	const struct tcphdr *header_;
	int32_t total_events_;
	int32_t total_flags_syn_;
	int32_t total_flags_synack_;
	int32_t total_flags_ack_;
	int32_t total_flags_rst_;
	int32_t total_flags_fin_;
#if defined(HAVE_TCP_QOS_METRICS)
        int32_t total_connection_setup_time_;
        int32_t total_server_reset_rate_;
        int32_t total_application_response_time_;
#endif
       	std::time_t last_timeout_;
       	std::time_t packet_time_;
#ifdef HAVE_REJECT_FUNCTION
	std::function <void (Flow*)> reject_func_;
#endif
	SharedPointer<AnomalyManager> anomaly_;
};

typedef std::shared_ptr<TCPProtocol> TCPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_TCP_TCPPROTOCOL_H_
