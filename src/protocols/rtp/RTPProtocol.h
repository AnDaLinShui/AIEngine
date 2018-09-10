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
#ifndef SRC_PROTOCOLS_RTP_RTPPROTOCOL_H_
#define SRC_PROTOCOLS_RTP_RTPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include <arpa/inet.h>
#include "flow/FlowManager.h"
#include "Cache.h"

namespace aiengine {

#define RTP_VERSION 2 

struct rtp_header {
	uint8_t 	version;   	/* protocol version */
    	uint8_t 	payload_type;   /* payload type */
    	uint16_t 	seq;      	/* sequence number */
    	uint32_t 	ts;            /* timestamp */
	uint32_t 	ssrc;          /* synchronization source */
} __attribute__((packed));

class RTPProtocol: public Protocol {
public:
    	explicit RTPProtocol();
    	virtual ~RTPProtocol();

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(rtp_header);

	int getHeaderSize() const { return header_size;}

        void processFlow(Flow *flow) override;
        bool processPacket(Packet& packet) override { return true; } 

	void statistics(std::basic_ostream<char>& out, int level) override;

	void releaseCache() override {}

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const rtp_header*> (raw_packet);
	}

	// Condition for say that a packet is rtp
	bool rtpChecker(Packet &packet); 
	
	// Protocol specific
	uint8_t getVersion() const { return (header_->version >> 6); }
	bool getPadding() const { return (header_->version & (1 << 5)); } 
	uint8_t getPayloadType() const; 

	int64_t getCurrentUseMemory() const override { return sizeof(RTPProtocol); }
	int64_t getAllocatedMemory() const override;
	int64_t getTotalAllocatedMemory() const override;

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	CounterMap getCounters() const override; 

        void setAnomalyManager(SharedPointer<AnomalyManager> amng) override { anomaly_ = amng; }

	Flow *getCurrentFlow() const { return current_flow_; }
private:
	const rtp_header *header_;

	// Some statistics 

        Flow *current_flow_;
        SharedPointer<AnomalyManager> anomaly_;
#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<RTPProtocol> RTPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_RTP_RTPPROTOCOL_H_
