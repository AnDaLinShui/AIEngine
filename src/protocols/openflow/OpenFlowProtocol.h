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
#ifndef SRC_PROTOCOLS_OPENFLOW_OPENFLOWPROTOCOL_H_
#define SRC_PROTOCOLS_OPENFLOW_OPENFLOWPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

struct openflow_header {
        uint8_t		version;
	uint8_t		type;
	uint16_t	length;
	uint32_t	tid;
} __attribute__((packed));

#define OF_VERSION_1 0x01
#define OF_VERSION_1_1 0x02
#define OF_VERSION_1_2 0x03
#define OF_VERSION_1_3 0x04

#define OFP_HELLO 0x00
#define OFP_FEATURE_REQUEST 0x05
#define OFP_FEATURE_REPLY 0x06 
#define OFP_SET_CONFIG 0x09 
#define OFP_PACKET_IN 0x0A
#define OFP_PACKET_OUT 0x0D

struct openflow_v1_pktin_header {
	openflow_header	hdr;
	uint32_t	bid;
	uint16_t	total_length;
	uint16_t	port;
	uint8_t		reason;
	uint8_t		padding;
	uint8_t		data[0];
} __attribute__((packed));

struct openflow_v13_pktin_header {
        openflow_header hdr;
        uint32_t        bid;
        uint16_t        total_length;
        uint8_t         reason;
        uint8_t         tbl_id;
	uint64_t 	cookie;
	uint16_t	match_type;
	uint16_t	match_length;
        uint8_t         data[0];
} __attribute__((packed));

struct openflow_v1_pktout_header {
	openflow_header	hdr;
	uint32_t	bid;
        uint16_t	in_port;
	uint16_t	actions_lenght;
	uint16_t	actions_type;
	uint16_t	action_length;
	uint16_t	out_port;
	uint16_t	max_length;
	uint8_t		data[0];
} __attribute__((packed));

struct openflow_v13_pktout_header {
	openflow_header	hdr;
        uint32_t        bid;
        uint32_t        in_port;
	uint16_t	actions_length;
	uint8_t		padd[6];
        uint8_t         data[0];
} __attribute__((packed));

// This class implements a minimum OpenFlow specification
// that is wide spread on Cloud environments

class OpenFlowProtocol: public Protocol {
public:
    	explicit OpenFlowProtocol();
    	virtual ~OpenFlowProtocol() {}

	static const uint16_t id = 0;	
	static const int header_size = sizeof(openflow_header);

	int getHeaderSize() const { return header_size; }

        void processFlow(Flow *flow) override;
        bool processPacket(Packet &packet) override { return true; } // Nothing to process

	void statistics(std::basic_ostream<char> &out, int level) override;

        void releaseCache() override {} // No need to free cache

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const openflow_header*> (raw_packet);
	}

	// Condition for say that a packet is openflow
	bool openflowChecker(Packet &packet); 

	uint8_t	getType() const { return header_->type; }
	uint16_t getLength() const { return ntohs(header_->length); }

	int64_t getCurrentUseMemory() const override { return sizeof(OpenFlowProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(OpenFlowProtocol); } 
	int64_t getTotalAllocatedMemory() const override { return sizeof(OpenFlowProtocol); } 

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	CounterMap getCounters() const override; 

#if defined(STAND_ALONE_TEST) || defined(TESTING)
        int32_t getTotalHellos() const { return total_ofp_hellos_; }
        int32_t getTotalFeatureRequest() const { return total_ofp_feature_requests_; }
        int32_t getTotalFeatureReplys() const { return total_ofp_feature_replys_; }
        int32_t getTotalSetConfigs() const { return total_ofp_set_configs_; }
        int32_t getTotalPacketsIn() const { return total_ofp_packets_in_; }
        int32_t getTotalPacketsOut() const { return total_ofp_packets_out_; }
#endif

private:
	void process_packet_in(MultiplexerPtr mux, Packet *packet);
	void process_packet_out(MultiplexerPtr mux, Packet *packet);

	const openflow_header *header_;
        int32_t total_ofp_hellos_;
        int32_t total_ofp_feature_requests_;
        int32_t total_ofp_feature_replys_;
        int32_t total_ofp_set_configs_;
        int32_t total_ofp_packets_in_;
        int32_t total_ofp_packets_out_;
};

typedef std::shared_ptr<OpenFlowProtocol> OpenFlowProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_OPENFLOW_OPENFLOWPROTOCOL_H_
