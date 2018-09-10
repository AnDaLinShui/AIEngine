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
#ifndef SRC_PROTOCOLS_GPRS_GPRSPROTOCOL_H_
#define SRC_PROTOCOLS_GPRS_GPRSPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include "Protocol.h"
#include "Cache.h"
#include "GPRSInfo.h"
#include "flow/FlowManager.h"

namespace aiengine {

// Minimum GPRS header, for data and signaling
struct gprs_header {
        uint8_t 	flags;	// Flags 
        uint8_t 	type;   // Message type 
        uint16_t 	length; // Length of data
	uint32_t 	teid;
        uint8_t 	data[0];      
} __attribute__((packed));

// Minimum PDP Context Request
struct gprs_create_pdp_header {
	uint16_t 	seq_num;	// Sequence number
	uint8_t 	n_pdu;		// N-PDU 
	uint8_t 	code;
	uint8_t 	presence;
	union {
		struct { // For extension header
			uint8_t hdr[4];
			uint64_t imsi;
		} __attribute__((packed)) ext;
		struct { // Regular header
			uint64_t imsi;
			uint8_t hdr[4];
		} __attribute__((packed)) reg;
	} un;	
	uint8_t data[0]; 
} __attribute__((packed));

struct gprs_create_pdp_header_ext {
	uint8_t 	tid_data[5];
	uint8_t 	tid_control_plane[5];
	uint8_t 	nsapi[2];
	uint8_t 	data[0];
} __attribute__((packed));

// Routing area identity header 0x03
struct gprs_create_pdp_header_routing {
        uint16_t 	mcc;           // Mobile Country Code
        uint16_t 	mnc;           // Mobile Network Code
        uint16_t 	lac;
        uint8_t 	rac;
	uint8_t 	data[0];
} __attribute__((packed));

// GPRS Extension header 
struct gprs_ext_header {
        uint8_t 	length;        // Length of the extension
        uint16_t 	seq;           // Sequence number
        uint8_t 	next_hdr;
} __attribute__((packed));

#define GPRS_ECHO_REQUEST 1
#define GPRS_ECHO_RESPONSE 2 
#define CREATE_PDP_CONTEXT_REQUEST 16 
#define	CREATE_PDP_CONTEXT_RESPONSE 17
#define	UPDATE_PDP_CONTEXT_REQUEST 18
#define	UPDATE_PDP_CONTEXT_RESPONSE 19
#define	DELETE_PDP_CONTEXT_REQUEST 20
#define	DELETE_PDP_CONTEXT_RESPONSE 21 
#define	T_PDU 255 

class GPRSProtocol: public Protocol {
public:
    	explicit GPRSProtocol();
    	virtual ~GPRSProtocol() {}

	static const uint16_t id = 0;
	static const int header_size = 8; // GTP version 1
	int getHeaderSize() const { return header_size; }

	void processFlow(Flow *flow) override;
	bool processPacket(Packet& packet) override { return true; } // Nothing to process

	void statistics(std::basic_ostream<char>& out, int level) override;

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; }
        MultiplexerPtrWeak getMultiplexer() { return mux_;}

        void setFlowForwarder(WeakPointer<FlowForwarder> ff) { flow_forwarder_= ff; }
        WeakPointer<FlowForwarder> getFlowForwarder() { return flow_forwarder_; }

	void releaseCache() override; // Release the objets attached to the flows 

        void setHeader(const uint8_t *raw_packet) override {
       
		header_ = reinterpret_cast<const gprs_header*>(raw_packet); 
        }

	// Condition for say that a packet is GPRS 
	bool gprsChecker(Packet& packet); 

	void setIPProtocolType(uint16_t type) { ip_protocol_type_ = type; }	
	uint8_t getType() const { return header_->type; }
	uint16_t getHeaderLength() const { return ntohs(header_->length); }
	bool haveSequenceNumber() const { return (header_->flags & (1 << 1)); }
	bool haveExtensionHeader() const { return (header_->flags & (1 << 2)); }

        void increaseAllocatedMemory(int value) override;
        void decreaseAllocatedMemory(int value) override;

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	int64_t getCurrentUseMemory() const override;
	int64_t getAllocatedMemory() const override; 
	int64_t getTotalAllocatedMemory() const override; 

        void setDynamicAllocatedMemory(bool value) override;
        bool isDynamicAllocatedMemory() const override; 

	int32_t getTotalCacheMisses() const override;

	CounterMap getCounters() const override; 

	void releaseFlowInfo(Flow *flow) override;

#if defined(STAND_ALONE_TEST) || defined(TESTING)
        int32_t getTotalCreatePDPContextRequests() const { return total_create_pdp_ctx_requests_; }
        int32_t getTotalCreatePDPContextResponses() const { return total_create_pdp_ctx_responses_; }
        int32_t getTotalUpdatePDPContextRequests() const { return total_update_pdp_ctx_requests_; }
        int32_t getTotalUpdatePDPContextResponses() const { return total_update_pdp_ctx_responses_; }
        int32_t getTotalDeletePDPContextRequests() const { return total_delete_pdp_ctx_requests_; }
        int32_t getTotalDeletePDPContextResponses() const { return total_delete_pdp_ctx_responses_; }
	int32_t getTotalPdus() const { return total_tpdus_; }
	int32_t getTotalEchoRequets() const { return total_echo_requests_; }
	int32_t getTotalEchoResponses() const { return total_echo_responses_; }
#endif

private:

	void process_create_pdp_context(Flow *flow);

	Cache<GPRSInfo>::CachePtr gprs_info_cache_;
	const gprs_header *header_;
	int32_t total_create_pdp_ctx_requests_;
	int32_t total_create_pdp_ctx_responses_;
	int32_t total_update_pdp_ctx_requests_;
	int32_t total_update_pdp_ctx_responses_;
	int32_t total_delete_pdp_ctx_requests_;
	int32_t total_delete_pdp_ctx_responses_;
	int32_t total_tpdus_;
	int32_t total_echo_requests_;
	int32_t total_echo_responses_;
	uint16_t ip_protocol_type_;
	FlowManagerPtrWeak flow_mng_;
};

typedef std::shared_ptr<GPRSProtocol> GPRSProtocolPtr;

} // namespace aiengine 

#endif  // SRC_PROTOCOLS_GPRS_GPRSPROTOCOL_H_
