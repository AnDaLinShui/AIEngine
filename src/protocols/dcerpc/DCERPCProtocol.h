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
#ifndef SRC_PROTOCOLS_DCERPC_DCERPCPROTOCOL_H_
#define SRC_PROTOCOLS_DCERPC_DCERPCPROTOCOL_H_

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

#define DCERPC_VERSION 5 

struct dcerpc_header {
	uint8_t 	version;	/* protocol version */
	uint8_t 	version_minor; 	/* protocol version */
    	uint8_t 	packet_type;    /* packet type */
    	uint8_t 	packet_flags;   /* packet flags */
	uint32_t 	data_repr;     /* data representation */
	uint16_t 	frag_length;   /* fragment length */
	uint16_t 	auth_lenght;   /* auth length */
	uint32_t 	callid;
	uint8_t 	data[0];
} __attribute__((packed));

struct dcerpc_context_item_header {
        uint16_t 	context_id;	/* context id */
	uint16_t 	items;		/* items */
	uint8_t 	uuid[16];	/* uuid */
	uint16_t 	intface_ver; 	/* interface version mayor */
	uint16_t 	intface_minor; /* interface version minor */
        uint8_t 	data[0];
} __attribute__((packed));

//pubs.opengroup.org/onlinepubs/9629399/chap12.htm
enum dcerpc_unit_types {
        DCERPC_UNIT_REQUEST 		= 0x00, 
        DCERPC_UNIT_PING		= 0x01, 
        DCERPC_UNIT_RESPONSE		= 0x02, 
        DCERPC_UNIT_FAULT 		= 0x03,
        DCERPC_UNIT_WORKING		= 0x04, 
        DCERPC_UNIT_NOCALL		= 0x05, 
        DCERPC_UNIT_REJECT		= 0x06,
        DCERPC_UNIT_ACK			= 0x07,
        DCERPC_UNIT_CL_CANCEL		= 0x08,
        DCERPC_UNIT_FACK		= 0x09,
        DCERPC_UNIT_CANCEL_ACK		= 0x0A,
        DCERPC_UNIT_BIND		= 0x0B,
        DCERPC_UNIT_BIND_ACK		= 0x0C,
        DCERPC_UNIT_BIND_NAK		= 0x0D,
        DCERPC_UNIT_ALTER_CONTEXT	= 0x0E,
        DCERPC_UNIT_ALTER_CONTEXT_RESP	= 0x0F,
        DCERPC_UNIT_AUTH3		= 0x10,
        DCERPC_UNIT_SHUTDOWN 		= 0x11,
        DCERPC_UNIT_CO_CANCEL		= 0x12,
        DCERPC_UNIT_ORPHANED		= 0x13 
};

class DCERPCProtocol: public Protocol {
public:
    	explicit DCERPCProtocol();
    	virtual ~DCERPCProtocol();

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(dcerpc_header);

	int getHeaderSize() const { return header_size;}

        void processFlow(Flow *flow) override;
        bool processPacket(Packet& packet) override { return true; } 

	void statistics(std::basic_ostream<char>& out, int level) override;

	void releaseCache() override;

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const dcerpc_header*> (raw_packet);
	}

	// Condition for say that a packet is dcerpc
	bool dcerpcChecker(Packet &packet); 

	// Protocol specific methods
	uint8_t getPacketType() const { return header_->packet_type; }
	uint16_t getFragmentLength() const { return header_->frag_length; }
	
	int64_t getCurrentUseMemory() const override; 
	int64_t getAllocatedMemory() const override;
	int64_t getTotalAllocatedMemory() const override;

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	void increaseAllocatedMemory(int value) override; 
	void decreaseAllocatedMemory(int value) override; 

        void setDynamicAllocatedMemory(bool value) override; 
        bool isDynamicAllocatedMemory() const override; 

	CounterMap getCounters() const override; 

	Flow *getCurrentFlow() const { return current_flow_; }

	void releaseFlowInfo(Flow *flow) override;

#if defined(PYTHON_BINDING)
        void showCache(std::basic_ostream<char> &out) const override;
#endif

private:
	void update_unit_type(uint8_t type);
	void process_bind_message(DCERPCInfo *info, const uint8_t *payload, int length);

	void attach_uuid(DCERPCInfo *info, const boost::string_ref &uuid);
	int64_t compute_memory_used_by_maps() const; 
	int32_t release_dcerpc_info(DCERPCInfo *info); 

	const dcerpc_header *header_;

	// Some statistics 
	int32_t total_requests_;
	int32_t total_pings_;
	int32_t total_responses_;
	int32_t total_faults_;
	int32_t total_workings_;
	int32_t total_nocalls_;
	int32_t total_rejects_;
	int32_t total_acks_;
	int32_t total_cl_cancels_;
	int32_t total_facks_;
	int32_t total_cancel_acks_;
	int32_t total_binds_;
	int32_t total_bind_acks_;
	int32_t total_bind_naks_;
	int32_t total_alter_contexts_;
	int32_t total_alter_context_resps_;
	int32_t total_auth3s_;
	int32_t total_shutdonws_;
	int32_t total_co_cancels_;
	int32_t total_orphaneds_;
	int32_t total_others_;

        Flow *current_flow_;

        Cache<DCERPCInfo>::CachePtr info_cache_;
        Cache<StringCache>::CachePtr uuid_cache_;

        GenericMapType uuid_map_;

        FlowManagerPtrWeak flow_mng_;
#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<DCERPCProtocol> DCERPCProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_DCERPC_DCERPCPROTOCOL_H_
