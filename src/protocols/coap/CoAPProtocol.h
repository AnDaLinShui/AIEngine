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
#ifndef SRC_PROTOCOLS_COAP_COAPPROTOCOL_H_
#define SRC_PROTOCOLS_COAP_COAPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <arpa/inet.h>
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "CoAPInfo.h"
#include "flow/FlowManager.h"
#include "Cache.h"

namespace aiengine {

#define COAP_VERSION 1

struct coap_header {
	uint8_t 	vertype;	/* version, type and lenght */
	uint8_t 	code;		/* code */
    	uint16_t 	msgid;		/* msgid */
    	uint8_t 	data[0];
} __attribute__((packed)); 

struct coap_ext_header {
	uint8_t deltalength;
	uint8_t data[0];
} __attribute__((packed));

enum coap_type {
	COAP_TYPE_CONFIRMABLE = 0,
	COAP_TYPE_NON_CONFIRMABLE, 
	COAP_TYPE_ACKNOWLEDGEMENT  
};

enum coap_code {
	COAP_CODE_GET = 1,
	COAP_CODE_POST = 2, 
	COAP_CODE_PUT = 3,  
	COAP_CODE_DELETE = 4,
	COAP_CODE_RESPONSE_CONTENT = 69 
};

enum coap_options_number {
	COAP_OPTION_URI_HOST = 3,
	COAP_OPTION_LOCATION_PATH = 8,
	COAP_OPTION_URI_PATH = 11
};

class CoAPProtocol: public Protocol {
public:
    	explicit CoAPProtocol();
    	virtual ~CoAPProtocol();

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(coap_header);
	static const int MAX_URI_BUFFER = 1024;

	int getHeaderSize() const { return header_size;}

        void processFlow(Flow *flow) override;
        bool processPacket(Packet& packet) override { return true; } 

	void statistics(std::basic_ostream<char>& out, int level) override;

	void releaseCache() override;

        void setDomainNameManager(const SharedPointer<DomainNameManager>& dnm) override; 
        void setDomainNameBanManager(const SharedPointer<DomainNameManager>& dnm) override { ban_domain_mng_ = dnm; }

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const coap_header*> (raw_packet);
	}

	// Condition for say that a packet is coap
	bool coapChecker(Packet &packet); 
	
	// Protocol specific
	uint8_t getVersion() const { return header_->vertype >> 6; }
	uint8_t getType() const { return (header_->vertype >> 4) & 0x02; }
	uint8_t getTokenLength() const { return header_->vertype & 0x0F; }
	uint16_t getCode() const { return header_->code; }
	uint16_t getMessageId() const { return ntohs(header_->msgid); }

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

#if defined(PYTHON_BINDING)
        boost::python::dict getCache() const override;
	void showCache(std::basic_ostream<char> &out) const override;
#elif defined(RUBY_BINDING)
	VALUE getCache() const;
#endif
	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

        void setAnomalyManager(SharedPointer<AnomalyManager> amng) override { anomaly_ = amng; }

	void releaseFlowInfo(Flow *flow) override;

	Flow *getCurrentFlow() const { return current_flow_; }
private:

	int64_t compute_memory_used_by_maps() const;
	int32_t release_coap_info(CoAPInfo *info);
	void process_common_header(CoAPInfo *info, const uint8_t *payload, int length);
	
	void attach_host_to_flow(CoAPInfo *info, const boost::string_ref &hostname);
	void attach_uri(CoAPInfo *info, const boost::string_ref &uri);

	const coap_header *header_;

        Cache<CoAPInfo>::CachePtr info_cache_;
        Cache<StringCache>::CachePtr host_cache_;
        Cache<StringCache>::CachePtr uri_cache_;

        GenericMapType host_map_;
        GenericMapType uri_map_;

        SharedPointer<DomainNameManager> domain_mng_;
        SharedPointer<DomainNameManager> ban_domain_mng_;

	// Some statistics 
	int32_t total_events_;
        int32_t total_allow_hosts_;
        int32_t total_ban_hosts_;
        int32_t total_coap_gets_;
	int32_t total_coap_posts_;
	int32_t total_coap_puts_;
	int32_t total_coap_deletes_; 
	int32_t total_coap_others_; 

        FlowManagerPtrWeak flow_mng_;
        Flow *current_flow_;
        SharedPointer<AnomalyManager> anomaly_;
        char uri_buffer_[MAX_URI_BUFFER] = {0};
#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<CoAPProtocol> CoAPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_COAP_COAPPROTOCOL_H_
