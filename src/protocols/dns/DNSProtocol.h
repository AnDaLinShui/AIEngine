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
//#pragma GCC diagnostic ignored "-Wwrite-strings"
#ifndef SRC_PROTOCOLS_DNS_DNSPROTOCOL_H_ 
#define SRC_PROTOCOLS_DNS_DNSPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
// #include <netinet/ip.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <unordered_map>
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "DNSInfo.h"
#include "DNSQueryTypes.h"
#include "Cache.h"
#include "flow/FlowManager.h"

namespace aiengine {

struct dns_header {
        uint16_t	xid;           
	uint8_t 	rd :1; // recursion desired
    	uint8_t 	tc :1; // truncated message
    	uint8_t 	aa :1; // authoritive answer
    	uint8_t 	opcode :4; // purpose of message
    	uint8_t 	qr :1; // query/response flag
    	uint8_t 	rcode :4; // response code
    	uint8_t 	cd :1; // checking disabled
    	uint8_t 	ad :1; // authenticated data
    	uint8_t 	z :1; // its z! reserved
    	uint8_t 	ra :1; // recursion available
        uint16_t       	questions;       
        uint16_t       	answers;       
        uint16_t       	authorities;
	uint16_t	additionals;     
	uint8_t		data[0];
} __attribute__((packed));

struct dns_common_resource_record {
	uint16_t 	ptr;
	uint16_t 	type;
	uint16_t 	class_type;
	uint32_t	ttl;
	uint16_t	length;
	uint8_t		data[0];
} __attribute__((packed));

struct dns_txt_record {
	uint8_t 	length;
	uint8_t		data[0];
} __attribute__((packed));

class DNSProtocol: public Protocol {
public:
    	explicit DNSProtocol();
    	virtual ~DNSProtocol(); 

	static const uint16_t id = 0;
	static const int header_size = sizeof(dns_header);
	static const int MAX_DNS_BUFFER_NAME = 128;
	
	int getHeaderSize() const { return header_size; }

	bool processPacket(Packet &packet) override { return true; }
	void processFlow(Flow *flow) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

        void setDomainNameManager(const SharedPointer<DomainNameManager> &dm) override; 
        void setDomainNameBanManager(const SharedPointer<DomainNameManager> &dm) override { ban_domain_mng_ = dm;}

	void releaseCache() override; 

        void setHeader(const uint8_t *raw_packet) override {
                
		header_ = reinterpret_cast <const dns_header*> (raw_packet);
        }

	// Condition for say that a payload is DNS 
	bool dnsChecker(Packet &packet); 
	
	void increaseAllocatedMemory(int value) override;
	void decreaseAllocatedMemory(int value) override;

	int32_t getTotalAllowQueries() const { return total_allow_queries_;}
	int32_t getTotalBanQueries() const { return total_ban_queries_;}

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

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

	void setAnomalyManager(SharedPointer<AnomalyManager> amng) override { anomaly_ = amng; }

	void releaseFlowInfo(Flow *flow) override;

#if defined(STAND_ALONE_TEST) || defined(TESTING)
        int32_t getTotalQueries() const { return total_queries_; }
        int32_t getTotalResponses() const { return total_responses_; }
        int32_t getTotalQuestions() const { return ntohs(header_->questions); }
        int32_t getTotalAnswers() const { return ntohs(header_->answers); }
#endif

private:

	int64_t compute_memory_used_by_maps() const;
	bool parse_response_answer(DNSInfo *info, const uint8_t *ptr, int answers);
	void attach_dns_to_flow(DNSInfo *info, boost::string_ref &domain, uint16_t qtype);
	void update_query_types(uint16_t type);
	void handle_standard_query(DNSInfo *info, int length);
	int parse_query_name(Flow *flow, int length);
	void handle_standard_response(DNSInfo *info, int length);
	int extract_domain_name(const uint8_t *ptr, int length);

	const dns_header *header_;

        int32_t total_allow_queries_;
        int32_t total_ban_queries_;
	int32_t total_queries_;
	int32_t total_responses_;
	int32_t total_events_;

	// Some statistics of the Dns Types
	int32_t total_dns_type_a_;
	int32_t total_dns_type_ns_;
	int32_t total_dns_type_cname_;
	int32_t total_dns_type_soa_;
	int32_t total_dns_type_ptr_;
	int32_t total_dns_type_mx_;
	int32_t total_dns_type_txt_;
	int32_t total_dns_type_aaaa_;
	int32_t total_dns_type_loc_;
	int32_t total_dns_type_srv_;
       	int32_t total_dns_type_ds_;
       	int32_t total_dns_type_sshfp_;
	int32_t total_dns_type_dnskey_;
	int32_t total_dns_type_ixfr_;
	int32_t total_dns_type_any_;
	int32_t total_dns_type_others_;

	int16_t current_length_;
	int16_t current_offset_;

	Cache<DNSInfo>::CachePtr info_cache_;
	Cache<StringCache>::CachePtr name_cache_;

	GenericMapType domain_map_;

	SharedPointer<DomainNameManager> domain_mng_;
	SharedPointer<DomainNameManager> ban_domain_mng_;

	FlowManagerPtrWeak flow_mng_;
	Flow *current_flow_;	
	SharedPointer<AnomalyManager> anomaly_;
	char dns_buffer_name_[MAX_DNS_BUFFER_NAME] = {0};
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<DNSProtocol> DNSProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_DNS_DNSPROTOCOL_H_
