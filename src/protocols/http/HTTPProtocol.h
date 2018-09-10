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
// #pragma GCC diagnostic ignored "-Wwrite-strings"
#ifndef SRC_PROTOCOLS_HTTP_HTTPPROTOCOL_H_
#define SRC_PROTOCOLS_HTTP_HTTPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include "StringCache.h"
#include <unordered_map>
#include "FlowRegexEvaluator.h"
#include "regex/Regex.h"
#include "flow/FlowManager.h"

namespace aiengine {

// Methods and response with statistics
typedef std::tuple<const char*,int32_t> HttpResponseType;
typedef std::function <bool (HTTPInfo*, boost::string_ref &parameter)> HttpParameterHandler;

class HTTPProtocol: public Protocol {
public:
    	explicit HTTPProtocol();
    	virtual ~HTTPProtocol();

	struct string_hasher {
        	size_t operator()(boost::string_ref const& s) const {

                	return boost::hash_range(s.begin(), s.end());
        	}
	};

	static const uint16_t id = 0;
	static constexpr int header_size = sizeof("GET / HTTP/1.0") - 1; // Size of the minimum http header 

	int getHeaderSize() const { return header_size; }

	int64_t getTotalL7Bytes() const { return total_l7_bytes_; }

	bool processPacket(Packet &packet) override { /* Nothing to process at packet level*/ return true; }
	void processFlow(Flow *flow) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

        void setDomainNameManager(const SharedPointer<DomainNameManager> &dm) override; 
        void setDomainNameBanManager(const SharedPointer<DomainNameManager> &dm) override { ban_domain_mng_ = dm; }

	void releaseCache() override; // Three caches will be clear 

        void setHeader(const uint8_t *raw_packet) override {
        
                header_ = raw_packet;
        }

        // Condition for say that a payload is HTTP 
        bool httpChecker(Packet &packet); 
        
	const uint8_t *getPayload() { return header_; }

	void increaseAllocatedMemory(int value) override;
	void decreaseAllocatedMemory(int value) override;
	
	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	int32_t getTotalAllowHosts() const { return total_allow_hosts_;}
	int32_t getTotalBanHosts() const { return total_ban_hosts_;}

	int16_t getHTTPHeaderSize() const { return http_header_size_; }
	int64_t getAllocatedMemory() const override;
	int64_t getTotalAllocatedMemory() const override;
	int64_t getCurrentUseMemory() const override;

        void setDynamicAllocatedMemory(bool value) override; 
        bool isDynamicAllocatedMemory() const override;

	int32_t getTotalCacheMisses() const override;
	int32_t getTotalEvents() const override;

	Flow *getCurrentFlow() { return current_flow_;} // used just for testing pourposes

	CounterMap getCounters() const override; 

#if defined(PYTHON_BINDING)
	boost::python::dict getCache() const override; 
	void showCache(std::basic_ostream<char> &out) const override;
#elif defined(RUBY_BINDING)
	VALUE getCache() const; 
#endif

	void setAnomalyManager(SharedPointer<AnomalyManager> amng) override { anomaly_ = amng; }

#if defined(STAND_ALONE_TEST) || defined(TESTING)
	int16_t getHTTPMethodSize() { return http_method_size_; }
	int16_t getHTTPParametersSize() { return http_parameters_size_; }

	int32_t getTotalGets() const { return total_gets_; }
	int32_t getTotalPosts() const { return total_posts_; }
	int32_t getTotalHeads() const { return total_heads_; }
	int32_t getTotalConnects() const { return total_connects_; }
	int32_t getTotalOptions() const { return total_options_; }
	int32_t getTotalPuts() const { return total_puts_; }
	int32_t getTotalDeletes() const { return total_deletes_; }
	int32_t getTotalTraces() const { return total_traces_; }
#endif

	void releaseFlowInfo(Flow *flow) override;

private:

	int64_t compute_memory_used_by_maps() const;
	int process_requests_and_responses(HTTPInfo *info, const boost::string_ref &header);

	void process_payloadl7(Flow * flow, HTTPInfo *info, const boost::string_ref &payloadl7);
	void attach_uri(HTTPInfo *info, const boost::string_ref &uri);
	void attach_host(HTTPInfo *info, const boost::string_ref &host);
	void attach_useragent(HTTPInfo *info, const boost::string_ref &ua);
	void attach_content_type(HTTPInfo *info, const boost::string_ref &ct);
	void attach_filename(HTTPInfo *info, const boost::string_ref &name);

	int extract_uri(HTTPInfo *info, const boost::string_ref &header);

	void parse_header(HTTPInfo *info, const boost::string_ref &header);
	bool process_host_parameter(HTTPInfo *info, const boost::string_ref &host);
	bool process_ua_parameter(HTTPInfo *info, const boost::string_ref &ua);
	bool process_content_length_parameter(HTTPInfo *info, const boost::string_ref &parameter);
	bool process_content_type_parameter(HTTPInfo *info, const boost::string_ref &ct);
	bool process_content_disposition_parameter(HTTPInfo *info, const boost::string_ref &cd);
	bool is_minimal_http_header(const char *hdr);
	std::tuple<bool, int> get_http_request_method(const boost::string_ref &hdr);

	int32_t release_http_info(HTTPInfo *info);
	void release_http_info_cache(HTTPInfo *info);

	void process_matched_uris(Flow *flow, HTTPInfo *info);

	static std::unordered_map<int, HttpResponseType> responses_;
	std::unordered_map<boost::string_ref, HttpParameterHandler, string_hasher> parameters_;

	const uint8_t *header_;
	int16_t http_header_size_;	
#if defined(STAND_ALONE_TEST) || defined(TESTING)
	int16_t http_method_size_;
	int16_t http_parameters_size_;
#endif
	int64_t total_l7_bytes_;// with no http headers;
	int32_t total_allow_hosts_;
	int32_t total_ban_hosts_;
	int32_t total_requests_;
	int32_t total_responses_;
	int32_t total_http_others_;
	int32_t total_gets_;
	int32_t total_posts_;
	int32_t total_heads_;
	int32_t total_connects_;
	int32_t total_options_;
	int32_t total_puts_;
	int32_t total_deletes_;
	int32_t total_traces_;
	int32_t total_events_;

	Cache<HTTPInfo>::CachePtr info_cache_;
	Cache<StringCache>::CachePtr uri_cache_;
	Cache<StringCache>::CachePtr host_cache_;
	Cache<StringCache>::CachePtr ua_cache_;
	Cache<StringCache>::CachePtr ct_cache_;
	Cache<StringCache>::CachePtr file_cache_;

	GenericMapType ua_map_;	
	GenericMapType host_map_;	
	GenericMapType uri_map_;	
	GenericMapType ct_map_;	
	GenericMapType file_map_;	

        SharedPointer<DomainNameManager> domain_mng_;
        SharedPointer<DomainNameManager> ban_domain_mng_;

	FlowManagerPtrWeak flow_mng_;
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
	boost::string_ref http_ref_header_;
	boost::string_ref header_field_;
	boost::string_ref header_parameter_;
	Flow *current_flow_;
	SharedPointer<AnomalyManager> anomaly_;
	FlowRegexEvaluator eval_;
};

typedef std::shared_ptr<HTTPProtocol> HTTPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_HTTP_HTTPPROTOCOL_H_
