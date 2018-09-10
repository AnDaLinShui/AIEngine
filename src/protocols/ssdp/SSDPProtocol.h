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
#ifndef SRC_PROTOCOLS_SSDP_SSDPPROTOCOL_H_ 
#define SRC_PROTOCOLS_SSDP_SSDPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

//#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <unordered_map>
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "SSDPInfo.h"
#include "Cache.h"
#include "flow/FlowManager.h"

namespace aiengine {

// Methods and response with statistics
typedef std::tuple<const char*, int, const char*, int32_t> SsdpMethodType;
typedef std::tuple<const char*, int32_t> SsdpResponseType;
typedef std::function <bool (SSDPInfo *info, const boost::string_ref &parameter)> SsdpParameterHandler;

class SSDPProtocol: public Protocol {
public:
    	explicit SSDPProtocol();
    	virtual ~SSDPProtocol() {}

	struct string_hasher
	{
        	size_t operator()(boost::string_ref const& s) const
        	{
                	return boost::hash_range(s.begin(), s.end());
        	}
	};

	static const uint16_t id = 0;
	static const int header_size = 0; // sizeof(struct dns_header);
	static const int MAX_SSDP_BUFFER_NAME = 128;

	int getHeaderSize() const { return header_size; }

	bool processPacket(Packet &packet) override { return true; }
	void processFlow(Flow *flow) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

        void setDomainNameManager(const SharedPointer<DomainNameManager> &dm) override; 
        void setDomainNameBanManager(const SharedPointer<DomainNameManager> &dm) override { ban_domain_mng_ = dm; }

	void releaseCache() override; 

        void setHeader(const uint8_t *raw_packet) override {
                
		header_ = raw_packet;
        }

	// Condition for say that a payload is SSDP 
	bool ssdpChecker(Packet &packet); 
	
        void increaseAllocatedMemory(int value) override;
        void decreaseAllocatedMemory(int value) override;

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

	void releaseFlowInfo(Flow *flow) override;

#if defined(STAND_ALONE_TEST) || defined(TESTING)
        int32_t getTotalNotifies() const { return total_notifies_; }
        int32_t getTotalMSearchs() const { return total_searchs_; }
        int32_t getTotalSubscribes() const { return total_subscribes_; }
        int32_t getTotalSSDPPs() const { return total_ssdpcs_; }
#endif

private:
	void parse_header(SSDPInfo *info, const boost::string_ref &header);
	int extract_uri(SSDPInfo *info, const boost::string_ref &header);

	void attach_uri(SSDPInfo *info, const boost::string_ref &host);
	void attach_host(SSDPInfo *info, const boost::string_ref &host);
	bool process_host_parameter(SSDPInfo *info, const boost::string_ref &host);
	std::tuple<bool, int> get_ssdp_request_method(const boost::string_ref &hdr);

	int64_t compute_memory_used_by_maps() const;
	int32_t release_ssdp_info(SSDPInfo *info);

	static std::unordered_map<int,SsdpResponseType> responses_;
	std::unordered_map<boost::string_ref, SsdpParameterHandler, string_hasher> parameters_;

	const uint8_t *header_;
	int16_t ssdp_header_size_;
        int64_t total_events_;
        int32_t total_ban_hosts_;
	int32_t total_allow_hosts_;
	int32_t total_requests_;
	int32_t total_responses_;
        int32_t total_notifies_;
        int32_t total_searchs_;
        int32_t total_subscribes_;
        int32_t total_ssdpcs_;
	int32_t total_ssdp_others_;

	Cache<SSDPInfo>::CachePtr info_cache_;
	Cache<StringCache>::CachePtr uri_cache_;
	Cache<StringCache>::CachePtr host_cache_;

	GenericMapType uri_map_;
	GenericMapType host_map_;

	SharedPointer<DomainNameManager> domain_mng_;
	SharedPointer<DomainNameManager> ban_domain_mng_;

	FlowManagerPtrWeak flow_mng_;	
	Flow *current_flow_;
        boost::string_ref header_field_;
        boost::string_ref header_parameter_;
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<SSDPProtocol> SSDPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SSDP_SSDPPROTOCOL_H_
