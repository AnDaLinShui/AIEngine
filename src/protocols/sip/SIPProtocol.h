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
#ifndef SRC_PROTOCOLS_SIP_SIPPROTOCOL_H_
#define SRC_PROTOCOLS_SIP_SIPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "StringCache.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include "Cache.h"
#include <unordered_map>
#include "regex/Regex.h"
#include "flow/FlowManager.h"
#include "SIPInfo.h"

namespace aiengine {

enum sip_state_code {
	SIP_NONE = 0x00,
        SIP_TRYING_CALL = 0x01,
        SIP_CALL_ESTABLISHED,
        SIP_FINISH_CALL,
        SIP_CALL_DONE 
};

class SIPProtocol: public Protocol {
public:
    	explicit SIPProtocol();
    	virtual ~SIPProtocol() {}

	static const uint16_t id = 0;
	static const int header_size = 0;

	int getHeaderSize() const { return header_size; }

	bool processPacket(Packet &packet) override { /* Nothing to process at packet level*/ return true; }
	void processFlow(Flow *flow) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override; // Three caches will be clean 

        void setHeader(const uint8_t *raw_packet) override {
        
                header_ = raw_packet;
        }

        // Condition for say that a payload is SIP
        bool sipChecker(Packet &packet); 

	const uint8_t *getPayload() { return header_; }

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

	void releaseFlowInfo(Flow *flow) override;

#if defined(PYTHON_BINDING)
        boost::python::dict getCache() const override;
        void showCache(std::basic_ostream<char> &out) const override;
#elif defined(RUBY_BINDING)
        VALUE getCache() const;
#endif

#if defined(STAND_ALONE_TEST) || defined(TESTING)
	int32_t getTotalRegisters() const { return total_registers_; }
	int32_t getTotalInvitess() const { return total_invites_; }
	int32_t getTotalPublishs() const { return total_publishs_; }
	int32_t getTotalPings() const { return total_pings_; }
	int32_t getTotalNotifies() const { return total_notifies_; }
	int32_t getTotalOptions() const { return total_options_; }
	int32_t getTotalInfos() const { return total_infos_; }
	int32_t getTotalRefers() const { return total_refers_; }
	int32_t getTotalCancels() const { return total_cancels_; }
	int32_t getTotalMessages() const { return total_messages_; }
	int32_t getTotalSubscribes() const { return total_subscribes_; }
	int32_t getTotalAcks() const { return total_acks_; }
	int32_t getTotalByes() const { return total_byes_; }
#endif

private:

	void attach_uri_to_flow(SIPInfo *info, const boost::string_ref &uri);
	void attach_from_to_flow(SIPInfo *info, const boost::string_ref &from);
	void attach_to_to_flow(SIPInfo *info, const boost::string_ref &to);
	void attach_via_to_flow(SIPInfo *info, const boost::string_ref &via);
	void extract_uri_value(SIPInfo *info, const boost::string_ref &header);
	void extract_from_value(SIPInfo *info, const boost::string_ref &header);
	void extract_to_value(SIPInfo *info, const boost::string_ref &header);
	void extract_via_value(SIPInfo *info, const boost::string_ref &header);

	void handle_invite(SIPInfo *info, const boost::string_ref &header);
	void handle_ok(SIPInfo *info, const boost::string_ref &header);
	void handle_bye(SIPInfo *info, const boost::string_ref &header);

	std::tuple<uint32_t, uint16_t> extract_ip_and_port_from_sdp(const boost::string_ref &hdr); 

	std::tuple<bool, int> get_sip_request_method(const boost::string_ref &hdr); 

	int64_t compute_memory_used_by_maps() const;
	int32_t release_sip_info(SIPInfo *info);

	SharedPointer<Regex> sip_from_;
	SharedPointer<Regex> sip_to_;
	SharedPointer<Regex> sip_via_;
	const uint8_t *header_;
	int32_t total_events_;

	// Some statistics of the SIP methods 
	int32_t total_requests_;
	int32_t total_responses_;
	int32_t total_registers_;
	int32_t total_invites_;
	int32_t total_publishs_;
	int32_t total_byes_;
	int32_t total_acks_;
	int32_t total_subscribes_;
	int32_t total_messages_;
	int32_t total_cancels_;
	int32_t total_refers_;
	int32_t total_infos_;
	int32_t total_options_;
	int32_t total_notifies_;
	int32_t total_pings_;
	int32_t total_sip_others_;

	Cache<SIPInfo>::CachePtr info_cache_;
	Cache<StringCache>::CachePtr uri_cache_;
	Cache<StringCache>::CachePtr via_cache_;
	Cache<StringCache>::CachePtr from_cache_;
	Cache<StringCache>::CachePtr to_cache_;

	GenericMapType uri_map_;	
	GenericMapType via_map_;
	GenericMapType from_map_;	
	GenericMapType to_map_;	

	FlowManagerPtrWeak flow_mng_;
	Flow *current_flow_;
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<SIPProtocol> SIPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SIP_SIPPROTOCOL_H_
