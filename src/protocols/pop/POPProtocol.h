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
#ifndef SRC_PROTOCOLS_POP_POPPROTOCOL_H_ 
#define SRC_PROTOCOLS_POP_POPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "POPInfo.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <unordered_map>
#include "flow/FlowManager.h"

namespace aiengine {

enum class POPCommandTypes : std::int8_t {
        POP_CMD_STAT =         0,
        POP_CMD_LIST,
        POP_CMD_RETR,
        POP_CMD_DELE,
        POP_CMD_NOOP,
        POP_CMD_RSET,
        POP_CMD_TOP,
        POP_CMD_UIDL,
        POP_CMD_USER,
        POP_CMD_PASS,
        POP_CMD_APOP,
        POP_CMD_STLS,
        POP_CMD_QUIT
};

// Commands with statistics
typedef std::tuple<const char*,int,const char*,int32_t, int8_t> PopCommandType;

class POPProtocol: public Protocol {
public:
    	explicit POPProtocol();
    	virtual ~POPProtocol(); 

	static const uint16_t id = 0;
	static const int header_size = 6; // Minimum header 220 \r\n;

	int getHeaderSize() const { return header_size; }

	bool processPacket(Packet &packet) override { return true; }
	void processFlow(Flow *flow) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override; 

        void setHeader(const uint8_t *raw_packet) override {
                
		header_ = raw_packet;
        }

	// Condition for say that a payload is POP 
	bool popChecker(Packet &packet); 

	const uint8_t *getPayload() { return header_; }

        void increaseAllocatedMemory(int value) override;
        void decreaseAllocatedMemory(int value) override;

        void setDomainNameManager(const SharedPointer<DomainNameManager> &dm) override;
        void setDomainNameBanManager(const SharedPointer<DomainNameManager> &dm) override { ban_domain_mng_ = dm;}

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

#if defined(STAND_ALONE_TEST) || defined(TESTING)
        int32_t getTotalClientCommands() const { return total_pop_client_commands_; }
        int32_t getTotalServerResponses() const { return total_pop_server_responses_; }

        Flow *getCurrentFlow() const { return current_flow_; }
#endif

	void releaseFlowInfo(Flow *flow) override;

private:
	void release_pop_info_cache(POPInfo *info);
        int32_t release_pop_info(POPInfo *info);
	int64_t compute_memory_used_by_maps() const;

	void handle_cmd_user(POPInfo *info, const boost::string_ref &header);
	void attach_user_name(POPInfo *info, const boost::string_ref &name);

	const uint8_t *header_;
	int32_t total_events_;	
	int32_t total_allow_domains_;	
	int32_t total_ban_domains_;

	static std::vector<PopCommandType> commands_;
	int32_t total_pop_client_commands_;
	int32_t total_pop_server_responses_;

        SharedPointer<DomainNameManager> domain_mng_;
        SharedPointer<DomainNameManager> ban_domain_mng_;

	Cache<POPInfo>::CachePtr info_cache_;
	Cache<StringCache>::CachePtr user_cache_;

        GenericMapType user_map_;

	FlowManagerPtrWeak flow_mng_;
	Flow *current_flow_;	
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
	SharedPointer<AnomalyManager> anomaly_;
};

typedef std::shared_ptr<POPProtocol> POPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_POP_POPPROTOCOL_H_
