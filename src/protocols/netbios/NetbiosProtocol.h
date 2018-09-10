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
#ifndef SRC_PROTOCOLS_NETBIOS_NETBIOSPROTOCOL_H_
#define SRC_PROTOCOLS_NETBIOS_NETBIOSPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif

#include "Protocol.h"
#include "NetbiosInfo.h"
#include "Cache.h"
#include <arpa/inet.h>
#include "flow/FlowManager.h"

namespace aiengine {

struct netbios_header {
	uint16_t 	id;
	uint16_t 	flags;
	uint16_t 	questions;
	uint16_t 	answers;
	uint16_t 	auths;
	uint16_t 	adds;
	uint8_t 	data[0];
} __attribute__((packed)); 

class NetbiosProtocol: public Protocol {
public:
    	explicit NetbiosProtocol();
    	virtual ~NetbiosProtocol();

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(netbios_header);

	int getHeaderSize() const { return header_size;}

        void processFlow(Flow *flow) override;
        bool processPacket(Packet &packet) override { return true; } 

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override; 

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const netbios_header*> (raw_packet);
	}

	// Condition for say that a packet is netbios
	bool netbiosChecker(Packet &packet);

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
        void setAnomalyManager(SharedPointer<AnomalyManager> amng) override { anomaly_ = amng; }

	void releaseFlowInfo(Flow *flow) override;

	Flow* getCurrentFlow() const { return current_flow_; }

private:

	void attach_netbios_name(NetbiosInfo *info, const boost::string_ref &name);
	int32_t release_netbios_info(NetbiosInfo *info);
	int64_t compute_memory_used_by_maps() const;

	const netbios_header *header_;
	int32_t total_events_;

        Cache<NetbiosInfo>::CachePtr info_cache_;
        Cache<StringCache>::CachePtr name_cache_;

        GenericMapType name_map_;

	FlowManagerPtrWeak flow_mng_;
	Flow *current_flow_;
#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
        SharedPointer<AnomalyManager> anomaly_;
	uint8_t netbios_name_[32];
};

typedef std::shared_ptr<NetbiosProtocol> NetbiosProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_NETBIOS_NETBIOSPROTOCOL_H_
