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
#ifndef SRC_PROTOCOLS_DHCP_DHCPPROTOCOL_H_
#define SRC_PROTOCOLS_DHCP_DHCPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <arpa/inet.h>
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "DHCPInfo.h"
#include "StringCache.h"
#include "flow/FlowManager.h"

namespace aiengine {

// ftp://ftp.isc.org/isc/dhcp/4.3.1rc1/

struct dhcp_header {
	uint8_t 	op;		/* packet opcode type */
	uint8_t 	htype;		/* hardware addr type */
	uint8_t 	hlen;		/* hardware addr length */
	uint8_t 	hops;		/* gateway hops */
    	uint32_t 	xid;		/* transaction ID */
    	uint16_t 	secs;		/* seconds since boot began */
    	uint16_t 	flags;		/* flags */
    	uint32_t 	ciaddr;		/* client IP address */
    	uint32_t 	yiaddr;		/* 'your' IP address */
    	uint32_t 	siaddr;		/* server IP address */
    	uint32_t 	giaddr;		/* gateway IP address */
    	uint8_t 	chaddr[16];	/* client hardware address */
    	uint8_t 	sname[64];
    	uint8_t 	file[128];
    	uint8_t 	magic[4];
    	uint8_t 	opt[0];
} __attribute__((packed));

enum dhcp_boot_type {
	DHCP_BOOT_REQUEST = 1,
	DHCP_BOOT_REPLY = 2
};

enum dhcp_type_code {
	DHCPDISCOVER = 1,
	DHCPOFFER,
	DHCPREQUEST,
	DHCPDECLINE,
	DHCPACK,
	DHCPNAK,
	DHCPRELEASE,
	DHCPINFORM
};

class DHCPProtocol: public Protocol {
public:
    	explicit DHCPProtocol();
    	virtual ~DHCPProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(dhcp_header);

	int getHeaderSize() const { return header_size; }

        void processFlow(Flow *flow) override;
        bool processPacket(Packet &packet) override { return true; } 

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override; 

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const dhcp_header*> (raw_packet);
	}

	// Condition for say that a packet is dhcp 
	bool dhcpChecker(Packet &packet); 

	uint8_t getType() const { return header_->op; }

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

#if defined(PYTHON_BINDING)
        boost::python::dict getCache() const override;
	void showCache(std::basic_ostream<char> &out) const override;
#elif defined(RUBY_BINDING)
        VALUE getCache() const;
#endif

        void setAnomalyManager(SharedPointer<AnomalyManager> amng) override { anomaly_ = amng; }

	void releaseFlowInfo(Flow *flow) override;

        Flow* getCurrentFlow() const { return current_flow_; }

#if defined(STAND_ALONE_TEST) || defined(TESTING)
        int32_t getTotalDiscovers() const { return total_dhcp_discover_; }
        int32_t getTotalOffers() const { return total_dhcp_offer_; }
        int32_t getTotalRequests() const { return total_dhcp_request_; }
        int32_t getTotalDeclines() const { return total_dhcp_decline_; }
        int32_t getTotalAcks() const { return total_dhcp_ack_; }
        int32_t getTotalNaks() const { return total_dhcp_nak_; }
        int32_t getTotalReleases() const { return total_dhcp_release_; }
        int32_t getTotalInforms() const { return total_dhcp_inform_; }
#endif

private:
	int32_t release_dhcp_info(DHCPInfo *info);
	int64_t compute_memory_used_by_maps() const;

	void attach_host_name(DHCPInfo *info, const boost::string_ref &name);
	void attach_ip(DHCPInfo *info, const boost::string_ref &ip);
	void handle_request(DHCPInfo *info, const uint8_t *payload, int length);
	void handle_reply(DHCPInfo *info, const uint8_t *payload, int length);
	void handle_ip_address(DHCPInfo *info);

	const dhcp_header *header_;
        
	// Some statistics 
        int32_t total_dhcp_discover_;
        int32_t total_dhcp_offer_;
        int32_t total_dhcp_request_;
        int32_t total_dhcp_decline_;
        int32_t total_dhcp_ack_;
        int32_t total_dhcp_nak_;
        int32_t total_dhcp_release_;
        int32_t total_dhcp_inform_;

        Cache<DHCPInfo>::CachePtr info_cache_;
        Cache<StringCache>::CachePtr host_cache_;
        Cache<StringCache>::CachePtr ip_cache_;

        GenericMapType host_map_;
        GenericMapType ip_map_;

        FlowManagerPtrWeak flow_mng_;
        Flow *current_flow_;
#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
        SharedPointer<AnomalyManager> anomaly_;
};

typedef std::shared_ptr<DHCPProtocol> DHCPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_DHCP_DHCPPROTOCOL_H_
