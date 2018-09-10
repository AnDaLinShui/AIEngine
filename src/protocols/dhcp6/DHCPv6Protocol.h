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
#ifndef SRC_PROTOCOLS_DHCPv6_DHCPv6PROTOCOL_H_
#define SRC_PROTOCOLS_DHCPv6_DHCPv6PROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <arpa/inet.h>
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "DHCPv6Info.h"
#include "StringCache.h"
#include "flow/FlowManager.h"

namespace aiengine {

struct dhcpv6_option {
        uint16_t 	code;		/* code */
        uint16_t 	len;		/* length */
        uint8_t 	data[0];
} __attribute__ ((packed));

struct dhcpv6_header {
	uint8_t 	type;		/* message type */
	uint8_t 	xid[3];		/* transaction id */
	struct dhcpv6_option options[0];
} __attribute__((packed));

/* DHCPv6 identity association for non-temporary address (IA_NA) option */
struct dhcpv6_ia_na_option {
        uint32_t 	iaid; 		/* Identity association identifier (IAID) */
        uint32_t 	renew;		/* Renew time (in seconds) T1 */
        uint32_t 	rebind;		/* Rebind time (in seconds) T2 */
        struct dhcpv6_option options[0];/* IA_NA options */
} __attribute__ (( packed ));

/* DHCPv6 identity association address (IAADDR) option */
struct dhcpv6_iaaddr_option {
	struct in6_addr address;        /* IPv6 address */
        uint32_t 	preferred;	/* Preferred lifetime (in seconds) */
        uint32_t 	valid;		/* Valid lifetime (in seconds) */
      	struct dhcpv6_option options[0];
} __attribute__ (( packed ));

enum dhcpv6_type_code {
	DHCPV6_SOLICIT = 	1,
        DHCPV6_ADVERTISE = 	2,
	DHCPV6_REQUEST = 	3,
	DHCPV6_CONFIRM = 	4,
	DHCPV6_RENEW = 		5,
	DHCPV6_REBIND = 	6,
	DHCPV6_REPLY = 		7, 
	DHCPV6_RELEASE = 	8, 
	DHCPV6_DECLINE = 	9, 
	DHCPV6_RECONFIGURE = 	10, 
	DHCPV6_INFO_REQUEST = 	11, 
	DHCPV6_RELAY_FORW = 	12, 
	DHCPV6_RELAY_REPL =	13
};

class DHCPv6Protocol: public Protocol {
public:
    	explicit DHCPv6Protocol();
    	virtual ~DHCPv6Protocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(dhcpv6_header);

	int getHeaderSize() const { return header_size; }

        void processFlow(Flow *flow) override;
        bool processPacket(Packet &packet) override { return true; } 

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override; 

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const dhcpv6_header*> (raw_packet);
	}

	// Condition for say that a packet is dhcp 
	bool dhcpv6Checker(Packet &packet); 

	uint8_t getType() const { return header_->type; }

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

private:
	int32_t release_dhcp6_info(DHCPv6Info *info);
	int64_t compute_memory_used_by_maps() const;

	void attach_ip(DHCPv6Info *info, const boost::string_ref &ip);
	void attach_host_name(DHCPv6Info *info, const boost::string_ref &name);
	void handle_request(DHCPv6Info *info, const uint8_t *payload, int length);

	const dhcpv6_header *header_;

	// Some statistics 
        int32_t total_dhcpv6_solicit_;
        int32_t total_dhcpv6_advertise_;
        int32_t total_dhcpv6_request_;
        int32_t total_dhcpv6_confirm_;
        int32_t total_dhcpv6_renew_;
        int32_t total_dhcpv6_rebind_;
        int32_t total_dhcpv6_reply_;
        int32_t total_dhcpv6_release_;
        int32_t total_dhcpv6_decline_;
        int32_t total_dhcpv6_reconfigure_;
        int32_t total_dhcpv6_info_request_;
        int32_t total_dhcpv6_relay_forw_;
        int32_t total_dhcpv6_relay_repl_;

        Cache<DHCPv6Info>::CachePtr info_cache_;
        Cache<StringCache>::CachePtr host_cache_;
        Cache<StringCache>::CachePtr ip6_cache_;

        GenericMapType host_map_;
        GenericMapType ip6_map_;

        FlowManagerPtrWeak flow_mng_;
        Flow *current_flow_;
#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
        SharedPointer<AnomalyManager> anomaly_;
};

typedef std::shared_ptr<DHCPv6Protocol> DHCPv6ProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_DHCPv6_DHCPv6PROTOCOL_H_
