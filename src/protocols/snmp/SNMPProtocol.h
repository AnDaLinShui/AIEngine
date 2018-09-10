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
#ifndef SRC_PROTOCOLS_SNMP_SNMPPROTOCOL_H_
#define SRC_PROTOCOLS_SNMP_SNMPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

// micro snmp ber header
struct snmp_header { 
	uint8_t 	code;
	uint8_t 	length;
	uint8_t 	type;
	uint8_t 	version_length;
	uint8_t 	data[0]; // snmp data 
} __attribute__((packed));

enum snmp_ber_types {
	SNMP_GET_REQ = 0xA0,
	SNMP_GET_NEXT_REQ = 0xA1,
	SNMP_GET_RES = 0xA2,
	SNMP_SET_REQ = 0xA3
};

class SNMPProtocol: public Protocol {
public:
    	explicit SNMPProtocol();
    	virtual ~SNMPProtocol();

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(struct snmp_header);

	int getHeaderSize() const { return header_size; }

        void processFlow(Flow *flow) override;
        bool processPacket(Packet &packet) override { return true; } 

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override {} // No need to free cache

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const snmp_header*> (raw_packet);
	}

	// Condition for say that a packet is snmp 
	bool snmpChecker(Packet &packet); 
	
	uint8_t getLength() const { return header_->length; }
	uint8_t getVersionLength() const { return header_->version_length; }

	int64_t getCurrentUseMemory() const override { return sizeof(SNMPProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(SNMPProtocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(SNMPProtocol); }
	int64_t getAllocatedMemory(int value) const { return sizeof(SNMPProtocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	int32_t getTotalEvents() const override { return total_events_; }

	CounterMap getCounters() const override; 

	void setAnomalyManager(SharedPointer<AnomalyManager> amng) override { anomaly_ = amng; }
private:
	const snmp_header *header_;
	int32_t total_events_;
	int32_t total_snmp_get_requests_;
	int32_t total_snmp_get_next_requests_;
	int32_t total_snmp_get_responses_;
	int32_t total_snmp_set_requests_;
	SharedPointer<AnomalyManager> anomaly_;
};

typedef std::shared_ptr<SNMPProtocol> SNMPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SNMP_SNMPPROTOCOL_H_
