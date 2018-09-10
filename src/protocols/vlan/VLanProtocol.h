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
#ifndef SRC_PROTOCOLS_VLAN_VLANPROTOCOL_H_
#define SRC_PROTOCOLS_VLAN_VLANPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

struct vlan_header {
        uint16_t       vlan_tpid;              /* ETH_P_8021Q/ETHERTYPE_VLAN */
        uint16_t       vlan_tci;               /* VLAN TCI */
} __attribute__((packed));

#define VLAN_TAG_LEN    4

class VLanProtocol: public Protocol {
public:
    	explicit VLanProtocol();
    	virtual ~VLanProtocol() {}

	static const uint16_t id = ETHERTYPE_VLAN;	
	static const int header_size = VLAN_TAG_LEN;

	int getHeaderSize() const { return header_size;}

       	void processFlow(Flow *flow) override {} // This protocol dont generate any flow 
	bool processPacket(Packet &packet) override;

	void statistics(std::basic_ostream<char>& out, int level) override;

	void releaseCache() override {} // No need to free cache

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const vlan_header*> (raw_packet);
	}

	// Condition for say that a packet its vlan 802.1q 
	bool vlanChecker(Packet &packet); 
	
	uint16_t getEthernetType() const { return ntohs(header_->vlan_tci);}
	uint16_t getVlanId() const { return (ntohs(header_->vlan_tpid) & 0x0FFF);} 

	int64_t getCurrentUseMemory() const override { return sizeof(VLanProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(VLanProtocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(VLanProtocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	CounterMap getCounters() const override; 

private:
	const vlan_header *header_;
};

typedef std::shared_ptr<VLanProtocol> VLanProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_VLAN_VLANPROTOCOL_H_
