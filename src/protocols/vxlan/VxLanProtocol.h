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
#ifndef SRC_PROTOCOLS_VXLAN_VXLANPROTOCOL_H_
#define SRC_PROTOCOLS_VXLAN_VXLANPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

struct vxlan_header {
        uint8_t		flags;   
        uint8_t		reserved[3];
	uint8_t		vni[3];
	uint8_t		reserv;
} __attribute__((packed));


// This class implements the Virtual Extensible Local Area Network
// that is wide spread on Cloud environments

class VxLanProtocol: public Protocol {
public:
    	explicit VxLanProtocol();
    	virtual ~VxLanProtocol() {}

	static const uint16_t id = 0;	
	static const int header_size = sizeof(struct vxlan_header);

	int getHeaderSize() const { return header_size; }

        void processFlow(Flow *flow) override;
        bool processPacket(Packet &packet) override { return true; } // Nothing to process

	void statistics(std::basic_ostream<char> &out, int level) override;

        void releaseCache() override {} // No need to free cache

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const vxlan_header*> (raw_packet);
	}

	// Condition for say that a packet is vxlan
	bool vxlanChecker(Packet &packet);

	uint32_t getVni() const { return ntohl(header_->vni[2] << 24 | header_->vni[1] << 16 | header_->vni[0] << 8); }

	int64_t getCurrentUseMemory() const override { return sizeof(VxLanProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(VxLanProtocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(VxLanProtocol); }
	// int64_t getAllocatedMemory(int value) const override { return sizeof(VxLanProtocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	CounterMap getCounters() const override; 

private:
	const vxlan_header *header_;
};

typedef std::shared_ptr<VxLanProtocol> VxLanProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_VXLAN_VXLANPROTOCOL_H_
