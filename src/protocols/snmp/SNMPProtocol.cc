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
#include "SNMPProtocol.h"
#include <iomanip>

namespace aiengine {

SNMPProtocol::SNMPProtocol():
	Protocol("SNMPProtocol", "snmp", IPPROTO_UDP),
	header_(nullptr),
	total_events_(0),
	total_snmp_get_requests_(0),
	total_snmp_get_next_requests_(0),
	total_snmp_get_responses_(0),
	total_snmp_set_requests_(0),
	anomaly_() {}

SNMPProtocol::~SNMPProtocol() { 

	anomaly_.reset(); 
}

bool SNMPProtocol::snmpChecker(Packet &packet) {

	int length = packet.getLength();

	if (length >= header_size) {
		if ((packet.getSourcePort() == 161)||(packet.getDestinationPort() == 161)) {
			setHeader(packet.getPayload());
			++total_valid_packets_;
			return true;
		}
	}
	++total_invalid_packets_;
	return false;
}

void SNMPProtocol::processFlow(Flow *flow) {

	setHeader(flow->packet->getPayload());	
	int length = flow->packet->getLength();

	total_bytes_ += length;
	++total_packets_;

	if ((getLength() > length)or(getVersionLength() > length)) { // the packet is corrupted
		++total_events_;
                if (flow->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        flow->setPacketAnomaly(PacketAnomalyType::SNMP_BOGUS_HEADER);
                }
		anomaly_->incAnomaly(flow, PacketAnomalyType::SNMP_BOGUS_HEADER);
                return;
	}

	int offset = getVersionLength() ;
	uint8_t btag = header_->data[offset];

	if (btag == 0x04 ) { // BER encoding for the community
		uint8_t community_length = header_->data[offset + 1];

		// very unlikely to happen, but....
		if (community_length > (length - offset)) {
			++total_events_;
                	if (flow->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        	flow->setPacketAnomaly(PacketAnomalyType::SNMP_BOGUS_HEADER);
                	}
			anomaly_->incAnomaly(flow, PacketAnomalyType::SNMP_BOGUS_HEADER);
			return;	
		}

		offset = offset + community_length + 2;
		btag = header_->data[offset];
		
		if (btag == SNMP_GET_REQ) { // get request
			++total_snmp_get_requests_;
		} else if (btag == SNMP_GET_NEXT_REQ) {
			++total_snmp_get_next_requests_;
		} else if (btag == SNMP_GET_RES) {
			++total_snmp_get_responses_;
		} else if (btag == SNMP_SET_REQ) {
			++total_snmp_set_requests_;
		}
	}
}

void SNMPProtocol::statistics(std::basic_ostream<char> &out, int level) { 

	if (level > 0) {
                int64_t alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory, unit);

                out << getName() << "(" << this <<") statistics" << std::dec << std::endl;
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ << std::endl;
		if (level > 1) {
			out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << std::endl;
			out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << std::endl;
                        if (level > 3) {
                                out << "\t" << "Total get requests:     " << std::setw(10) << total_snmp_get_requests_ << std::endl;
                                out << "\t" << "Total get next requests:" << std::setw(10) << total_snmp_get_next_requests_ << std::endl;
                                out << "\t" << "Total get responses:    " << std::setw(10) << total_snmp_get_responses_ << std::endl;
                                out << "\t" << "Total set requests:     " << std::setw(10) << total_snmp_set_requests_ << std::endl;
                        } 
			if (level > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
			}
		}
	}
}

CounterMap SNMPProtocol::getCounters() const { 
	CounterMap cm;

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
	cm.addKeyValue("get reqs", total_snmp_get_requests_);
	cm.addKeyValue("get next reqs", total_snmp_get_next_requests_);
	cm.addKeyValue("get resp", total_snmp_get_responses_);
	cm.addKeyValue("set req", total_snmp_set_requests_);

        return cm;
}

} // namespace aiengine
