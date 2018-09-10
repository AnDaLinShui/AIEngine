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
#include "QuicProtocol.h"
#include <iomanip>

namespace aiengine {

QuicProtocol::QuicProtocol():
	Protocol("QuicProtocol", "quic", IPPROTO_UDP),
	header_(nullptr) {} 

bool QuicProtocol::quicChecker(Packet &packet){

	int length = packet.getLength();

	if (length >= header_size) {
		// Quic is started by the clients so just the destination port is checked
		// and the first packet read must be one
		if ((packet.getDestinationPort() == 80)or
			(packet.getDestinationPort() == 443)) {

			setHeader(packet.getPayload());
			if (header_->pkt_number == 0x01) {
				++total_valid_packets_;
				return true;
			}
		}
	}
	++total_invalid_packets_;
	return false;
}

void QuicProtocol::processFlow(Flow *flow) {

	// TODO
	total_bytes_ += flow->packet->getLength();
	++total_packets_;
}

void QuicProtocol::statistics(std::basic_ostream<char> &out, int level){ 

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
			if (level > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
			}
		}
	}
}

CounterMap QuicProtocol::getCounters() const {
	CounterMap cm;

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
	
        return cm;
}

} // namespace aiengine
