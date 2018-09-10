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
#include "EthernetProtocol.h"
#include <iomanip> // setw

namespace aiengine {


EthernetProtocol::EthernetProtocol(const std::string &name, const std::string &short_name):
	Protocol(name, short_name),
	max_ethernet_len_(ETHER_MAX_LEN),
	eth_header_(nullptr) {}

bool EthernetProtocol::ethernetChecker(Packet &packet) {

	int length = packet.getLength();

	// max_ethernet_len_ on network devices shoudl be equal to the mtu
	// but on pcap/pcapng files there is no limit of packet size
	if ((length >= 20 + 14) and (length <= max_ethernet_len_)) {
		const uint8_t *pkt = packet.getPayload();
		setHeader(pkt);

		packet.setPacketAnomaly(PacketAnomalyType::NONE);
		packet.link_packet.setPayload(pkt);
		packet.link_packet.setLength(length);
		++total_valid_packets_;
		// Normaly we increase the total_packets on the processPacket function
		// However this is a special case due to the ethernet is close the PacketDispatcher

		++total_packets_;
		total_bytes_ += length;
		return true;
	} else {
		++total_invalid_packets_;
		return false;
	}
}


// Just used when there is ethernet on the middle part of a stack
// Check vxlan for further details

bool EthernetProtocol::processPacket(Packet &packet) { 

	MultiplexerPtr mux = mux_.lock();

        if (mux) {
                mux->setNextProtocolIdentifier(getEthernetType());

                mux->setHeaderSize(header_size);
		packet.link_packet.setPayload(packet.getPayload());
		packet.link_packet.setLength(packet.getLength());
                packet.setPrevHeaderSize(header_size);
	}
	return true;
}
	
void EthernetProtocol::statistics(std::basic_ostream<char> &out, int level) { 

	if (level > 0) {
		int64_t alloc_memory = getAllocatedMemory();
		std::string unit = "Bytes";

		unitConverter(alloc_memory,unit);

		out << getName() << "(" << this <<") statistics" << std::dec << std::endl;
		out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ << std::endl;
		if (level > 1) {
			out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << std::endl;
			out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << std::endl;
			if ( level > 2) {
				if (mux_.lock())
					mux_.lock()->statistics(out);
			}
		}
	}
}

CounterMap EthernetProtocol::getCounters() const { 
	CounterMap cm;

	cm.addKeyValue("packets", total_packets_);
	cm.addKeyValue("bytes", total_bytes_);

        return cm;
}

} // namespace aiengine 
