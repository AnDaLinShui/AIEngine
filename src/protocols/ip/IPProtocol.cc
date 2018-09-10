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
#include "IPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

IPProtocol::IPProtocol(const std::string &name, const std::string &short_name):
	Protocol(name,short_name),
	header_(nullptr),
	total_frag_packets_(0),
	total_events_(0),
	anomaly_() {} 

IPProtocol::~IPProtocol() {

	anomaly_.reset();
}

bool IPProtocol::ipChecker(Packet &packet) {

	int length = packet.getLength();

	setHeader(packet.getPayload());

	if ((length >= header_size)&&(isIPver4())) {
		++total_valid_packets_;
		return true;
	} else {
		++total_invalid_packets_;
		return false;
	}
}

bool IPProtocol::processPacket(Packet &packet) {

        MultiplexerPtr mux = mux_.lock();
	int bytes = 0;

	++total_packets_;

	mux->address.setSourceAddress(getSrcAddr());
	mux->address.setDestinationAddress(getDstAddr());

	// Some packets have padding data at the end
	if (getPacketLength() < packet.getLength())
		bytes = getPacketLength();
	else
		bytes = packet.getLength();

	mux->total_length = bytes;
	total_bytes_ += bytes;

	packet.net_packet.setPayload(packet.getPayload());
        packet.net_packet.setLength(bytes);
	
	mux->setNextProtocolIdentifier(getProtocol());
	packet.setPrevHeaderSize(header_size);

#ifdef DEBUG
	std::cout << __FILE__ << ":" << __func__ << ": ip.src(" << getSrcAddrDotNotation() << ")ip.dst(" << getDstAddrDotNotation() << ")ip.id(" << getID() << ")" ;
	std::cout << "ip.hdrlen(" << getIPHeaderLength() << ")ip.len(" << getPacketLength() << ")ip.ttl(" << (int)getTTL() << ")" << std::endl;
#endif

	if (isFragment() == true) {
		++total_events_;
		++total_frag_packets_;
		packet.setPacketAnomaly(PacketAnomalyType::IPV4_FRAGMENTATION);
                anomaly_->incAnomaly(PacketAnomalyType::IPV4_FRAGMENTATION);
		return false;
	}
	return true;
}


void IPProtocol::processFlow(Flow *flow) {

	// TODO: Encapsulations such as ip over ip	
}

void IPProtocol::statistics(std::basic_ostream<char> &out, int level){

	if (level > 0) {
		int64_t alloc_memory = getAllocatedMemory();
		std::string unit = "Bytes";

		unitConverter(alloc_memory,unit);

		out << getName() << "(" << this <<") statistics" << std::endl;
		out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ << std::endl;
		if (level > 1) {
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << std::endl;
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << std::endl;
			if (level > 3) {
				out << "\t" << "Total fragment packets: " << std::setw(10) << total_frag_packets_ << std::endl;
			}
			if (level > 2) {
				if (mux_.lock())
					mux_.lock()->statistics(out);
			}
		}
	}
}

CounterMap IPProtocol::getCounters() const {
	CounterMap cm;

	cm.addKeyValue("packets", total_packets_);
	cm.addKeyValue("bytes", total_bytes_);
	cm.addKeyValue("fragmented packets", total_frag_packets_);

       	return cm;
}

} // namespace aiengine
