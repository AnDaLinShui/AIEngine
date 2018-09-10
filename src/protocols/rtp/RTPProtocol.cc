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
#include "RTPProtocol.h"
#include <iomanip>

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr RTPProtocol::logger(log4cxx::Logger::getLogger("aiengine.rtp"));
#endif

RTPProtocol::RTPProtocol():
	Protocol("RTPProtocol", "rtp", IPPROTO_UDP),
	header_(nullptr),
	current_flow_(nullptr),
	anomaly_() {} 

RTPProtocol::~RTPProtocol() {

	anomaly_.reset();
}

bool RTPProtocol::rtpChecker(Packet &packet) {

	int length = packet.getLength();

	if (length >= header_size) {
		setHeader(packet.getPayload());
		if (header_->version == 0x80) {
			++total_valid_packets_;
			return true;
		}
	}
	++total_invalid_packets_;
	return false;
}

int64_t RTPProtocol::getAllocatedMemory() const {

        int64_t mem = sizeof(RTPProtocol);

        return mem;
}

int64_t RTPProtocol::getTotalAllocatedMemory() const {

	return getAllocatedMemory();
}

uint8_t RTPProtocol::getPayloadType() const { 

	uint8_t pt = header_->payload_type;
	
	// Check if the first bit is set
	if (((pt) & (1 << 7)) != 0) 
		pt &= ~(1 << 7); // Sets the first bit to zero

	return pt;
}

void RTPProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;
	++flow->total_packets_l7;

	current_flow_ = flow;

	if (length >= header_size) {
		setHeader(flow->packet->getPayload());
		if (header_->version == 0x80) {
			// TODO, process for zrtp?
		}
	} else {
                if (flow->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        flow->setPacketAnomaly(PacketAnomalyType::RTP_BOGUS_HEADER);
                }
                anomaly_->incAnomaly(PacketAnomalyType::RTP_BOGUS_HEADER);
	}
}

void RTPProtocol::statistics(std::basic_ostream<char>& out, int level) { 

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

CounterMap RTPProtocol::getCounters() const {
       	CounterMap cm;
 
        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);

        return cm;
}

} // namespace aiengine
