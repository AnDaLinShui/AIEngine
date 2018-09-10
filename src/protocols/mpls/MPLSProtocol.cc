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
#include "MPLSProtocol.h"
#include <iomanip> // setw
#include <bitset>

namespace aiengine {

MPLSProtocol::MPLSProtocol():
	Protocol("MPLSProtocol", "mpls"),
	header_(nullptr) {}

bool MPLSProtocol::mplsChecker(Packet &packet) {

	int length = packet.getLength();

	if (length >= header_size) {
		setHeader(packet.getPayload());
		++total_valid_packets_;
		return true;
	} else {
		++total_invalid_packets_;
		return false;
	}
}

bool MPLSProtocol::processPacket(Packet &packet) {

        MultiplexerPtr mux = mux_.lock();
        ++total_packets_;
        total_bytes_ += packet.getLength();

        if (mux) {
		uint32_t label;
		int mpls_header_size = 0;
		int counter = 0;
		const uint8_t *mpls_header = header_;
		bool sw = true;

		// Process the MPLS Header and forward to the next level
		do {
			label = mpls_header[0] << 12;
			label |= mpls_header[1] << 4;
			label |= mpls_header[2] >> 4;
	
			std::bitset<1> b1(mpls_header[2]);

			mpls_header = (mpls_header + 4);
			mpls_header_size += 4;
			++counter;
			if ((b1[0] == true)||(counter > 2)) sw = false;
		} while(sw);

		mux->setHeaderSize(mpls_header_size);			       
		packet.setPrevHeaderSize(mpls_header_size); 
		mux->setNextProtocolIdentifier(ETHERTYPE_IP);
        }

	return true;
}

void MPLSProtocol::statistics(std::basic_ostream<char> &out, int level) {

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
				if (mux_.lock())
					mux_.lock()->statistics(out);
			}
		}
	}
}

CounterMap MPLSProtocol::getCounters() const {
	CounterMap cm;
 
        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);

        return cm;
}

} // namespace aiengine
