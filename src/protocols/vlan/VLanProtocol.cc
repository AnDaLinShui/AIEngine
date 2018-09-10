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
#include "VLanProtocol.h"
#include <iomanip>

namespace aiengine {

VLanProtocol::VLanProtocol():
	Protocol("VLanProtocol","vlan"),
	header_(nullptr) {}

bool VLanProtocol::vlanChecker(Packet &packet){

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

bool VLanProtocol::processPacket(Packet &packet) { 

	++total_packets_;
	total_bytes_ += packet.getLength();

	if (!mux_.expired()) {
        	MultiplexerPtr mux = mux_.lock();

                mux->setNextProtocolIdentifier(getEthernetType());

                // Sets the Tag for the packet
                packet.setTag(getVlanId());
                
		mux->setHeaderSize(header_size);
                packet.setPrevHeaderSize(header_size);
        }
	return true;
}

void VLanProtocol::statistics(std::basic_ostream<char>& out, int level){ 

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
			if (level > 2) {
				if (mux_.lock())
					mux_.lock()->statistics(out);
			}
		}
	}
}

CounterMap VLanProtocol::getCounters() const {
	CounterMap cm;

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);

        return cm;
}

} // namespace aiengine
