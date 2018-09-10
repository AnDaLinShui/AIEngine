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
#include "NTPProtocol.h"
#include <iomanip>

namespace aiengine {

NTPProtocol::NTPProtocol():
	Protocol("NTPProtocol", "ntp", IPPROTO_UDP),
	header_(nullptr),
	total_ntp_unspecified_(0),
	total_ntp_sym_active_(0),
	total_ntp_sym_passive_(0),
	total_ntp_client_(0),
	total_ntp_server_(0),
	total_ntp_broadcast_(0),
	total_ntp_reserved_(0) {} 

bool NTPProtocol::ntpChecker(Packet &packet) {

	int length = packet.getLength();

	if (length >= header_size) {
		if ((packet.getSourcePort() == 123)||(packet.getDestinationPort() == 123)) {
			setHeader(packet.getPayload());
			++total_valid_packets_;
			return true;
		}
	}
	++total_invalid_packets_;
	return false;
}

void NTPProtocol::processFlow(Flow *flow) {

	setHeader(flow->packet->getPayload());	
	uint8_t mode = getMode();
	total_bytes_ += flow->packet->getLength();

	++total_packets_;

	if (mode == NTP_MODE_CLIENT) {
		++total_ntp_client_;
	} else if (mode == NTP_MODE_SERVER) {
		++total_ntp_server_;
	} else if (mode == NTP_MODE_UNSPEC) {
		++total_ntp_unspecified_;
	} else if (mode == NTP_MODE_SYM_ACT) {
		++total_ntp_sym_active_;
	} else if (mode == NTP_MODE_SYM_PAS) {
		++total_ntp_sym_passive_;
	} else if (mode == NTP_MODE_BROADCAST) {
		++total_ntp_broadcast_;
	} else if ((mode == NTP_MODE_RES1)or(mode == NTP_MODE_RES2)) {
		++total_ntp_reserved_;	
	}	
}

void NTPProtocol::statistics(std::basic_ostream<char> &out, int level){ 

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
                                out << "\t" << "Total clients:          " << std::setw(10) << total_ntp_client_ << std::endl;
                                out << "\t" << "Total servers:          " << std::setw(10) << total_ntp_server_ << std::endl;
                                out << "\t" << "Total unspecifieds:     " << std::setw(10) << total_ntp_unspecified_ << std::endl;
                                out << "\t" << "Total sym actives:      " << std::setw(10) << total_ntp_sym_active_ << std::endl;
                                out << "\t" << "Total sym passives:     " << std::setw(10) << total_ntp_sym_passive_ << std::endl;
                                out << "\t" << "Total broadcasts:       " << std::setw(10) << total_ntp_broadcast_ << std::endl;
                                out << "\t" << "Total reserveds:        " << std::setw(10) << total_ntp_reserved_ << std::endl;
                        } 
			if (level > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
			}
		}
	}
}

CounterMap NTPProtocol::getCounters() const {
    	CounterMap cm;
 
        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
	cm.addKeyValue("clients", total_ntp_client_);
	cm.addKeyValue("servers", total_ntp_server_);
	cm.addKeyValue("unspecifieds", total_ntp_unspecified_);
	cm.addKeyValue("sym actives", total_ntp_sym_active_);
	cm.addKeyValue("sym passives", total_ntp_sym_passive_);
	cm.addKeyValue("broadcasts", total_ntp_broadcast_);
	cm.addKeyValue("reserveds", total_ntp_reserved_);
	
        return cm;
}

} // namespace aiengine
