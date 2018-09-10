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
#include "ICMPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

ICMPProtocol::ICMPProtocol():
	Protocol("ICMPProtocol", "icmp"),
	header_(nullptr),
	total_echo_request_(0),
	total_echo_replay_(0),
	total_destination_unreachable_(0),
	total_source_quench_(0),
	total_redirect_(0),
	total_router_advertisment_(0),
	total_router_solicitation_(0),
	total_ttl_exceeded_(0),
	total_timestamp_request_(0),
	total_timestamp_replay_(0),
	total_others_(0) {}

// Condition for say that a packet is icmp
bool ICMPProtocol::icmpChecker(Packet &packet) {

	int length = packet.getLength();

	setHeader(packet.getPayload());

	if (length >= header_size) {
		++total_valid_packets_;
		return true;
	} else {
		++total_invalid_packets_;
		return false;
	}
}

void ICMPProtocol::statistics(std::basic_ostream<char> &out, int level) {

	if (level > 0) {
                int64_t alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory,unit);

                out << getName() << "(" << this <<") statistics" << std::dec << "\n";
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << "\n";
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << "\n";
		out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ << std::endl;
		if (level > 1) {
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << "\n";
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << "\n";
                        if (level > 3) {
                                out << "\t" << "Total echo requests:    " << std::setw(10) << total_echo_request_ << "\n";
                                out << "\t" << "Total echo replays:     " << std::setw(10) << total_echo_replay_ << "\n";
                                out << "\t" << "Total dest unreachables:" << std::setw(10) << total_destination_unreachable_ << "\n";
                                out << "\t" << "Total source quenchs:   " << std::setw(10) << total_source_quench_ << "\n";
                                out << "\t" << "Total redirects:        " << std::setw(10) << total_redirect_ << "\n";
                                out << "\t" << "Total rt advertistments:" << std::setw(10) << total_router_advertisment_ << "\n";
                                out << "\t" << "Total rt solicitations: " << std::setw(10) << total_router_solicitation_ << "\n";
                                out << "\t" << "Total ttl exceededs:    " << std::setw(10) << total_ttl_exceeded_ << "\n";
                                out << "\t" << "Total timestamp reqs:   " << std::setw(10) << total_timestamp_request_ << "\n";
                                out << "\t" << "Total timestamp reps:   " << std::setw(10) << total_timestamp_replay_ << "\n";
                                out << "\t" << "Total others:           " << std::setw(10) << total_others_ << std::endl;
                        }
			if (level > 2) {
				if (mux_.lock())
					mux_.lock()->statistics(out);
			}
		}
	}
}

bool ICMPProtocol::processPacket(Packet &packet) {

	uint16_t type = getType();

	if (type == ICMP_ECHO)
		++total_echo_request_;
	else if (type == ICMP_ECHOREPLY) 
		++total_echo_replay_;	
	else if (type == ICMP_UNREACH) 
		++total_destination_unreachable_;
	else if (type == ICMP_SOURCEQUENCH) 
		++total_source_quench_;
	else if (type == ICMP_REDIRECT) 
		++total_redirect_;
	else if (type == ICMP_ROUTERADVERT) 
		++total_router_advertisment_;
	else if (type == ICMP_ROUTERSOLICIT) 
		++total_router_solicitation_;
	else if (type == ICMP_TIMXCEED) 
		++total_ttl_exceeded_;
	else if (type == ICMP_TSTAMP) 
		++total_timestamp_request_;
	else if (type == ICMP_TSTAMPREPLY) 
		++total_timestamp_replay_;
	else
		++total_others_;

	total_bytes_ += packet.getLength();
	++total_packets_;

	return true;	
}

CounterMap ICMPProtocol::getCounters() const {
	CounterMap cm;

	cm.addKeyValue("packets", total_packets_);
	cm.addKeyValue("bytes", total_bytes_);
	cm.addKeyValue("echo", total_echo_request_);
	cm.addKeyValue("echoreplay", total_echo_replay_);
        cm.addKeyValue("destination unreach", total_destination_unreachable_);
        cm.addKeyValue("source quench", total_source_quench_);
        cm.addKeyValue("redirect", total_redirect_);
        cm.addKeyValue("router advertisment", total_router_advertisment_);
        cm.addKeyValue("router solicitation", total_router_solicitation_);
        cm.addKeyValue("time exceeded", total_ttl_exceeded_);
	cm.addKeyValue("timestamp request", total_timestamp_request_);
	cm.addKeyValue("timestamp replay", total_timestamp_replay_);

        return cm;
}

} // namespace aiengine
 
