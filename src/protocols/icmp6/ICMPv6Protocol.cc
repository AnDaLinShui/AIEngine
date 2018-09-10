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
#include "ICMPv6Protocol.h"
#include <iomanip> // setw

namespace aiengine {

ICMPv6Protocol::ICMPv6Protocol():
	Protocol("ICMPv6Protocol", "icmp6"),
	header_(nullptr),
	total_echo_request_(0),
	total_echo_replay_(0),
	total_destination_unreachable_(0),
	total_redirect_(0),
	total_router_advertisment_(0),
	total_router_solicitation_(0),
	total_ttl_exceeded_(0) {}

bool ICMPv6Protocol::icmp6Checker(Packet &packet) {

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

void ICMPv6Protocol::statistics(std::basic_ostream<char> &out, int level) {

	if (level > 0) {
                int64_t alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory,unit);

                out << getName() << "(" << this <<") statistics" << std::dec << "\n";
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << "\n";
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << std::endl;;
		if (level > 1) {
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << "\n";
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << "\n";
                        if (level > 3) {
                                out << "\t" << "Total echo requests:    " << std::setw(10) << total_echo_request_ << "\n";
                                out << "\t" << "Total echo replays:     " << std::setw(10) << total_echo_replay_ << "\n";
                                out << "\t" << "Total dest unreachables:" << std::setw(10) << total_destination_unreachable_ << "\n";
                                out << "\t" << "Total redirects:        " << std::setw(10) << total_redirect_ << "\n";
                                out << "\t" << "Total rt advertistments:" << std::setw(10) << total_router_advertisment_ << "\n";
                                out << "\t" << "Total rt solicitations: " << std::setw(10) << total_router_solicitation_ << "\n";
                                out << "\t" << "Total ttl exceededs:    " << std::setw(10) << total_ttl_exceeded_ << std::endl;
                        }
			if (level > 2) {
				if (mux_.lock())
					mux_.lock()->statistics(out);
			}
		}
	}
}

bool ICMPv6Protocol::processPacket(Packet &packet) {

        uint16_t type = getType();

        if (type == ICMP6_ECHO_REQUEST)
                ++total_echo_request_;
        else if (type == ICMP6_ECHO_REPLY)
                ++total_echo_replay_;
        else if (type == ICMP6_DST_UNREACH)
                ++total_destination_unreachable_;
        else if (type == ND_REDIRECT)
                ++total_redirect_;
        else if (type == ND_ROUTER_ADVERT)
                ++total_router_advertisment_;
        else if (type == ND_ROUTER_SOLICIT)
                ++total_router_solicitation_;
        else if (type == ICMP6_TIME_EXCEEDED)
                ++total_ttl_exceeded_;

	total_bytes_ += packet.getLength();
	++total_packets_;

	return true;
}

CounterMap ICMPv6Protocol::getCounters() const {
	CounterMap cm;

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("echo", total_echo_request_);
        cm.addKeyValue("echoreply", total_echo_replay_);
        cm.addKeyValue("destination unreach", total_destination_unreachable_);
        cm.addKeyValue("redirect", total_redirect_);
        cm.addKeyValue("router advertisment", total_router_advertisment_);
        cm.addKeyValue("router solicitation", total_router_solicitation_);
        cm.addKeyValue("time exceeded", total_ttl_exceeded_);

        return cm;
}

} // namespace aiengine
 
