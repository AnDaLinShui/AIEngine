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
#include "TCPInfo.h"

namespace aiengine {

void TCPInfo::reset() { 
	syn = 0; syn_ack = 0; ack= 0; fin = 0; rst = 0; push= 0; 
	seq_num[0] = 0; 
	seq_num[1] = 0; 
	state_prev = static_cast<int>(TcpState::CLOSED);
	state_curr = static_cast<int>(TcpState::CLOSED);
#if defined(HAVE_TCP_QOS_METRICS)
	last_sample_time = 0;
	last_client_data_time = 0;
	connection_setup_time = 0;
	server_reset_rate = 0;
	application_response_time = 0;
#endif	
}

void TCPInfo::serialize(JsonFlow &j) {

	std::ostringstream out;
	
	out << *this;
#if !defined(RUBY_BINDING)
       	j.j["info"]["tcpflags"] = out.str();
#else
        std::map<std::string, json_map_t> info;

       	info["tcpflags"] = out.str();
       	j.j["info"] = info;
#endif
}

std::ostream& operator<< (std::ostream &out, const TCPInfo &info) {

	out << "Flg[S(" << info.syn << ")SA(" << info.syn_ack << ")A(" << info.ack;
	out << ")F(" << info.fin << ")R(" << info.rst << ")P(" << info.push << ")Seq(" << info.seq_num[0] << "," << info.seq_num[1] << ")]";
#if defined(HAVE_TCP_QOS_METRICS)
	out << "QoS[ST(" << info.connection_setup_time << ")RR(" << info.server_reset_rate << ")";
	out << "RT(" << info.application_response_time << ")]";
#endif
	return out;
}

} // namespace aiengine
