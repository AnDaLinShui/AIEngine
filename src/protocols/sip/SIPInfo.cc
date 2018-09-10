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
#include "SIPInfo.h"
#include "SIPProtocol.h"

namespace aiengine {

void SIPInfo::reset() { 

	resetStrings();
	state_ = SIP_NONE;
	src_port = 0;
	dst_port = 0;
	src_addr.s_addr = 0;
	dst_addr.s_addr = 0;
}

void SIPInfo::resetStrings() { 

	uri.reset(); 
	from.reset(); 
	to.reset(); 
	via.reset(); 
}

void SIPInfo::serialize(JsonFlow &j) {

#if !defined(RUBY_BINDING)
	if (uri)
        	j.j["info"]["uri"] = uri->getName();

        if (from)
                j.j["info"]["from"] = from->getName();

        if (to)
                j.j["info"]["to"] = to->getName();

        if (via)
                j.j["info"]["via"] = via->getName();

	if (state_ == SIP_CALL_ESTABLISHED) {
		// All the values are populated
		j.j["info"]["voip"]["ip"]["src"] = inet_ntoa(src_addr);
		j.j["info"]["voip"]["ip"]["dst"] = inet_ntoa(dst_addr);
		j.j["info"]["voip"]["port"]["src"] = src_port;
		j.j["info"]["voip"]["port"]["dst"] = dst_port;
	}
#else
        std::map<std::string, json_map_t> info;

        if (uri)
                info["uri"] = uri->getName();

        if (from)
                info["from"] = from->getName();

        if (to)
                info["to"] = to->getName();

        if (via)
                info["via"] = via->getName();

        j.j["info"] = info;

	if (state_ == SIP_CALL_ESTABLISHED) {
		// TODO
        	//std::map<std::string, json_map_t> voip;
        	std::map<std::string, json_map_t> addr;
        	std::map<std::string, json_map_t> port;

        	addr["src"] = inet_ntoa(src_addr);
        	addr["dst"] = inet_ntoa(dst_addr);
        	//j.j["ip"] = addr;

        	port["src"] = src_port;
        	port["dst"] = dst_port;
        	//j.j["port"] = port;

		//j.j["voip"] = voip;
	}
#endif
}

std::ostream& operator<< (std::ostream &out, const SIPInfo &info) {

	if (info.uri) out << " Uri:" << info.uri->getName();
	if (info.from) out << " From:" << info.from->getName();
	if (info.to) out << " To:" << info.to->getName();
        if (info.via) out << " Via:" << info.via->getName();
	if (info.state_ == SIP_CALL_ESTABLISHED) out << " OnCall";
	if (info.state_ == SIP_TRYING_CALL) out << " TryingCall";
 
        return out;
}

} // namespace aiengine
