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
#include "SSHInfo.h"

namespace aiengine {

void SSHInfo::reset() { 

	total_encrypted_bytes_ = 0;
	is_client_handshake_ = true;
	is_server_handshake_ = true;
}

void SSHInfo::serialize(JsonFlow &j) {

#if !defined(RUBY_BINDING)
       	j.j["info"]["handshake"] = isHandshake();

        j.j["info"]["crypt_bytes"] = total_encrypted_bytes_;
#else
        std::map<std::string, json_map_t> info;

        info["handshake"] = isHandshake();
        info["crypt_bytes"] = total_encrypted_bytes_;

        j.j["info"] = info;
#endif
}

std::ostream& operator<< (std::ostream &out, const SSHInfo &info) {

	out << " Handshake:" << (info.isHandshake() ? "True" : "False"); 
	if (info.isHandshake() == false)
		out << " CBytes:" << info.total_encrypted_bytes_;

        return out;
}

} // namespace aiengine
