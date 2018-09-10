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
#include "IMAPInfo.h"

namespace aiengine {

void IMAPInfo::reset() { 
	client_commands_ = 0;
	server_commands_ = 0;
	user_name.reset();
	is_banned_ = false;
	is_starttls_ = false;
}

void IMAPInfo::serialize(JsonFlow &j) {

#if !defined(RUBY_BINDING)
        if (user_name)
                j.j["info"]["user"] = user_name->getName();

	if (is_starttls_)
		j.j["info"]["tls"] = true;
#else
        std::map<std::string, json_map_t> info;

        if (user_name)
                info["user"] = user_name->getName();
	
	if (is_starttls_)
		info["tls"] = true;

        j.j["info"] = info;
#endif
}

std::ostream& operator<< (std::ostream &out, const IMAPInfo &info) {

	if (info.isBanned()) out << "Banned";
	if (info.user_name) out << " User:" << info.user_name->getName();

	return out;
}

} // namespace aiengine

