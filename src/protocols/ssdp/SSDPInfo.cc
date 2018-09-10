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
#include "SSDPInfo.h"

namespace aiengine {

void SSDPInfo::reset() {
	is_banned_ = false; 
	total_requests_ = 0;
	total_responses_ = 0;
	response_code_ = 0;
	host_name.reset(); 
	uri.reset();
	matched_domain_name.reset();
}

void SSDPInfo::serialize(JsonFlow &j) {

#if !defined(RUBY_BINDING)
       	j.j["info"]["reqs"] = total_requests_;
        j.j["info"]["ress"] = total_responses_;

        if (host_name)
                j.j["info"]["host"] = host_name->getName();

        if (uri)
                j.j["info"]["uri"] = uri->getName();

        if (matched_domain_name)
               j.j["info"]["matchs"] = matched_domain_name->getName();
#else
        std::map<std::string, json_map_t> info;

        info["reqs"] = total_requests_;
        info["ress"] = total_responses_;

        if (host_name)
                info["host"] = host_name->getName();

        if (uri)
                info["uri"] = uri->getName();

        if (matched_domain_name)
               info["matchs"] = matched_domain_name->getName();

        j.j["info"] = info;
#endif
}

void SSDPInfo::resetStrings() { 

	uri.reset();
	host_name.reset(); 
}

std::ostream& operator<< (std::ostream &out, const SSDPInfo &info) {

	if (info.isBanned()) out << "Banned";
	if (info.host_name) out << " Host:" << info.host_name->getName();
	if (info.uri) out << " Uri:" << info.uri->getName();

	return out;
}

} // namespace aiengine

