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
#include "DNSInfo.h"

namespace aiengine {

void DNSInfo::reset() { 

	name.reset() ; 
	qtype_ = 0; 
	items_.clear(); 
	matched_domain_name.reset(); 
	is_banned_ = false;
}

void DNSInfo::serialize(JsonFlow &j) {

#if !defined(RUBY_BINDING)
        if (name)
         	j.j["info"]["dnsdomain"] = name->getName();

        if (matched_domain_name)
                j.j["info"]["matchs"] = matched_domain_name->getName();

       	j.j["info"]["qtype"] = qtype_;

        if (items_.size() > 0 )
               j.j["info"]["ips"] = items_;
#else
        std::map<std::string, json_map_t> info;

        if (name)
                info["dnsdomain"] = name->getName();

        if (matched_domain_name)
                info["matchs"] = matched_domain_name->getName();

       	info["qtype"] = qtype_;

       	if (items_.size() > 0 )
        	info["ips"] = items_;

        j.j["info"] = info;
#endif
}

void DNSInfo::addIPAddress(const char* ipstr) { 
	
	items_.emplace_back(ipstr); 
}

void DNSInfo::addName(const char* name) { 
	
	items_.emplace_back(name); 
}

void DNSInfo::addName(const char *name, int length) {

	items_.emplace_back(name, length);
}

std::ostream& operator<< (std::ostream &out, const DNSInfo &info) {

	if (info.isBanned()) out << "Banned";
	if (info.name) out << " Domain:" << info.name->getName();

	return out;
}

} // namespace aiengine
