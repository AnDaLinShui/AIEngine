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
#include "DHCPInfo.h"

namespace aiengine {

void DHCPInfo::reset() { 
	lease_time_ = 0;
	host_name.reset();
	ip.reset();
}

void DHCPInfo::serialize(JsonFlow &j) {

#if !defined(RUBY_BINDING)
        if (host_name)
                j.j["info"]["hostname"] = host_name->getName();
        
	if (ip)
                j.j["info"]["ip"] = ip->getName();

        if (lease_time_ > 0)
                j.j["info"]["leasetime"] = lease_time_;
#else
        std::map<std::string, json_map_t> info;

        if (host_name)
                info["hostname"] = host_name->getName();

        if (ip)
                info["ip"] = ip->getName();

       	if (lease_time_ > 0)
                info["leasetime"] = lease_time_;

        j.j["info"] = info;
#endif
}

std::ostream& operator<< (std::ostream &out, const DHCPInfo &info) {

	if (info.host_name) out << " Host:" << info.host_name->getName();
	if (info.ip) out << " IP:" << info.ip->getName();
	if (info.getLeaseTime() > 0) out << " Lease:" << info.getLeaseTime();

	return out;
}

} // namespace aiengine

