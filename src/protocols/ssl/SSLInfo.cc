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
#include "SSLInfo.h"

namespace aiengine {

void SSLInfo::reset() {

	host_name.reset();
	issuer.reset();
	matched_domain_name.reset();
	is_banned_ = false;
	data_pdus_ = 0;
	version_ = 0;
	heartbeat_ = false;
	alert_ = false;
	alert_code_ = 0;
	cipher_ = 0;
}
 
void SSLInfo::serialize(JsonFlow &j) {

#if !defined(RUBY_BINDING)
       	j.j["info"]["pdus"] = data_pdus_;
	j.j["info"]["cipher"] = cipher_;	

        if (alert_)
               j.j["info"]["alert"] = alert_code_;

        if (heartbeat_)
               j.j["info"]["heartbeat"] = "yes";

        if (host_name)
               j.j["info"]["host"] = host_name->getName();

        if (issuer)
               j.j["info"]["issuer"] = issuer->getName();

        if (matched_domain_name)
                j.j["info"]["matchs"] = matched_domain_name->getName();
#else
        std::map<std::string, json_map_t> info;

       	info["pdus"] = data_pdus_;
	info["cipher"] = cipher_;	

       	if (alert_)
               info["alert"] = alert_code_;

       	if (heartbeat_)
               info["heartbeat"] = "yes";

       	if (host_name)
               info["host"] = host_name->getName();

       	if (issuer)
               info["issuer"] = issuer->getName();

        if (matched_domain_name)
                info["matchs"] = matched_domain_name->getName();

       	j.j["info"] = info;
#endif
}

std::ostream& operator<< (std::ostream &out, const SSLInfo &info) {

	out << " Pdus:" << info.getTotalDataPdus();
	out << " Cipher:0x" << std::hex << info.cipher_ << std::dec;
	if (info.isBanned()) out << "Banned";
	if (info.host_name) out << " Host:" << info.host_name->getName();
	if (info.issuer) out << " Issuer:" << info.issuer->getName();

	return out;
}

} // namespace aiengine  
