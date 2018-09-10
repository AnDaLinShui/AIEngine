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
#include "SMTPInfo.h"

namespace aiengine {

void SMTPInfo::reset() { 
	resetStrings();
	command_ = 0;
	is_banned_ = false; 
	is_data_ = false; 
	is_starttls_ = false; 
	total_data_bytes_ = 0;
	total_data_blocks_ = 0;
}

void SMTPInfo::serialize(JsonFlow &j) {

#if !defined(RUBY_BINDING)
       	j.j["info"]["total"] = total_data_blocks_;
       	j.j["info"]["bytes"] = total_data_bytes_;

        if (from)
                j.j["info"]["from"] = from->getName();

        if (to)
                j.j["info"]["to"] = to->getName();

	if (is_starttls_)
		j.j["info"]["tls"] = true;
#else
        std::map<std::string, json_map_t> info;

       	info["total"] = total_data_blocks_;
       	info["bytes"] = total_data_bytes_;

        if (from)
                info["from"] = from->getName();

        if (to)
                info["to"] = to->getName();
	
	if (is_starttls_)
		info["tls"] = true;
      
       	j.j["info"] = info;
#endif
}
	
void SMTPInfo::resetStrings() { 

	matched_domain_name.reset();
	from.reset(); 
	to.reset(); 
}

std::ostream& operator<< (std::ostream &out, const SMTPInfo &info) {

	if (info.isBanned()) out << "Banned";
	if (info.from)  out << " From:" << info.from->getName();
	if (info.to) out << " To:" << info.to->getName();

	return out;
}

} // namespace aiengine
