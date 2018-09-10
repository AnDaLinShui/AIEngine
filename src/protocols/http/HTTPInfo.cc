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
#include "HTTPInfo.h"

namespace aiengine {

void HTTPInfo::reset() {

	direction_ = FlowDirection::NONE; 
	content_length_ = 0; 
	data_chunk_length_ = 0; 
	have_data_ = false; 
	is_banned_ = false;
	total_requests_ = 0;
	total_responses_ = 0;
	response_code_ = 0; 
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
	needs_release_ = false; 
#endif
	write_uri_ = false;
	matched_domain_name.reset();
	resetStrings(); 
}

void HTTPInfo::serialize(JsonFlow &j) {

#if !defined(RUBY_BINDING)
       	j.j["info"]["reqs"] = total_requests_;
       	j.j["info"]["ress"] = total_responses_;

        if (host_name)
        	j.j["info"]["host"] = host_name->getName();

        if (ct)
               	j.j["info"]["ctype"] = ct->getName();

        if (filename)
               	j.j["info"]["filename"] = filename->getName();

        if (matched_domain_name)
               	j.j["info"]["matchs"] = matched_domain_name->getName();

	if (write_uri_) {
		j.j["info"]["uri"] = uri->getName();
		write_uri_ = false; // Just write one time
	}
#else
        std::map<std::string, json_map_t> info;

       	info["reqs"] = total_requests_;
       	info["ress"] = total_responses_;

       	if (host_name)
        	info["host"] = host_name->getName();
      
       	if (ct)
               	info["ctype"] = ct->getName();

       	if (filename)
               	info["filename"] = filename->getName();

       	if (matched_domain_name)
               	info["matchs"] = matched_domain_name->getName();

	if (write_uri_) {
		info["uri"] = uri->getName();
		write_uri_ = false; // Just write one time
	}

       	j.j["info"] = info;
#endif
}

void HTTPInfo::resetStrings() { 

	uri.reset(); 
	host_name.reset(); 
	ua.reset(); 
	ct.reset();
	filename.reset();
}

std::ostream& operator<< (std::ostream &out, const HTTPInfo &info) {

	out << " Req(" << info.getTotalRequests();
	out << ")Res(" << info.getTotalResponses();
	out << ")Code(" << info.getResponseCode() << ") ";

	if (info.isBanned()) out << "Banned";
	if (info.host_name) out << " Host:" << info.host_name->getName();
	if (info.ct) out << " ContentType:" << info.ct->getName();
	if (info.filename) out << " Filename:" << info.filename->getName();
	if (info.ua) out << " UserAgent:" << info.ua->getName();

        return out;
}

} // namespace aiengine
