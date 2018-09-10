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
#include "MQTTInfo.h"

namespace aiengine {

void MQTTInfo::reset() { 
	have_data_ = false;
	command_ = 0;
	total_server_commands_ = 0;
	total_client_commands_ = 0;
	data_chunk_length_ = 0;
	topic.reset();
}

void MQTTInfo::serialize(JsonFlow &j) {

#if !defined(RUBY_BINDING)
       	j.j["info"]["operation"] = (int)command_;
        j.j["info"]["total_server"] = total_server_commands_;
        j.j["info"]["total_client"] = total_client_commands_;

        if (topic)
        	j.j["info"]["topic"] = topic->getName();
#else
        std::map<std::string, json_map_t> info;

        info["operation"] = (int)command_;
        info["total_server"] = total_server_commands_;
        info["total_client"] = total_client_commands_;

        if (topic)
                info["topic"] = topic->getName();

       	j.j["info"] = info;
#endif
}

std::ostream& operator<< (std::ostream &out, const MQTTInfo &info) {

	out << " Cmd(" << (int)info.getCommand();
	out << ")Cli(" << info.getTotalClientCommands();
	out << ")Ser(" << info.getTotalServerCommands() << ") ";

	if (info.topic) out << " Topic:" << info.topic->getName();

	return out;
}
	
} // namespace aiengine
