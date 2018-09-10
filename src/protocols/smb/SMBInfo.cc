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
#include "SMBInfo.h"

namespace aiengine {

void SMBInfo::reset() { 

	filename.reset();	
	command_ = 0;
}

void SMBInfo::serialize(JsonFlow &j) {

#if !defined(RUBY_BINDING)
        j.j["info"]["cmd"] = command_;

        if (filename)
                j.j["info"]["filename"] = filename->getName();
#else
        std::map<std::string, json_map_t> info;

        info["cmd"] = command_; 

        if (filename)
                info["filename"] = filename->getName();

        j.j["info"] = info;
#endif
}

std::ostream& operator<< (std::ostream &out, const SMBInfo &info) {

	out << " CMD:" << info.command_;
        if (info.filename)
                out << " File:" <<  info.filename->getName();

	return out;
}

} // namespace aiengine

