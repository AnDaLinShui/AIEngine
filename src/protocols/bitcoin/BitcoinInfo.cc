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
#include "BitcoinInfo.h"

namespace aiengine {

void BitcoinInfo::reset() {
	total_transactions_ = 0;
	total_blocks_ = 0;
	total_rejects_ = 0;
}

void BitcoinInfo::serialize(JsonFlow &j) {

#if !defined(RUBY_BINDING)
       	j.j["info"]["tx"] = total_transactions_;
       	j.j["info"]["blocks"] = total_blocks_;
       	j.j["info"]["rejects"] = total_rejects_;
#else
        std::map<std::string, json_map_t> info;

       	info["tx"] = total_transactions_;
       	info["blocks"] = total_blocks_;
       	info["rejects"] = total_rejects_;

        j.j["info"] = info;
#endif
}

std::ostream& operator<< (std::ostream &out, const BitcoinInfo &info) {

	out << " TX:" << info.total_transactions_;
	out << " Blocks:" << info.total_blocks_;
	out << " Rejects:" << info.total_rejects_;

	return out;
}

} // namespace aiengine  
