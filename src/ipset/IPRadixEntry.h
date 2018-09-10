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
#ifndef SRC_IPSET_IPRADIXENTRY_H_
#define SRC_IPSET_IPRADIXENTRY_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

namespace aiengine {

class IPRadixEntry {
public:
	uint32_t addr;
	int prefix_len;

	IPRadixEntry(uint32_t ip, int prefix): addr(ip), prefix_len(prefix) {}
	IPRadixEntry(): IPRadixEntry(0, 0) {}

    	uint32_t operator[] (int n) const {
        	if (addr & (0x80000000 >> n))
            		return 1;
        	else
            		return 0;
    	}


	bool operator== (const IPRadixEntry &rhs) const {
		return prefix_len == rhs.prefix_len && addr == rhs.addr;
	}

	bool operator< (const IPRadixEntry &rhs) const {
		if (addr == rhs.addr)
			return prefix_len < rhs.prefix_len;
		else
			return addr < rhs.addr;
	}

};

static IPRadixEntry radix_substr(const IPRadixEntry &entry, int begin, int num)
{
    uint32_t mask;

    if (num == 32)
        mask = 0;
    else
        mask = 1 << num;

    mask  -= 1;
    mask <<= 32 - num - begin;

    IPRadixEntry ret((entry.addr & mask) << begin, num);

    return ret;
}

static IPRadixEntry radix_join(const IPRadixEntry &entry1, const IPRadixEntry &entry2)
{
    IPRadixEntry ret(entry1.addr, entry1.prefix_len + entry2.prefix_len);

    ret.addr       |= entry2.addr >> entry1.prefix_len;

    return ret;
}

static int radix_length(const IPRadixEntry &entry)
{
    return entry.prefix_len;
}

} // namespace aiengine

#endif  // SRC_IPSET_IPRADIXENTRY_H_
