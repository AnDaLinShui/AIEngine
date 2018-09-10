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
#ifndef SRC_PROTOCOLS_DHCPv6_DHCPv6INFO_H_
#define SRC_PROTOCOLS_DHCPv6_DHCPv6INFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include "Pointer.h"
#include "StringCache.h"
#include "FlowInfo.h"

namespace aiengine {

class DHCPv6Info : public FlowInfo {
public:
    	explicit DHCPv6Info() { reset(); }
    	virtual ~DHCPv6Info() {}

	void reset(); 
	void serialize(JsonFlow &j); 

	// TODO Check RFC3315
	void setLifetime(uint32_t t1, uint32_t t2) { t1_ = t1; t2_ = t2; }
	uint32_t getT1() const { return t1_; }
	uint32_t getT2() const { return t2_; }

	SharedPointer<StringCache> host_name;
	SharedPointer<StringCache> ip6;

	friend std::ostream& operator<< (std::ostream &out, const DHCPv6Info &info); 

#if defined(BINDING)
	const char *getHostName() const { return (host_name ? host_name->getName() : ""); }
	const char *getIPAddress() const { return (ip6 ? ip6->getName() : ""); }
#endif
private:
	uint32_t t1_;
	uint32_t t2_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_DHCPv6_DHCPv6INFO_H_
