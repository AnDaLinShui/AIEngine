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
#ifndef SRC_PROTOCOLS_SIP_SIPINFO_H_
#define SRC_PROTOCOLS_SIP_SIPINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <algorithm>
#include <arpa/inet.h>
#include "Pointer.h"
#include "StringCache.h"
#include "FlowInfo.h"

namespace aiengine {

class SIPInfo : public FlowInfo {
public:
    	explicit SIPInfo() { reset(); }
    	virtual ~SIPInfo() {}

	void reset(); 
	void serialize(JsonFlow &j); 
	void resetStrings();

        SharedPointer<StringCache> uri;
        SharedPointer<StringCache> from;
        SharedPointer<StringCache> to;
        SharedPointer<StringCache> via;

	struct in_addr src_addr;
        struct in_addr dst_addr;
	uint16_t src_port;
	uint16_t dst_port;

	friend std::ostream& operator<< (std::ostream &out, const SIPInfo &info);

	uint8_t getState() const { return state_; }
	void setState(uint8_t state) { state_ = state; }

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
	const char *getUri() const { return (uri ? uri->getName() : "");}	
	const char *getFrom() const { return (from ? from->getName() : "");}	
	const char *getTo() const { return (to ? to->getName() : "");}	
	const char *getVia() const { return (via ? via->getName() : "");}	
#endif

private:
	uint8_t state_;	
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SIP_SIPINFO_H_
