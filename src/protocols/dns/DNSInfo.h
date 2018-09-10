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
#ifndef SRC_PROTOCOLS_DNS_DNSINFO_H_
#define SRC_PROTOCOLS_DNS_DNSINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <vector> 
#include "StringCache.h"
#include "names/DomainName.h"
#include "FlowInfo.h"

namespace aiengine {

class DNSInfo : public FlowInfo {
public:
    	explicit DNSInfo() { reset(); }
    	virtual ~DNSInfo() {}

	void reset();
	void serialize(JsonFlow &j); 

	uint16_t getQueryType() const { return qtype_; }
	void setQueryType(uint16_t qtype) { qtype_ = qtype; }

        void setIsBanned(bool value) { is_banned_ = value; }
        bool isBanned() const { return is_banned_; }

	SharedPointer<StringCache> name;
	SharedPointer<DomainName> matched_domain_name;

	friend std::ostream& operator<< (std::ostream& out, const DNSInfo& dinfo);

#if defined(BINDING)
	const char *getDomainName() const { return (name ? name->getName() : ""); }
#endif
	void addIPAddress(const char* ipstr);
	void addName(const char* name);
	void addName(const char* name, int length);

	std::vector<std::string>::const_iterator begin() { return items_.begin(); }
	std::vector<std::string>::const_iterator end() { return items_.end(); }

#if defined(PYTHON_BINDING)
        SharedPointer<DomainName> getMatchedDomainName() const { return matched_domain_name;}
#elif defined(RUBY_BINDING)
        DomainName& getMatchedDomainName() const { return *matched_domain_name.get();}
#elif defined(JAVA_BINDING) || defined(LUA_BINDING)
        DomainName& getMatchedDomainName() const { return *matched_domain_name.get();}
#endif

private:
	uint16_t qtype_;
	bool is_banned_;
	std::vector<std::string> items_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_DNS_DNSINFO_H_
