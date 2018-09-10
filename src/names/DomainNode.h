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
#ifndef SRC_NAMES_DOMAINNODE_H_
#define SRC_NAMES_DOMAINNODE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Pointer.h"
#include <unordered_map>
#include <boost/utility/string_ref.hpp>
#include <boost/functional/hash.hpp>
#include <iostream>

namespace aiengine {

class DomainName;

class DomainNode {
public:
    	explicit DomainNode(const std::string &key);
	virtual ~DomainNode() {}

	struct string_hasher {
        	size_t operator()(boost::string_ref const &s) const {

                	return boost::hash_range(s.begin(), s.end());
        	}
	};

	typedef std::unordered_map<boost::string_ref, SharedPointer<DomainNode>, string_hasher> DomainNodeMapType;

	SharedPointer<DomainNode> haveKey(boost::string_ref &key); 
	void addKey(const SharedPointer<DomainNode> &node); 
	void removeKey(const SharedPointer<DomainNode> &node); 

	int getTotalKeys() const { return map_.size(); }

	void setDomainName(const SharedPointer<DomainName> &domain) { domain_ = domain;}
	SharedPointer<DomainName> getDomainName() { return domain_;}

	const char *getKey() { return key_.c_str();}

        DomainNodeMapType::iterator begin() { return map_.begin(); }
        DomainNodeMapType::iterator end() { return map_.end(); }

private:
	DomainNodeMapType map_;
	std::string key_;
	SharedPointer<DomainName> domain_;
};

} // namespace aiengine

#endif  // SRC_NAMES_DOMAINNODE_H_
