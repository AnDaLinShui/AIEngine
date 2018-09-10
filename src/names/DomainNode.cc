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
#include "DomainNode.h"

namespace aiengine {

DomainNode::DomainNode(const std::string &key):
	map_(),
	key_(key),
	domain_() 
	{}
    	
SharedPointer<DomainNode> DomainNode::haveKey(boost::string_ref &key) {

	auto it = map_.find(key);
	SharedPointer<DomainNode> node;

	if (it!=map_.end())
		node = it->second;
	return node;
}

void DomainNode::addKey(const SharedPointer<DomainNode> &node) {

	map_.insert(std::pair<boost::string_ref, SharedPointer<DomainNode>>(boost::string_ref(node->getKey()), node));
}	

void DomainNode::removeKey(const SharedPointer<DomainNode> &node) {

	map_.erase(node->getKey());
}	

} // namespace aiengine
