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
#include "IPSetManager.h"
#include <iomanip> // setw

namespace aiengine {

IPSetManager::IPSetManager(const std::string &name):
	name_(name),
	plugged_to_name_(""),
	sets_(),
	matched_set_() {}

SharedPointer<IPAbstractSet> IPSetManager::getMatchedIPSet() const { 

	return matched_set_;
}

void IPSetManager::addIPSet(const SharedPointer<IPAbstractSet>& ipset) {

	sets_.push_back(ipset);
}

void IPSetManager::removeIPSet(const SharedPointer<IPAbstractSet>& ipset) {
	
	auto ret = std::find(std::begin(sets_), std::end(sets_), ipset);
	if (ret != sets_.end()) {
		sets_.erase(ret);
	}
}

void IPSetManager::removeIPSet(const std::string &name) {
	
	auto ret = std::find_if(std::begin(sets_), std::end(sets_), [&] (const SharedPointer<IPAbstractSet> &ip) {
		return (name.compare(ip->getName()) == 0);
	});
	if (ret != sets_.end()) {
		sets_.erase(ret);
	}
}

bool IPSetManager::lookupIPAddress(const std::string &ip) {

	matched_set_.reset();

	for (auto &it: sets_) {
		bool value = it->lookupIPAddress(ip);

		if (value) {
			matched_set_ = it;
			return true;
		}
	}
	return false;
}

bool IPSetManager::lookupIPAddress(const IPAddress &address) {

	matched_set_.reset();
        for (auto &it: sets_) {
                bool value = it->lookupIPAddress(address);

                if (value) {
                        matched_set_ = it;
                        return true;
                }
        }
	return false;
}

void IPSetManager::show_ipsets(std::basic_ostream<char> &out, std::function<bool (const IPAbstractSet&)> condition) const {

	out << "IPSetManager (" << name_ << ")";

        if (plugged_to_name_.length() > 0) {
                out << " Plugged on " << plugged_to_name_;
        }
	out << std::endl;

	out << "\tTotal IPSets:           " << std::setw(10) << sets_.size() <<std::endl;
    
	for(auto &it : sets_) {
		if (condition(*it)) {
                	IPSet *ipset = dynamic_cast<IPSet*>(it.get());
			if (ipset) {	
				ipset->statistics(out);
			} else {
                		IPRadixTree *ipset = dynamic_cast<IPRadixTree*>(it.get());
				if (ipset) {
					ipset->statistics(out);
				} else {
#ifdef HAVE_BLOOMFILTER
					IPBloomSet *ipset = dynamic_cast<IPBloomSet*>(it.get());
					if (ipset) {
						ipset->statistics(out);
					}
#endif
				}
			}
		}
	}
}

std::ostream& operator<< (std::ostream &out, const IPSetManager &im) {

	im.show_ipsets(out, [&] (const IPAbstractSet& ip) { return true; });

	return out;
}

void IPSetManager::statistics(const std::string &name) {

	show_ipsets(OutputManager::getInstance()->out(), [&] (const IPAbstractSet &ip)
        {
                if (name.compare(ip.getName()) == 0)
                        return true;
		else
			return false;
        });
}

void IPSetManager::resetStatistics() {

        for (auto &it: sets_) {
		it->total_ips_not_on_set_ = 0;
		it->total_ips_on_set_ = 0;
        }
}

#if defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING) || defined(GO_BINDING)

void IPSetManager::addIPSet(IPSet &ipset) {
	// Create a shared pointer and reset it to the object
	SharedPointer<IPSet> ip = SharedPointer<IPSet>(new IPSet());
	ip.reset(&ipset);

	addIPSet(ip);
}

void IPSetManager::removeIPSet(IPSet &ipset) {
	SharedPointer<IPSet> ip = SharedPointer<IPSet>(new IPSet());
	ip.reset(&ipset);

	removeIPSet(ip);
}

void IPSetManager::addIPSet(IPRadixTree &iprad) {
	// Create a shared pointer and reset it to the object
	SharedPointer<IPRadixTree> ip = SharedPointer<IPRadixTree>(new IPRadixTree());
	ip.reset(&iprad);

	addIPSet(ip);
}

void IPSetManager::removeIPSet(IPRadixTree &iprad) {
	SharedPointer<IPRadixTree> ip = SharedPointer<IPRadixTree>(new IPRadixTree());
	ip.reset(&iprad);

	removeIPSet(ip);
}
#endif

} // namespace aiengine
