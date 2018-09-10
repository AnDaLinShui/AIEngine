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
#ifndef SRC_IPSET_IPSETMANAGER_H_
#define SRC_IPSET_IPSETMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string>
#include <iostream>
#include <vector>
#include "Pointer.h"
#include "IPAbstractSet.h"
#include "IPSet.h"
#include "IPRadixTree.h"
#include "IPBloomSet.h"
#include "OutputManager.h"

namespace aiengine {

class IPSetManager { 
public:
    	explicit IPSetManager(const std::string &name);
    	explicit IPSetManager(): IPSetManager("Generic IPSetManager") {}
    	virtual ~IPSetManager() {}

        const char* getName() const { return name_.c_str(); }
        void setName(const std::string &name) { name_ = name; }

	void setPluggedToName(const std::string &name) { plugged_to_name_ = name; }
	const char *getPluggedToName() const { return plugged_to_name_.c_str(); }

	void addIPSet(const SharedPointer<IPAbstractSet>& ipset);
	void removeIPSet(const SharedPointer<IPAbstractSet>& ipset);
	void removeIPSet(const std::string &name);
	bool lookupIPAddress(const std::string &ip); 
	bool lookupIPAddress(const IPAddress &address); 

	int32_t getTotalSets() const { return sets_.size(); }

	void statistics(std::basic_ostream<char> &out) { out << *this; }
	void statistics() { statistics(OutputManager::getInstance()->out());}
	void statistics(const std::string &name);

	void resetStatistics();

#ifdef PYTHON_BINDING
	// Methods for exposing the class to python iterable methods
	std::vector<SharedPointer<IPAbstractSet>>::iterator begin() { return sets_.begin(); }
	std::vector<SharedPointer<IPAbstractSet>>::iterator end() { return sets_.end(); }
#endif

#if defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING) || defined(GO_BINDING)
        void addIPSet(IPSet &ipset); 
	void removeIPSet(IPSet &ipset); 
        void addIPSet(IPRadixTree &iprad); 
	void removeIPSet(IPRadixTree &iprad); 
#endif

	friend std::ostream& operator<< (std::ostream &out, const IPSetManager &im);

	SharedPointer<IPAbstractSet> getMatchedIPSet() const;
private:
	void show_ipsets(std::basic_ostream<char> &out, std::function<bool (const IPAbstractSet&)> condition) const; 

	std::string name_;
	std::string plugged_to_name_;
	std::vector<SharedPointer<IPAbstractSet>> sets_;
	SharedPointer<IPAbstractSet> matched_set_;
};

typedef std::shared_ptr<IPSetManager> IPSetManagerPtr;
typedef std::weak_ptr<IPSetManager> IPSetManagerPtrWeak;

} // namespace aiengine

#endif  // SRC_IPSET_IPSETMANAGER_H_
