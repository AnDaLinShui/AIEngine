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
#ifndef SRC_NAMES_DOMAINNAMEMANAGER_H_ 
#define SRC_NAMES_DOMAINNAMEMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "DomainName.h"
#include "DomainNode.h"
#include <iostream>
#include <fstream>
#include <boost/algorithm/string.hpp>
#include <boost/utility/string_ref.hpp>

namespace aiengine {

class DomainNameManager {
public:
#if defined(PYTHON_BINDING)
	explicit DomainNameManager(const std::string &name, boost::python::list &doms);
	explicit DomainNameManager(boost::python::list &doms):DomainNameManager("Generic Domain Name Manager", doms) {}
#endif
	explicit DomainNameManager(const std::string &name);
	explicit DomainNameManager():DomainNameManager("Generic Domain Name Manager") {}

    	virtual ~DomainNameManager() {}

	void setName(const std::string &name) { name_ = name; }
	const char *getName() const { return name_.c_str(); }

	void setPluggedToName(const std::string &name) { plugged_to_name_ = name; }
	const char *getPluggedToName() const { return plugged_to_name_.c_str(); }

#if defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING) || defined(GO_BINDING)
        void addDomainName(DomainName &domain) {

		SharedPointer<DomainName> d = SharedPointer<DomainName>(new DomainName());
		
		d.reset(&domain);
                addDomainName(d);
        }
	
#endif

#if defined(BINDING)
	void showMatchedDomains() const { showMatchedDomains(OutputManager::getInstance()->out()); }
	void showMatchedDomains(std::basic_ostream<char> &out) const;
#endif

	void resetStatistics();

	void addDomainName(const SharedPointer<DomainName> &domain); 
	void addDomainName(const std::string &name, const std::string &expression);

	void removeDomainName(const SharedPointer<DomainName> &domain); 
	void removeDomainNameByName(const std::string &name);

	SharedPointer<DomainName> getDomainName(const boost::string_ref &name);
	SharedPointer<DomainName> getDomainName(const char *name); 

	int32_t getTotalDomains() const { return total_domains_; }

	friend std::ostream& operator<< (std::ostream &out, const DomainNameManager &domain);

	void statistics() { statistics(OutputManager::getInstance()->out()); }
	void statistics(std::ostream &out);
	void statistics(const std::string &name);

#if defined(STAND_ALONE)
	int64_t getTotalBytes() const { return total_bytes_; }
#endif

private:
	void transverse(const SharedPointer<DomainNode> node,
		std::function <void(const SharedPointer<DomainNode>&, const SharedPointer<DomainName>&) > condition) const; 
	SharedPointer<DomainNode> find_domain_name_node(const SharedPointer<DomainName> &domain);
	void remove_domain_name_by_name(const SharedPointer<DomainNode> node, const std::string &name);

	std::string name_;
	std::string plugged_to_name_;
	SharedPointer<DomainNode> root_;
	int32_t total_domains_;
	int64_t total_bytes_; // memory comsumption
	boost::string_ref key_;
};

typedef std::shared_ptr<DomainNameManager> DomainNameManagerPtr;
typedef std::weak_ptr<DomainNameManager> DomainNameManagerPtrWeak;

} // namespace aiengine

#endif  // SRC_NAMES_DOMAINNAMEMANAGER_H_
