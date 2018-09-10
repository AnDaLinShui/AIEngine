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
#ifndef SRC_IPSET_IPRADIXTREE_H_
#define SRC_IPSET_IPRADIXTREE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <memory>
#include <string>
#include <iostream>
#include <boost/algorithm/string.hpp>
#include "IPAbstractSet.h"
#include "IPRadixEntry.h"
#include "radix_tree.hpp"

#if defined(PYTHON_BINDING)
#include <boost/python.hpp>
#include <boost/function.hpp>
#elif defined(JAVA_BINDING)
#include "JaiCallback.h"
#endif

namespace aiengine {

class IPRadixTree : public IPAbstractSet {
public:
#if defined(PYTHON_BINDING)
        explicit IPRadixTree(const std::string &name, boost::python::list &ips);
        explicit IPRadixTree(boost::python::list &ips):IPRadixTree("Generic IPRadixTree", ips) {}
#endif
	explicit IPRadixTree(const std::string &name):IPAbstractSet(name), rttable_(), total_networks_(0) {}
    	explicit IPRadixTree():IPRadixTree("Generic IPRadixTree") {}
    	virtual ~IPRadixTree() {}

	void clear();

	void addIPAddress(const std::string &ip);
	void removeIPAddress(const std::string &ip);

	bool lookupIPAddress(const std::string &ip); 
	bool lookupIPAddress(const IPAddress &address);
	int getFalsePositiveRate() { return 0; }

	void statistics(std::basic_ostream<char> &out) { out<< *this; }
	void statistics() { statistics(std::cout); }

	void resetStatistics();

	int32_t getTotalBytes() const;
	int32_t getTotalNetworks() const { return total_networks_; }

	friend std::ostream& operator<< (std::ostream &out, const IPRadixTree &is);

#if defined(PYTHON_BINDING)
	void show();
	void show(std::basic_ostream<char> &out); 

	void setCallback(PyObject *callback) { call.setCallback(callback); }
	PyObject *getCallback() const { return call.getCallback(); }
#elif defined(RUBY_BINDING)
        void setCallback(VALUE callback) { call.setCallback(callback); }
#elif defined(JAVA_BINDING)
        void setCallback(JaiCallback *callback) { call.setCallback(callback); }
#elif defined(LUA_BINDING)
	void setCallback(lua_State* lua, const char *callback) { call.setCallback(lua,callback); }
	const char *getCallback() const { return call.getCallback(); }
#elif defined(GO_BINDING)
        void setCallback(GoaiCallback *callback) { call.setCallback(callback); }
#endif

private:
	radix_tree<IPRadixEntry, bool> rttable_;
	int32_t total_networks_;
};

typedef std::shared_ptr<IPRadixTree> IPRadixTreePtr;
typedef std::weak_ptr<IPRadixTree> IPRadixTreePtrWeak;

} // namespace aiengine

#endif  // SRC_IPSET_IPRADIXTREE_H_
