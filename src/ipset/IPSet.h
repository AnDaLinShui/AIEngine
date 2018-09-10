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
#ifndef SRC_IPSET_IPSET_H_
#define SRC_IPSET_IPSET_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "IPAbstractSet.h"
#include "IPAddress.h"
#include <unordered_set>
#include <memory>
#include <string>
#include <iostream>

#if defined(PYTHON_BINDING)
#include <boost/python.hpp>
#include <boost/function.hpp>
#elif defined(JAVA_BINDING)
#include "JaiCallback.h"
#endif

namespace aiengine {

class IPSet : public IPAbstractSet {
public:
#if defined(PYTHON_BINDING)
	explicit IPSet(const std::string &name, boost::python::list &ips, boost::python::object callback);
	explicit IPSet(const std::string &name, boost::python::list &ips);
	explicit IPSet(boost::python::list &ips):IPSet("Generic IPSet", ips) {}
#endif
	explicit IPSet(const std::string &name):IPAbstractSet(name), total_bytes_(0) {}
    	explicit IPSet():IPSet("Generic IPSet") {}
    	virtual ~IPSet() {}

	void clear();
	void addIPAddress(const std::string &ip);
	void removeIPAddress(const std::string &ip);

	bool lookupIPAddress(const std::string &ip); // use for testing ipv6 mainly 
	bool lookupIPAddress(const IPAddress &address); 
	int getFalsePositiveRate() { return 0; }

	int getTotalBytes() const;

	void statistics(std::basic_ostream<char> &out) { out<< *this; }
	void statistics() { statistics(OutputManager::getInstance()->out()); }

	void resetStatistics();

	friend std::ostream& operator<< (std::ostream &out, const IPSet &is);

#if defined(PYTHON_BINDING)
	void show() const;
	void show(std::basic_ostream<char> &out) const;

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
	std::unordered_set<std::string> smap_; // For ipv6
	std::unordered_set<uint32_t> imap_; // For ipv4
	int32_t total_bytes_;
};

typedef std::shared_ptr<IPSet> IPSetPtr;
typedef std::weak_ptr<IPSet> IPSetPtrWeak;

} // namespace aiengine

#endif  // SRC_IPSET_IPSET_H_
