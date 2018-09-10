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
#include "IPSet.h"
#include <boost/asio.hpp>
#include <fstream>
#include <iomanip> // setw

namespace aiengine {

#if defined(PYTHON_BINDING) 
IPSet::IPSet(const std::string &name, boost::python::list &ips):
	IPSet(name) {

	for (int i = 0; i < len(ips); ++i ) {
		// Check if is a std::string 
		boost::python::extract<std::string> extractor(ips[i]);
		if (extractor.check()) {
			auto ip = extractor();

                        addIPAddress(ip);
		}
	}
}

IPSet::IPSet(const std::string &name, boost::python::list &ips, boost::python::object callback):
	IPSet(name, ips) {

        if (!callback.is_none()) {
                // Take the PyObject from the boost::python::object
                PyObject *obj = callback.ptr();

                setCallback(obj);
        }
}

#endif

int32_t IPSet::getTotalBytes() const {

	int32_t value = imap_.size() * sizeof(uint32_t);

	for (auto &it: smap_) {
		value += it.capacity();
	}
	return value;
}

void IPSet::resetStatistics() {

	total_ips_not_on_set_ = 0;
	total_ips_on_set_ = 0;
}

void IPSet::clear() {

	imap_ = std::unordered_set<uint32_t>();
	smap_ = std::unordered_set<std::string>();

	total_ips_ = 0;
	resetStatistics();
}

void IPSet::removeIPAddress(const std::string &ip) {

	struct sockaddr_in6 sa6;
	struct sockaddr_in sa;

	if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr))) {
		// is an IPv4 address
		auto it = imap_.find(sa.sin_addr.s_addr);
		if (it != imap_.end()) {
			imap_.erase(it);
			--total_ips_;
		}
	} else {
		if (inet_pton(AF_INET6, ip.c_str(), &(sa6.sin6_addr))) {
			// is an IPv6 address
			auto it = smap_.find(ip.c_str());
			if (it != smap_.end()) {
				smap_.erase(it);
				--total_ips_;
			}
		}
	}
}

void IPSet::addIPAddress(const std::string &ip) {

	struct sockaddr_in6 sa6;
	struct sockaddr_in sa;

	if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr))) {
		// is an IPv4 address
		imap_.insert(sa.sin_addr.s_addr);
		++total_ips_;
	} else {
		if (inet_pton(AF_INET6, ip.c_str(), &(sa6.sin6_addr))) {
			// is an IPv6 address
			smap_.insert(ip.c_str());
			++total_ips_;
		}
	}
}

bool IPSet::lookupIPAddress(const std::string &ip) {

	if (smap_.find(ip) != smap_.end()) {
		++total_ips_on_set_;
		return true;
	} else {
		++total_ips_not_on_set_;
		return false;
	}
}

bool IPSet::lookupIPAddress(const IPAddress &address) {

#ifdef DEBUG
	std::cout << __FILE__ << ":" << __func__ << ":IP:" << address.getDstAddrDotNotation() << std::endl;
#endif
	if (address.getType() == IPPROTO_IP) {
		if (imap_.find(address.getDestinationAddress()) != imap_.end()) {
			++total_ips_on_set_;
			return true;
		} else {
			++total_ips_not_on_set_;
			return false;
		}
	} else {
		if (smap_.find(address.getDstAddrDotNotation()) != smap_.end()) {
			++total_ips_on_set_;
			return true;
		} else {
			++total_ips_not_on_set_;
			return false;
		}
	}
	return false;	
}

std::ostream& operator<< (std::ostream &out, const IPSet &is) {

	out << "IPSet (" << is.getName() << ")";
#if defined(BINDING)
        if (is.call.haveCallback())
                out << " Callback:" << is.call.getCallbackName();
#endif
	out << std::endl;
	out << "\tTotal IP address:       " << std::setw(10) << is.total_ips_ <<std::endl;
	out << "\tTotal lookups in:       " << std::setw(10) << is.total_ips_on_set_ <<std::endl;
	out << "\tTotal lookups out:      " << std::setw(10) << is.total_ips_not_on_set_ <<std::endl;
	return out;
}

#if defined(PYTHON_BINDING)
void IPSet::show(std::basic_ostream<char> &out) const {

	out << "IPSet (" << getName() << ")";
        if (call.haveCallback())
                out << " Callback:" << call.getCallbackName();

	out << "\n"; 

	for (auto &ip: imap_) {
		struct in_addr in;

		in.s_addr = ip;
		out << "\t" << inet_ntoa(in) << "\n";
	}
	for (auto &ip: smap_) {
		out << "\t" << ip << "\n";
	}
	out.flush(); 
}

void IPSet::show() const {

	show(OutputManager::getInstance()->out());
}

#endif

} // namespace aiengine
