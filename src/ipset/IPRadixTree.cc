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
#include "IPRadixTree.h"
#include <boost/asio.hpp>
#include <fstream>
#include <iomanip> // setw

namespace aiengine {

#if defined(PYTHON_BINDING) 
IPRadixTree::IPRadixTree(const std::string &name, boost::python::list &ips):
        IPRadixTree(name) {

        for (int i = 0; i < len(ips); ++i ) {
                // Check if is a std::string 
                boost::python::extract<std::string> extractor(ips[i]);
                if (extractor.check()) {
                        auto ip = extractor();

                        addIPAddress(ip);
                }
        }
}
#endif

int32_t IPRadixTree::getTotalBytes() const {

	int32_t value = rttable_.size() * sizeof(IPRadixEntry);

	return value;
}

void IPRadixTree::resetStatistics() {

        total_ips_not_on_set_ = 0;
        total_ips_on_set_ = 0;
}

void IPRadixTree::clear() {

	// Reset the internal structs
	rttable_.clear();

        total_ips_ = 0;
        total_networks_ = 0;
	resetStatistics();
}

void IPRadixTree::removeIPAddress(const std::string &ip) {

        in_addr nw_addr;
        std::vector<std::string> addr;

        boost::split(addr, ip, boost::is_any_of("/"));

        if (inet_aton(addr[0].c_str(), &nw_addr) != 0) {
                int prefix_len = 32;
                if (addr.size() == 2) {
                        prefix_len = std::atoi(addr[1].c_str());
                	if ((prefix_len > 32)or(prefix_len == 0))
                        	return;
		}

                int shift = 32 - prefix_len;
                uint32_t mask = ~((1 << shift) - 1);

                IPRadixEntry entry(ntohl(nw_addr.s_addr) & mask, prefix_len);

		if (rttable_.erase(entry)) {
                	if (prefix_len == 32)
                        	--total_ips_;
                	else
                        	--total_networks_;
		}
        }
}

void IPRadixTree::addIPAddress(const std::string &ip) {

	in_addr nw_addr;
	std::vector<std::string> addr;
	boost::split(addr, ip, boost::is_any_of("/"));

	if (inet_aton(addr[0].c_str(), &nw_addr) != 0) {
		int prefix_len = 32;
		if (addr.size() == 2) { 
			prefix_len = std::atoi(addr[1].c_str());
                	if ((prefix_len > 32)or(prefix_len == 0))
				return;
		}
	
		int shift = 32 - prefix_len;
		uint32_t mask = ~((1 << shift) - 1);

		IPRadixEntry entry(ntohl(nw_addr.s_addr) & mask, prefix_len);

		if (prefix_len == 32) 
			++total_ips_;
		else
			++total_networks_;

		rttable_[entry] = true;
	}
}

bool IPRadixTree::lookupIPAddress(const std::string &ip) {

	in_addr addr_dst;

	if (inet_aton(ip.c_str(), &addr_dst) != 0) {
		IPAddress addr;

		addr.setDestinationAddress(addr_dst.s_addr);
		return lookupIPAddress(addr);	
	}
	return false;
}


bool IPRadixTree::lookupIPAddress(const IPAddress &address) {

	IPRadixEntry entry(ntohl(address.getDestinationAddress()), 32);

	radix_tree<IPRadixEntry, bool>::iterator it;

	it = rttable_.longest_match(entry);
	if (it == rttable_.end()) {
		++total_ips_not_on_set_;
		return false;
	}

	++total_ips_on_set_;
	return true;
}

std::ostream& operator<< (std::ostream &out, const IPRadixTree &is) {

	out << "IPRadixTree (" << is.getName() << ")";
#if defined(BINDING)
        if (is.call.haveCallback())
                out << " Callback:" << is.call.getCallbackName();
#endif
	out << std::endl;
	out << "\tTotal IP address:       " << std::setw(10) << is.total_ips_ <<std::endl;
	out << "\tTotal IP networks:      " << std::setw(10) << is.total_networks_ <<std::endl;
	out << "\tTotal lookups in:       " << std::setw(10) << is.total_ips_on_set_ <<std::endl;
	out << "\tTotal lookups out:      " << std::setw(10) << is.total_ips_not_on_set_ <<std::endl;
	return out;
}

#if defined(PYTHON_BINDING)
void IPRadixTree::show(std::basic_ostream<char> &out) {

        out << "IPRadixTree (" << getName() << ")";
        if (call.haveCallback())
                out << " Callback:" << call.getCallbackName();
        out << "\n";

        for (auto it = rttable_.begin(); it != rttable_.end(); ++it) {
		char str[INET_ADDRSTRLEN];
		auto rad = it->first;
		uint32_t ipaddr = ntohl(rad.addr);
		int prefix = rad.prefix_len;
		inet_ntop(AF_INET, &(ipaddr), str, INET_ADDRSTRLEN);

		out << "\t" << str;
		if (prefix < 32) 
			out << "/" << prefix;
		out << "\n";
        }
        out.flush(); 
}

void IPRadixTree::show() {

	show(OutputManager::getInstance()->out());
}

#endif

} // namespace aiengine
