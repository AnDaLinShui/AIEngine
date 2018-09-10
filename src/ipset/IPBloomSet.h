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
#ifndef SRC_IPSET_IPBLOOMSET_H_
#define SRC_IPSET_IPBLOOMSET_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <memory>
#include <string>
#include <iostream>
#include "IPAbstractSet.h"

#ifdef HAVE_BLOOMFILTER 

#include <boost/bloom_filter/dynamic_bloom_filter.hpp>

#ifdef PYTHON_BINDING
#include <boost/python.hpp>
#include <boost/function.hpp>
#endif

namespace aiengine {

class IPBloomSet : public IPAbstractSet {
public:

    	explicit IPBloomSet(const std::string &name):IPAbstractSet(name),bloom_(BLOOM_NUM_BITS) {}
    	explicit IPBloomSet():IPBloomSet("Generic IPBloomSet") {}

	static const size_t BLOOM_NUM_BITS = 4194304; // 1MB

    	virtual ~IPBloomSet() {}

	void clear();

	void addIPAddress(const std::string &ip);

	bool lookupIPAddress(const std::string &ip); 
	bool lookupIPAddress(const IPAddress &address);
	int getFalsePositiveRate() const { return (bloom_.false_positive_rate() * 100.0); }

	int32_t getTotalBytes() const;

	void statistics(std::basic_ostream<char>& out) { out<< *this; }
	void statistics() { statistics(std::cout);}

	void resetStatistics();

	friend std::ostream& operator<< (std::ostream& out, const IPBloomSet& is);

	void resize(int num_bits) { bloom_.resize(num_bits); }

private:
	boost::bloom_filters::dynamic_bloom_filter<std::string> bloom_;
};

typedef std::shared_ptr<IPBloomSet> IPBloomSetPtr;
typedef std::weak_ptr<IPBloomSet> IPBloomSetPtrWeak;

} // namespace aiengine

#endif // HAVE_BLOOMFILTER

#endif  // SRC_IPSET_IPBLOOMSET_H_
