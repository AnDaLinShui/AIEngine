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
#ifndef SRC_CACHE_H_
#define SRC_CACHE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Pointer.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <stack>

namespace aiengine {

template <class A_Type> class Cache {
public:

	typedef aiengine::SharedPointer<Cache<A_Type>> CachePtr;

    	explicit Cache(const std::string& name);
    	explicit Cache():Cache("") {}
    	virtual ~Cache() { destroy(items_.size()); }

	static constexpr int classSize = sizeof(A_Type) + sizeof(SharedPointer<A_Type>);

	void release(const SharedPointer<A_Type> &a); 
	SharedPointer<A_Type> acquire(); 
	
	void create(int number); 
	void destroy(int number); 

	int32_t getTotal() const { return items_.size(); }
	int32_t getTotalAcquires() const { return total_acquires_; }
	int32_t getTotalReleases() const { return total_releases_; }
	int32_t getTotalFails() const { return total_fails_; }
	int32_t getAllocatedMemory() const { return allocated_bytes_; }

	// Returns the total memory used by the engine that is out of this cache
	int32_t getCurrentUseMemory() const { return ((getTotalAcquires() - getTotalReleases()) * classSize); }
	int32_t getCurrentAllocatedMemory() const { return (items_.size() * classSize); }
	const char *getName() const { return name_.c_str(); }

        void statistics(std::basic_ostream<char> &out); 
        void statistics() { statistics(std::cout); }

	void setDynamicAllocatedMemory(bool value) { is_dynamic_ = value; }
	bool isDynamicAllocatedMemory() const { return  is_dynamic_; }

#if defined(STAND_ALONE_TEST) || defined(TESTING)
	bool generate_bad_alloc_exception;
#endif
private:
	int32_t total_acquires_;
	int32_t total_releases_;
	int32_t total_fails_;
	int32_t allocated_bytes_;
	bool is_dynamic_; 
	std::string name_;
	// a stack of pointers to the created Flows
	std::stack<SharedPointer<A_Type>> items_;
	SharedPointer<A_Type> empty_;
};

} // namespace aiengine

#include "Cache_Impl.h"

#endif  // SRC_CACHE_H_
