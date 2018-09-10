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
#ifndef SRC_CACHE_IMPL_H_
#define SRC_CACHE_IMPL_H_

#ifndef SRC_CACHE_H_
#error 'Cache_Impl.h' is not supposed to be included directly. Include 'Cache.h' instead.
#endif

namespace aiengine {

template <class A_Type> 
Cache<A_Type>::Cache(const std::string &name):
#if defined(STAND_ALONE_TEST) || defined(TESTING)
	generate_bad_alloc_exception(false),
#endif
	total_acquires_(0),
	total_releases_(0),
	total_fails_(0),
	allocated_bytes_(0),
	is_dynamic_(false), // The default is to manage the memory statically
	name_(name),
	items_(),
	empty_() {} 

template <class A_Type> 
void Cache<A_Type>::release(const SharedPointer<A_Type> &a) {  
	
	++total_releases_;
	a->reset();
	items_.push(a);
}

template <class A_Type> 
SharedPointer<A_Type> Cache<A_Type>::acquire() {
	
	if (!items_.empty()) {
		SharedPointer<A_Type> a = items_.top();
		items_.pop();
		++total_acquires_;
		return a;
	} else if (is_dynamic_) {
		try {
#if defined(STAND_ALONE_TEST) || defined(TESTING)
			if (generate_bad_alloc_exception == true) 
				throw std::bad_alloc();
#endif

			std::allocator<A_Type> alloc;

			auto item = AllocateShared<A_Type>(alloc);
			allocated_bytes_ += classSize; 
			++total_acquires_;
			return item;
		} catch (const std::bad_alloc &ba) {} 
	}
	++total_fails_;
	return empty_;
}

template <class A_Type> 
void Cache<A_Type>::create(int number) {

	int j = 0;
	try {
#if defined(STAND_ALONE_TEST) || defined(TESTING)
		if (generate_bad_alloc_exception == true) 
			throw std::bad_alloc();
#endif

		std::allocator<A_Type> alloc;

		for (int i = 0; i < number; ++i) {
			items_.push(AllocateShared<A_Type>(alloc));
			++j;
		}
	} catch (const std::bad_alloc &ba) {}

	allocated_bytes_ += (classSize * j);
}

template <class A_Type> 
void Cache<A_Type>::destroy(int number) {
	
	for (int i = 0; i < number ; ++i) {
		if (!items_.empty()) {
			items_.pop();
			allocated_bytes_ -= classSize;
		} else {
			break;
		} 
	}
}


template <class A_Type> 
void Cache<A_Type>::statistics(std::basic_ostream<char> &out) {

	const char *units[] = { "KBytes", "MBytes", "GBytes" };
	const char *unit = "Bytes";
	int alloc_memory = items_.size() * classSize;

	// compute the current memory allocated now on the cache 
	for(auto i: units) {
		if (alloc_memory > 1024) {
			unit = i;
			alloc_memory = alloc_memory / 1024;
		} else {
			break;
		}
	}
	
	// compute the total memory that have been allocated on the cache
	const char *cunit = "Bytes";
	int calloc_memory = allocated_bytes_;

	for(auto i: units) {
		if (calloc_memory > 1024) {
			cunit = i;
			calloc_memory = calloc_memory / 1024;
		} else {
			break;
		}
	}

	out << name_ << " statistics" << "\n";
	out << "\t" << "Total items:            " << std::setw(10) << items_.size() << "\n";
	out << "\t" << "Total allocated:        " << std::setw(9 - std::strlen(cunit)) << calloc_memory << " " << cunit << "\n";
	out << "\t" << "Total current alloc:    " << std::setw(9 - std::strlen(unit)) << alloc_memory << " " << unit << "\n";
	out << "\t" << "Total acquires:         " << std::setw(10) << total_acquires_ << "\n";
	out << "\t" << "Total releases:         " << std::setw(10) << total_releases_ << "\n";
	out << "\t" << "Total fails:            " << std::setw(10) << total_fails_ << std::endl;
}

} // namespace aiengine

#endif  // SRC_CACHE_IMPL_H_
