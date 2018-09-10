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
#pragma once
#ifndef SRC_COUNTERMAP_H_
#define SRC_COUNTERMAP_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <string>

namespace aiengine {

class CounterMap
{
public:
	CounterMap() {}
	virtual ~CounterMap() {}

#if defined(PYTHON_BINDING) 
	void addKeyValue(const char *key, int64_t value) {
		map_[key] = value;
	}
#elif defined(JAVA_BINDING) || defined(LUA_BINDING) || defined(GO_BINDING)
	void addKeyValue(const char *key, int32_t value) {
		map_[key] = value;
	}
#elif defined(RUBY_BINDING)
	void addKeyValue(const char *key, int64_t value) {
		rb_hash_aset(map_, rb_str_new2(key), INT2NUM(value));
	}
#else
	void addKeyValue(const char *key, int64_t value) {}
#endif
	
#if defined(PYTHON_BINDING) 
	boost::python::dict getRawCounters() { return map_; }
#elif defined(RUBY_BINDING)
	VALUE getRawCounters() { return map_; }
#elif defined(JAVA_BINDING) || defined(LUA_BINDING) || defined(GO_BINDING)
	std::map<std::string, int32_t> getRawCounters() { return map_; } 
#endif
	
private:
#if defined(PYTHON_BINDING) 
	boost::python::dict map_;
#elif defined(RUBY_BINDING)
	VALUE map_ = rb_hash_new();;
#elif defined(JAVA_BINDING) || defined(LUA_BINDING) || defined(GO_BINDING)
	std::map<std::string, int32_t> map_;
#endif
};

} // namespace aiengine

#endif  // SRC_COUNTERMAP_H_

