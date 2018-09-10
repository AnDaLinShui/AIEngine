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
#ifndef SRC_SIGNATURE_H_
#define SRC_SIGNATURE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <string>

#if defined(PYTHON_BINDING)
#include <boost/python.hpp>
#include <boost/function.hpp>
#include "Callback.h"
#elif defined(RUBY_BINDING)
#include "Callback.h"
#elif defined(JAVA_BINDING)
#include "JaiCallback.h"
#include "Callback.h"
#elif defined(LUA_BINDING)
#include "Callback.h"
#elif defined(GO_BINDING)
#include "GoaiCallback.h"
#include "Callback.h"
#endif

namespace aiengine {

class Flow;

class Signature
{
public:
	Signature(const std::string &name, const std::string &exp):
		total_matchs_(0),
		total_evaluates_(0), 
#if defined(BINDING)
	 	call(),	
#endif
		name_(name),
		expression_(exp),
		reject_connection_(false)
        {}

	Signature():Signature("", "") {}

	virtual ~Signature() {}

      	const char *getName() const { return name_.c_str(); }
        const char *getExpression() const { return expression_.c_str(); }
      	void setName(const std::string &name) { name_ = name; }
        void setExpression(const std::string &exp) { expression_ = exp; }
        
	void incrementMatchs() { ++total_matchs_; }
        int32_t getMatchs() const { return total_matchs_; }
	int32_t getTotalEvaluates() const { return total_evaluates_;}

#if defined(PYTHON_BINDING)
	void setCallback(PyObject *callback) { call.setCallback(callback); }
	PyObject *getCallback() const { return call.getCallback(); }
#elif defined(RUBY_BINDING)
	void setCallback(VALUE callback) { call.setCallback(callback); }
#elif defined(JAVA_BINDING)
	void setCallback(JaiCallback *callback) { call.setCallback(callback); }
#elif defined(LUA_BINDING)
	void setCallback(lua_State* L, const char *callback) { call.setCallback(L, callback); }
	const char *getCallback() const { return call.getCallback(); }
#elif defined(GO_BINDING)
	void setCallback(GoaiCallback *callback) { call.setCallback(callback); }
#endif

	bool getRejectConnection() const { return reject_connection_; }
	void setRejectConnection(bool value) { reject_connection_ = value; }

	int32_t total_matchs_;
	int32_t total_evaluates_;
#if defined(BINDING)
	const char *getCallbackName() const { return call.getCallbackName(); }
	Callback call;	
#endif

private:
	std::string name_;	
	std::string expression_;	
	bool reject_connection_;
};

} // namespace aiengine

#endif  // SRC_SIGNATURE_H_

