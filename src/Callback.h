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
#ifndef SRC_CALLBACK_H_
#define SRC_CALLBACK_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(PYTHON_BINDING)
#include "PyGilContext.h"
#include <boost/python.hpp>
#include <boost/function.hpp>
#elif defined(RUBY_BINDING)
#include <ruby.h>
#include <ruby/version.h>
#elif defined(JAVA_BINDING)
#include "JaiCallback.h"
#elif defined(LUA_BINDING)
#include <lua.hpp>
#elif defined(GO_BINDING)
#include "GoaiCallback.h"
#endif
#include <iostream>

namespace aiengine {

class Flow;
// http://www.lysator.liu.se/~norling/ruby_callbacks.html
class Callback { 
#if defined(PYTHON_BINDING)
public:
	Callback():callback_set_(false), callback_(nullptr) {}
	virtual ~Callback(); 

	bool haveCallback() const { return callback_set_; }

	void setCallbackWithNoArgs(PyObject *callback);
	void setCallback(PyObject *callback); 
	void executeCallback(Flow *flow);
	void executeCallback();
	
	PyObject *getCallback() const { return callback_; }
	const char *getCallbackName() const;
	
private:
	bool callback_set_;
	PyObject *callback_;
#elif defined(RUBY_BINDING)
public:
	Callback():callback_set_(false), callback_(Qnil), memory_wrapper_(Qnil) {
		memory_wrapper_ = Data_Wrap_Struct(0 /* klass */, staticMark, NULL, static_cast<void*>(this));
		rb_gc_register_address(&memory_wrapper_);

	}
	virtual ~Callback() { rb_gc_unregister_address(&memory_wrapper_); }

	bool haveCallback() const { return callback_set_;}
	
	void setCallback(VALUE callback);
	void setCallbackWithNoArgs(VALUE callback);
	VALUE getCallback() const { return callback_; }
	const char *getCallbackName() const { return ""; } // TODO

	// verify that haveCallback is true before execute the function
	void executeCallback(Flow *flow); 
	void executeCallback(); 
	
protected:
	static void staticMark(Callback *me) { me->mark(); }

	void mark();
private:
	bool callback_set_;
	VALUE callback_;
	VALUE memory_wrapper_;
#elif defined(JAVA_BINDING)
public:
	Callback():callback_set_(false), callback_(nullptr) {}
	virtual ~Callback() {}

	bool haveCallback() const { return callback_set_;}

	void setCallback(JaiCallback *callback);
	JaiCallback *getCallback() const { return callback_; }
	const char *getCallbackName() const { return ""; } // TODO
 
	void executeCallback(Flow *flow);
	
private:
	bool callback_set_;
	JaiCallback *callback_;
#elif defined(LUA_BINDING)
public:
	Callback():callback_name_(), ref_function_(LUA_NOREF), callback_set_(false), L_(nullptr) {}
	virtual ~Callback(); 

	bool haveCallback() const { return callback_set_; }

	const char *getCallback() const { return callback_name_.c_str(); }
	const char *getCallbackName() const { return callback_name_.c_str(); } 

	void setCallback(lua_State* L, const char *callback); 
	void setCallbackWithNoArgs(lua_State* L, const char *callback); 
	void executeCallback(Flow *flow); 
	void executeCallback(); 
private:
	bool push_pointer(lua_State *L, void* ptr, const char* type_name, int owned = 0); 

	std::string callback_name_;
	int ref_function_;
	bool callback_set_;
	lua_State *L_;
#elif defined(GO_BINDING)
public:
        Callback():callback_set_(false), callback_(nullptr) {}
        virtual ~Callback() {}

        bool haveCallback() const { return callback_set_;}

        void setCallback(GoaiCallback *callback);
        GoaiCallback *getCallback() const { return callback_; }
        const char *getCallbackName() const { return ""; } // TODO

        void executeCallback(Flow *flow);

private:
        bool callback_set_;
        GoaiCallback *callback_;
#else
public:
	Callback():callback_set_(false) {}
	virtual ~Callback() {}

	bool haveCallback() const { return callback_set_; }
private:
	bool callback_set_;
#endif
};

} // namespace aiengine

#endif  // SRC_CALLBACK_H_

