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
#include "Callback.h"
#include "Flow.h"

#if defined(LUA_BINDING)
#include "swigluarun.h"
#endif

namespace aiengine {

#if defined(PYTHON_BINDING)

const char *Callback::getCallbackName() const {
	static char buffer[256] = { "Can not retrieve callback name" };

	PyObject *obj = PyObject_Repr(callback_);

	const char *name = reinterpret_cast<const char*>(&buffer[0]);

#if PY_MAJOR_VERSION < 3
	strncpy(buffer, PyString_AsString(obj), 255);
#else
	PyObject * temp_bytes = PyUnicode_AsEncodedString(obj, "ASCII", "strict");
	if (temp_bytes != NULL) {
		strncpy(buffer, PyBytes_AS_STRING(temp_bytes), 255);

		Py_XDECREF(temp_bytes);	
	}
#endif
	Py_XDECREF(obj);
	return name;
}

void Callback::setCallbackWithNoArgs(PyObject *callback) {

	// the user unset the callback to none
	if ((callback == Py_None) or (callback == nullptr)) {
		if (callback_) {
                	Py_XDECREF(callback_);
                	callback_ = nullptr;
			callback_set_ = false;
		}
		return;
	}

	if (!PyCallable_Check(callback)) {
		throw std::runtime_error("Object is not callable.\n");
   	} else {
     		if ( callback_ ) Py_XDECREF(callback_);
      		callback_ = callback;
      		Py_XINCREF(callback_);
		callback_set_ = true;
	}
}

void Callback::setCallback(PyObject *callback) {

	// the user unset the callback to none
	if (callback == Py_None) {
		if (callback_) {
                	Py_XDECREF(callback_);
                	callback_ = nullptr;
			callback_set_ = false;
		}
		return;
	}
	
	if (!PyCallable_Check(callback)) {
		throw std::runtime_error("Object is not callable.\n");
   	} else {
		int args = 0;
#if PY_MAJOR_VERSION < 3
		PyObject *fc = PyObject_GetAttrString(callback, "func_code");
#else
		PyObject *fc = PyObject_GetAttrString(callback, "__code__");
#endif
		if (fc) {
			PyObject* ac = PyObject_GetAttrString(fc, "co_argcount");
                	if (ac) {
#if PY_MAJOR_VERSION < 3
				args = PyInt_AsLong(ac);
#else
				args = PyLong_AsLong(ac);
#endif
			}
			Py_XDECREF(ac);
		}
		Py_XDECREF(fc);

		if (args != 1) {
			throw std::runtime_error("Object should have one parameter.\n");
		} else {
      			if ( callback_ ) Py_XDECREF(callback_);
      			callback_ = callback;
      			Py_XINCREF(callback_);
			callback_set_ = true;
		}
   	}
}

Callback::~Callback() {

	if ((callback_set_)and(callback_ != Py_None)) {
		Py_XDECREF(callback_);
		callback_ = nullptr;
	}
}

void Callback::executeCallback(Flow *flow) {

        try {
		PyGilContext gil_lock;

        	boost::python::call<void>(callback_, boost::python::ptr(flow));
        } catch (std::exception &e) {
        	std::cout << __FILE__ << ":" << __func__ << ":ERROR:" << e.what() << std::endl;
        }
}

void Callback::executeCallback() {

        try {
                PyGilContext gil_lock;

                boost::python::call<void>(callback_);
        } catch (std::exception &e) {
                std::cout << __FILE__ << ":" << __func__ << ":ERROR:" << e.what() << std::endl;
        }
}

#elif defined(RUBY_BINDING)

void Callback::setCallback(VALUE callback) {

	if (!NIL_P(callback)) {
		// Verify the number of arguments of the callback by calling the method arity

		VALUE value = rb_funcall(callback, rb_intern("arity"), 0);
		int nargs = NUM2INT(value);

		if (nargs != 1) {
			rb_raise(rb_eRuntimeError, "Object should have one parameter.\n");
		}	
        	callback_ = callback;
                callback_set_ = true;
	} else {
        	callback_ = Qnil;
                callback_set_ = false;
	}
}

void Callback::setCallbackWithNoArgs(VALUE callback) {

        if (!NIL_P(callback)) {
                callback_ = callback;
                callback_set_ = true;
        } else {
                callback_ = Qnil;
                callback_set_ = false;
        }
}

#ifdef TypedData_Wrap_Struct
# define USE_TYPEDDATA	1
#endif

#if USE_TYPEDDATA 

size_t flow_typed_wrapped_struct_other_memsize(const void* st) {
  	return sizeof(Flow);
}

static const rb_data_type_t flow_definition_type = {
     	"Flow",
     	{ 0, 0, flow_typed_wrapped_struct_other_memsize, }
	,
};

#endif

void Callback::executeCallback(Flow *flow) {

	if (!NIL_P(callback_)) {
		ID id = rb_intern("Flow");

		if (rb_const_defined(rb_cData, id)) {	
	
                        VALUE rbFlowClass = rb_const_get(rb_cData, id);

			// std::cout << "type:" << rb_typeddata_is_kind_of(rbFlowClass, &flow_definition_type) << std::endl;
#if USE_TYPEDDATA 
			VALUE rbFlow = TypedData_Wrap_Struct(rbFlowClass ,&flow_definition_type, flow);
       			rb_funcall(callback_,rb_intern("call"), 1, rbFlow);
#else
	                VALUE rbFlow = Data_Wrap_Struct(rbFlowClass, 0 , 0, flow);	
       			rb_funcall(callback_,rb_intern("call"), 1, rbFlow);
#endif
		}
        }
}

void Callback::executeCallback() {

        if (!NIL_P(callback_)) {
        	rb_funcall(callback_, rb_intern("call"), 0, 0);
        }
}

void Callback::mark() {

	if (!NIL_P(callback_)) {
        	rb_gc_mark(callback_);
        }
}

#elif defined(JAVA_BINDING)

void Callback::setCallback(JaiCallback *callback) {

        if (callback != nullptr) {
                callback_ = callback;
                callback_set_ = true;
        } else {
                callback_ = nullptr;
                callback_set_ = false;
        }
}

void Callback::executeCallback(Flow *flow) {

	if (callback_ != nullptr) {
		callback_->call(flow);
	}
}

#elif defined(LUA_BINDING)

Callback::~Callback() {

	if ((ref_function_ != LUA_NOREF) and ( L_ != nullptr)) {
		// delete the reference from registry
		luaL_unref(L_, LUA_REGISTRYINDEX, ref_function_);
	}
}

void Callback::setCallback(lua_State* L, const char *callback) {

	lua_getglobal(L, callback);
	if (lua_isfunction(L, -1)) {
		ref_function_ = luaL_ref(L, LUA_REGISTRYINDEX);
		callback_set_ = true;
		L_ = L;
		callback_name_ = callback;
	} else {
		lua_pop(L, 1);
		ref_function_ = LUA_NOREF;
		callback_set_ = false;
		L_ = nullptr;
		throw std::runtime_error("not a valid LUA function");
	}
        return;
}


void Callback::setCallbackWithNoArgs(lua_State* L, const char *callback) {

	setCallback(L, callback);
}	


bool Callback::push_pointer(lua_State *L, void* ptr, const char* type_name, int owned) {

  	// task 1: get the object 'type' which is registered with SWIG
  	// you need to call SWIG_TypeQuery() with the class name
  	// (normally, just look in the wrapper file to get this)

 	swig_type_info * pTypeInfo = SWIG_TypeQuery(L, type_name);
	if (pTypeInfo == 0)
  		return false;   // error
  	// task 2: push the pointer to the Lua stack
  	// this requires a pointer & the type
  	// the last param specifies if Lua is responsible for deleting the object

	SWIG_NewPointerObj(L, ptr, pTypeInfo, owned);
	return true;
}


void Callback::executeCallback(Flow *flow) {

	lua_rawgeti(L_, LUA_REGISTRYINDEX, ref_function_);

	if (push_pointer(L_, flow, "aiengine::Flow*", 0)) {
        	int ret; 
        	if ((ret = lua_pcall(L_, 1, 0, 0)) != 0) {
			std::cout << __FILE__ << ":" << __func__ << ":ERROR:" << lua_tostring(L_, -1) << std::endl;
		} 
	}	
}

void Callback::executeCallback() {

	lua_rawgeti(L_, LUA_REGISTRYINDEX, ref_function_);

       	int ret; 
       	if ((ret = lua_pcall(L_, 0, 0, 0)) != 0) {
		std::cout << __FILE__ << ":" << __func__ << ":ERROR:" << lua_tostring(L_, -1) << std::endl;
	} 
}

#elif defined(GO_BINDING)

void Callback::setCallback(GoaiCallback *callback) {

        if (callback != nullptr) {
                callback_ = callback;
                callback_set_ = true;
        } else {
                callback_ = nullptr;
                callback_set_ = false;
        }
}

void Callback::executeCallback(Flow *flow) {

        if (callback_ != nullptr) {
		callback_->call(flow);
        }
}

#endif

} // namespace aiengine


