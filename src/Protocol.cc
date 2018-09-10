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
#include "Protocol.h"
#if defined(LUA_BINDING)
#include "swigluarun.h"
#endif

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr Protocol::logger(log4cxx::Logger::getLogger("aiengine.protocol"));
#endif

Protocol::Protocol(const std::string &name, const std::string &short_name, uint16_t protocol_layer):
	ipset_mng_(),
	mux_(), 
	flow_forwarder_(),
	total_valid_packets_(0),
	total_invalid_packets_(0),
	total_packets_(0),
	total_bytes_(0),
	stats_level_(0),
	name_(name),
	short_name_(short_name),
	protocol_id_(0),
	protocol_layer_(protocol_layer),
	is_active_(false)
#if defined(BINDING)
	,key_(),
	data_(),
#if defined(PYTHON_BINDING)
	dbptr_(),
	is_set_db_(false),
	packet_sampling_(32)
#elif defined(RUBY_BINDING)
	dbptr_(Qnil),
	is_set_db_(false),
	packet_sampling_(32)
#elif defined(JAVA_BINDING) || defined(GO_BINDING)
	dbptr_(nullptr),
	is_set_db_(false),
	packet_sampling_(32)
#elif defined(LUA_BINDING)
	L_(nullptr),
	is_set_db_(false),
	packet_sampling_(32),
	ref_function_insert_(LUA_NOREF),
	ref_function_update_(LUA_NOREF),
	ref_function_remove_(LUA_NOREF)
#endif
#endif
	{}

Protocol::Protocol(const std::string &name, const std::string &short_name):
	Protocol(name, short_name, 0)
	{}

Protocol::~Protocol() { 

	ipset_mng_.reset(); 
	name_.clear(); 
	short_name_.clear(); 
}


void Protocol::setIPSetManager(const SharedPointer<IPSetManager> ipset_mng) { 

	if (ipset_mng_) {
		ipset_mng_->setPluggedToName("");
	}
	if (ipset_mng) {
		ipset_mng_ = ipset_mng;
		ipset_mng_->setPluggedToName(getName());
	} else {
		ipset_mng_.reset();
	}
}

#ifdef PYTHON_BINDING
void Protocol::setDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling) { 

	// The user could unref the DatabaseAdaptor on execution time
	if (dbptr.is_none()) {
		is_set_db_ = false;
		dbptr_ = dbptr;
	} else {
		dbptr_ = dbptr; 
		is_set_db_ = true; 
		packet_sampling_ = packet_sampling; 
	}
}
#elif defined(RUBY_BINDING)
void Protocol::setDatabaseAdaptor(VALUE dbptr, int packet_sampling) { 

        if (!NIL_P(dbptr)) {
		// Ruby dont have the concept of abstract clases so in order
		// to verify that VALUE inheritance from DatabaseAdaptor we just
		// verify from the object dbptr that the methods insert,update and remove
		// exists on the instance
		
		if (rb_respond_to(dbptr, rb_intern("insert"))) {
			if (rb_respond_to(dbptr, rb_intern("update"))) {
				if (rb_respond_to(dbptr, rb_intern("remove"))) {
                			dbptr_ = dbptr;
                			is_set_db_ = true;
					packet_sampling_ = packet_sampling;
				}
			}
		}
        } else {
                dbptr_ = Qnil;
                is_set_db_ = false;
        }
}
#elif defined(JAVA_BINDING) || defined(GO_BINDING) 
void Protocol::setDatabaseAdaptor(DatabaseAdaptor *dbptr, int packet_sampling) {

	if (dbptr == nullptr) {
		dbptr_ = nullptr;
		is_set_db_ = false;
		packet_sampling_ = 0;
	} else {
		dbptr_ = dbptr;
		is_set_db_ = true;
		packet_sampling_ = packet_sampling;
	}	
}

#elif defined(LUA_BINDING)

void Protocol::setDatabaseAdaptor(lua_State *L, const char *obj_name, int packet_sampling) {

	/// https://www.lua.org/source/5.1/lua.h.html
	const char *object_name = lua_tostring(L, -1);
	std::string sname(object_name);

	if (sname.compare(obj_name) == 0) {
        	lua_getglobal(L, object_name);
        	if (lua_istable(L, -1)) {
                	lua_getfield(L, -1, "insert");
			if (lua_isfunction(L, -1)) {
				ref_function_insert_ = luaL_ref(L, LUA_REGISTRYINDEX);
			} else {	
				std::cerr << "No 'insert' method on Lua class " << object_name << std::endl;
				return;
			}
                	lua_getfield(L, -1, "update");
			if (lua_isfunction(L, -1)) {
				ref_function_update_ = luaL_ref(L, LUA_REGISTRYINDEX);
			} else {	
				std::cerr << "No 'update' method on Lua class " << object_name << std::endl;
				return;
			}
                	lua_getfield(L, -1, "remove");
			if (lua_isfunction(L, -1)) {
				ref_function_remove_ = luaL_ref(L, LUA_REGISTRYINDEX);
			} else {	
				std::cout << "No 'remove' method on Lua class " << object_name << std::endl;
				return;
			}
			L_ = L;
			is_set_db_ = true;
			packet_sampling_ = packet_sampling;
		}
	}
}

#endif

#if defined(BINDING) // Code specific for the different languages

#if defined(RUBY_BINDING)

// function for call ruby objects
static VALUE ruby_database_callback(VALUE ptr) {

	ruby_shared_data *data = (ruby_shared_data*)ptr;

	return rb_funcall2(data->obj, data->method_id, data->nargs, data->args);
}

#endif

void Protocol::databaseAdaptorInsertHandler(Flow *flow) {

	key_.str("");
	key_.clear();

        key_ << *flow;
#if defined(PYTHON_BINDING)
       	try {
		PyGilContext gil_lock;

               	boost::python::call_method<void>(dbptr_.ptr(), "insert", key_.str());
        } catch(std::exception &e) {
              	std::cout << __FILE__ << ":" << __func__ << ":ERROR:" << e.what() << std::endl;
        } 
#elif defined(RUBY_BINDING)

	ruby_shared_data rbdata;

	rbdata.obj = dbptr_;
	rbdata.method_id = rb_intern("insert");
	rbdata.nargs = 1;
	rbdata.args[0] = rb_str_new2(key_.str().c_str());
 
	int error = 0;
	VALUE result = rb_protect(ruby_database_callback, (VALUE)&rbdata, &error);

	if (error)
		throw "Ruby exception on insert";	

#elif defined(JAVA_BINDING) || defined(GO_BINDING)
	if (dbptr_ != nullptr) { 
		dbptr_->insert(key_.str());
	}
#elif defined(LUA_BINDING)

        lua_rawgeti(L_, LUA_REGISTRYINDEX, ref_function_insert_);

	lua_pushstring(L_, key_.str().c_str());

        int ret = 0;
        if ((ret = lua_pcall(L_, 1, 0, 0)) != 0) {
        	std::cout << __FILE__ << ":" << __func__ << ":ERROR:" << lua_tostring(L_, -1) << std::endl;
        }

#endif
}

void Protocol::databaseAdaptorUpdateHandler(Flow *flow) {

	key_.str("");
	key_.clear();
	data_.str("");
	data_.clear();

        key_ << *flow;
        flow->serialize(data_);

#if defined(PYTHON_BINDING)
        try {
		PyGilContext gil_lock;

              	boost::python::call_method<void>(dbptr_.ptr(), "update", key_.str(), data_.str());
        } catch(std::exception &e) {
                std::cout << __FILE__ << ":" << __func__ << ":ERROR:" << e.what() << std::endl;
        }
#elif defined(RUBY_BINDING)

        ruby_shared_data rbdata;

        rbdata.obj = dbptr_;
        rbdata.method_id = rb_intern("update");
        rbdata.nargs = 2;
        rbdata.args[0] = rb_str_new2(key_.str().c_str());
        rbdata.args[1] = rb_str_new2(data_.str().c_str());

        int error = 0;
        VALUE result = rb_protect(ruby_database_callback, (VALUE)&rbdata, &error);

        if (error)
                throw "Ruby exception on update";
#elif defined(JAVA_BINDING) || defined(GO_BINDING)
	if (dbptr_ != nullptr) { 
		dbptr_->update(key_.str(), data_.str());
	}
#elif defined(LUA_BINDING)

        lua_rawgeti(L_, LUA_REGISTRYINDEX, ref_function_update_);

        lua_pushstring(L_, key_.str().c_str());
        lua_pushstring(L_, data_.str().c_str());

        int ret = 0;
        if ((ret = lua_pcall(L_, 2, 0, 0)) != 0) {
                std::cout << __FILE__ << ":" << __func__ << ":ERROR:" << lua_tostring(L_, -1) << std::endl;
        }

#endif
}

void Protocol::databaseAdaptorRemoveHandler(Flow *flow) {

	key_.str("");
	key_.clear();

        key_ << *flow;

#if defined(PYTHON_BINDING)
        try {
		PyGilContext gil_lock;

               	boost::python::call_method<void>(dbptr_.ptr(), "remove", key_.str());
        } catch(std::exception &e) {
                std::cout <<  __FILE__ << ":" << __func__ << ":ERROR:" << e.what() << std::endl;
        }
#elif defined(RUBY_BINDING)

        ruby_shared_data rbdata;

        rbdata.obj = dbptr_;
        rbdata.method_id = rb_intern("remove");
        rbdata.nargs = 1;
        rbdata.args[0] = rb_str_new2(key_.str().c_str());

        int error = 0;
        VALUE result = rb_protect(ruby_database_callback, (VALUE)&rbdata, &error);

        if (error)
                throw "Ruby exception on remove";
#elif defined(JAVA_BINDING) || defined(GO_BINDING)
	if (dbptr_ != nullptr) { 
		dbptr_->remove(key_.str());
	}
#elif defined(LUA_BINDING)

        lua_rawgeti(L_, LUA_REGISTRYINDEX, ref_function_remove_);

        lua_pushstring(L_, key_.str().c_str());

        int ret = 0;
        if ((ret = lua_pcall(L_, 1, 0, 0)) != 0) {
                std::cout << __FILE__ << ":" << __func__ << ":ERROR:" << lua_tostring(L_, -1) << std::endl;
        }

#endif
}

#endif

void Protocol::infoMessage(const std::string &msg) {

#ifdef HAVE_LIBLOG4CXX
        LOG4CXX_INFO(logger, msg);
#else
	aiengine::information_message(msg);
#endif
}

void Protocol::showCacheMap(std::basic_ostream<char> &out, const char *tab, const GenericMapType &mt, const std::string &title, const std::string &item_name) const {

        out << tab << title << " usage" << "\n";

        std::vector<PairStringCacheHits> g_list(mt.begin(), mt.end());
        // Sort by using lambdas
        std::sort(
                g_list.begin(),
                g_list.end(),
                [] (PairStringCacheHits const &a, PairStringCacheHits const &b)
                {
			const StringCacheHits &h1 = a.second;
			const StringCacheHits &h2 = b.second;

                        return h1.hits > h2.hits;
        });

        for(auto it = g_list.begin(); it != g_list.end(); ++it) {
                SharedPointer<StringCache> uri = ((*it).second).sc;
                int hits = ((*it).second).hits;
                if (uri)
                         out << tab << "\t" << item_name << ":" << uri->getName() <<":" << hits << "\n";
        }
	out.flush();
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)

#if defined(PYTHON_BINDING)
boost::python::dict Protocol::addMapToHash(const GenericMapType &mt, const char *header) const {
        boost::python::dict cc;
#elif defined(RUBY_BINDING)
VALUE Protocol::addMapToHash(const GenericMapType &mt, const char *header) const {
        VALUE cc = rb_hash_new();
#endif
        for (auto &item: mt) {
                boost::string_ref label = item.first;
                int32_t hits = (item.second).hits;

                std::string key(header);

		key += label.data();
#if defined(PYTHON_BINDING)
		cc[key.c_str()] = hits;
#elif defined(RUBY_BINDING)
		rb_hash_aset(cc, rb_str_new2(key.c_str()), INT2NUM(hits));
#endif
        }

        return cc;
}

#endif

int32_t Protocol::releaseStringToCache(Cache<StringCache>::CachePtr &cache, const SharedPointer<StringCache> &item) {

	int32_t bytes_released = 0;

	if (item) {
                bytes_released = item->getNameSize();
                cache->release(item);
	}
	return bytes_released;
}

} // namespace aiengine  

