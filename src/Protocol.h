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
#ifndef SRC_PROTOCOL_H_
#define SRC_PROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif

#if defined(RUBY_BINDING)
#include <ruby.h>
#endif

#include <sys/types.h>
#if defined(__OPENBSD__)
#include <netinet/in_systm.h>
#include <net/ethertypes.h>
#else
#include <net/ethernet.h>
#endif

#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <boost/utility/string_ref.hpp>
#include "Pointer.h"
#include "FlowForwarder.h"
#include "Multiplexer.h"
#include "DatabaseAdaptor.h"
#include "ipset/IPSetManager.h"
#include "names/DomainNameManager.h"
#include "CounterMap.h"
#include "Cache.h"
#include "Message.h"

namespace aiengine {

class Flow;

struct StringCacheHits {
public:
	StringCacheHits(const SharedPointer<StringCache> &s):
		sc(s),
		hits(1) {}

	SharedPointer<StringCache> sc;
	int32_t hits;
};

typedef std::map<boost::string_ref, StringCacheHits> GenericMapType;
typedef std::pair<boost::string_ref, StringCacheHits> PairStringCacheHits; 

static std::function <void(int64_t&,std::string&)> unitConverter = [](int64_t &bytes, std::string &unit) noexcept { 
	if (bytes >1024) { bytes = bytes / 1024; unit = "KBytes"; } 
	if (bytes >1024) { bytes = bytes / 1024; unit = "MBytes"; } 
	if (bytes >1024) { bytes = bytes / 1024; unit = "GBytes"; } 
	if (bytes >1024) { bytes = bytes / 1024; unit = "TBytes"; } 
};

#if defined(JAVA_BINDING)

typedef std::map<std::string, int32_t> JavaCounters;

#elif defined(RUBY_BINDING)

typedef struct ruby_shared_data {
        VALUE obj;
	ID method_id;
	int nargs;
	VALUE args[4];
} ruby_shared_data;

#elif defined(LUA_BINDING)

typedef std::map<std::string, int32_t> LuaCounters;

#endif

class Protocol {
public:
    	explicit Protocol(const std::string &name, const std::string &short_name, uint16_t protocol_layer);
    	explicit Protocol(const std::string &name, const std::string &short_name);
    	virtual ~Protocol();

	virtual void setHeader(const uint8_t *raw_packet) = 0;

	virtual void statistics(std::basic_ostream<char> &out, int level) = 0;

	void setStatisticsLevel(int level) { stats_level_ = level; }

        int64_t getTotalBytes()  const { return total_bytes_; }
        int64_t getTotalPackets() const { return total_packets_; }
        int64_t getTotalValidPackets() const { return total_valid_packets_; }
        int64_t getTotalInvalidPackets() const { return total_invalid_packets_; }

	const char* getName() { return name_.c_str();} 
	const char* getShortName() { return short_name_.c_str();} 

	bool isActive() const { return is_active_; }
	void setActive(bool value) { is_active_ = value; }

	virtual void processFlow(Flow *flow) = 0;
	virtual bool processPacket(Packet &packet) = 0;

	void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; }
	MultiplexerPtrWeak getMultiplexer() { return mux_; } 

	void setFlowForwarder(WeakPointer<FlowForwarder> ff) { flow_forwarder_ = ff; }
	WeakPointer<FlowForwarder> getFlowForwarder() { return flow_forwarder_; } 

	uint16_t getProtocolLayer() const { return protocol_layer_; }

	void infoMessage(const std::string& msg);

	// Clear cache resources
	virtual void releaseCache() = 0;
	// virtual void releaseCache(int seconds) = 0;

	// Memory comsumption of the Protocol, caches items.
	virtual int64_t getAllocatedMemory() const = 0;
	// Memory comsumption of all the memory used
	virtual int64_t getTotalAllocatedMemory() const = 0;
	// current memory used by the caches
	virtual int64_t getCurrentUseMemory() const = 0;

	virtual void setDynamicAllocatedMemory(bool value) = 0;
	virtual bool isDynamicAllocatedMemory() const = 0;

	// used on mainly on the bindings
	virtual void increaseAllocatedMemory(int value) {}
	virtual void decreaseAllocatedMemory(int value) {}

        virtual void setDomainNameManager(const SharedPointer<DomainNameManager> &dnm) {} // Non pure virtual methods
        virtual void setDomainNameBanManager(const SharedPointer<DomainNameManager> &dnm) {}

	virtual void releaseFlowInfo(Flow *flow) {}

#ifdef HAVE_REJECT_FLOW
	virtual void addRejectFunction(std::function <void (Flow*)> reject) {}
#endif
	virtual void setAnomalyManager(SharedPointer<AnomalyManager> amng) {}

	virtual int32_t getTotalCacheMisses() const { return 0; }
	virtual int32_t getTotalEvents() const { return 0; }

	virtual CounterMap getCounters() const = 0;

#if defined(PYTHON_BINDING)
	virtual boost::python::dict getCache() const { return boost::python::dict(); }

	virtual void showCache(std::basic_ostream<char> &out) const {};

	void setDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling);  

	boost::python::dict addMapToHash(const GenericMapType &mt, const char *header = "") const;

#elif defined(RUBY_BINDING)
	virtual VALUE getCache() const { return Qnil; }
	void setDatabaseAdaptor(VALUE dbptr, int packet_sampling);  
	
	VALUE addMapToHash(const GenericMapType &mt, const char *header = "") const;
#elif defined(JAVA_BINDING) || defined(GO_BINDING)
	void setDatabaseAdaptor(DatabaseAdaptor *dbptr, int packet_sampling);
#elif defined(LUA_BINDING)
	void setDatabaseAdaptor(lua_State *L, const char *obj_name, int packet_sampling);
#endif

#if defined(BINDING)

	bool getDatabaseObjectIsSet() const { return is_set_db_;}
	int getPacketSampling() const { return packet_sampling_;}

	void databaseAdaptorInsertHandler(Flow *flow);
	void databaseAdaptorUpdateHandler(Flow *flow); 
	void databaseAdaptorRemoveHandler(Flow *flow); 
#endif
	void setIPSetManager(const SharedPointer<IPSetManager> ipset_mng); 

	SharedPointer<IPSetManager> ipset_mng_;
        MultiplexerPtrWeak mux_;
        WeakPointer<FlowForwarder> flow_forwarder_;
protected:
	// Helper for show the content of cache of StringCache types
	void showCacheMap(std::basic_ostream<char> &out, const char *tab, const GenericMapType &mt, const std::string &title, const std::string &item_name) const;

	int32_t releaseStringToCache(Cache<StringCache>::CachePtr &cache, const SharedPointer<StringCache> &item);

	int64_t total_valid_packets_;
	int64_t total_invalid_packets_;
	int64_t total_packets_;
	int64_t total_bytes_;
	int stats_level_;
private:
	std::string name_;
	std::string short_name_;
	uint16_t protocol_id_;
	uint16_t protocol_layer_; // TCP or UDP
	bool is_active_;
#if defined(BINDING)
	std::ostringstream key_;
	std::ostringstream data_;
#if defined(PYTHON_BINDING)
        boost::python::object dbptr_;
        bool is_set_db_;
	int packet_sampling_;
#elif defined(RUBY_BINDING)
	VALUE dbptr_;
	bool is_set_db_;
	int packet_sampling_;
#elif defined(JAVA_BINDING) || defined(GO_BINDING) 
	DatabaseAdaptor *dbptr_;
	bool is_set_db_;
	int packet_sampling_;
#elif defined(LUA_BINDING)
	lua_State *L_;
	bool is_set_db_;
	int packet_sampling_;
	int ref_function_insert_;
	int ref_function_update_;
	int ref_function_remove_;
#endif
#endif // defined(BINDING)

#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr <Protocol> ProtocolPtr;
typedef std::weak_ptr <Protocol> ProtocolPtrWeak;

} // namespace aiengine  

#endif  // SRC_PROTOCOL_H_
