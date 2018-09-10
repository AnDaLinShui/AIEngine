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
#ifndef SRC_PROTOCOLS_MQTT_MQTTPROTOCOL_H_ 
#define SRC_PROTOCOLS_MQTT_MQTTPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "MQTTInfo.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include "Cache.h"
#include <unordered_map>
#include "names/DomainNameManager.h"
#include "flow/FlowManager.h"

namespace aiengine {

// Minimum MQTT header, for data and signaling
struct mqtt_header {
	uint8_t 	type;
	uint8_t 	length;
	uint8_t 	data[0];
} __attribute__((packed));

struct mqtt_connect_header {
	uint8_t 	pad1;
	uint8_t 	pad2;
	char 		proto_name[4];
	uint8_t 	proto_level;
	uint8_t 	flags;
	uint16_t 	keep_alive;
} __attribute__((packed));

enum class MQTTControlPacketTypes : std::int8_t {
	MQTT_CPT_RESERVED1 = 	0,
	MQTT_CPT_CONNECT ,  	
	MQTT_CPT_CONNACK ,  	
	MQTT_CPT_PUBLISH ,  	
	MQTT_CPT_PUBACK ,  	
	MQTT_CPT_PUBREC ,  	
	MQTT_CPT_PUBREL ,  	
	MQTT_CPT_PUBCOMP ,  	
	MQTT_CPT_SUBSCRIBE ,  	
	MQTT_CPT_SUBACK ,  	
	MQTT_CPT_UNSUBSCRIBE ,  	
	MQTT_CPT_UNSUBACK ,  	
	MQTT_CPT_PINGREQ ,  	
	MQTT_CPT_PINGRESP ,  	
	MQTT_CPT_DISCONNECT ,  	
	MQTT_CPT_RESERVED2  	
};

// Commands with statistics
typedef std::tuple<std::int8_t, const char*,int32_t> MqttControlPacketType;

class MQTTProtocol: public Protocol {
public:
    	explicit MQTTProtocol();
    	virtual ~MQTTProtocol(); 

	static const uint16_t id = 0;
	static const int header_size = sizeof(mqtt_header); 

	int getHeaderSize() const { return header_size;}

	bool processPacket(Packet &packet) override { return true; }
	void processFlow(Flow *flow) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override; 

        void setHeader(const uint8_t *raw_packet) override {
                
		header_ = reinterpret_cast<const mqtt_header*>(raw_packet);
        }

	// Condition for say that a payload is MQTT 
	bool mqttChecker(Packet &packet); 

	int8_t getCommandType() const { return header_->type >> 4; }
	uint8_t getFlags() const { return header_->type & 0x0F; }
	int32_t getLength(); 

	int32_t getTotalClientCommands() const { return total_mqtt_client_commands_; }
	int32_t getTotalServerCommands() const { return total_mqtt_server_responses_; }

        void increaseAllocatedMemory(int value) override; 
        void decreaseAllocatedMemory(int value) override; 

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	int64_t getCurrentUseMemory() const override;
	int64_t getAllocatedMemory() const override;
	int64_t getTotalAllocatedMemory() const override;

        void setDynamicAllocatedMemory(bool value) override; 
        bool isDynamicAllocatedMemory() const override; 

	int32_t getTotalCacheMisses() const override;
	int32_t getTotalEvents() const override { return total_events_; }

	Flow *getCurrentFlow() const { return current_flow_; }

	CounterMap getCounters() const override; 

#if defined(PYTHON_BINDING)
        boost::python::dict getCache() const override;
	void showCache(std::basic_ostream<char> &out) const override;
#elif defined(RUBY_BINDING)
        VALUE getCache() const;
#endif
	void setAnomalyManager(SharedPointer<AnomalyManager> amng) override { anomaly_ = amng; }

	void releaseFlowInfo(Flow *flow) override;

private:
	void release_mqtt_info_cache(MQTTInfo *info);
	int32_t release_mqtt_info(MQTTInfo *info);
	int64_t compute_memory_used_by_maps() const;

	void attach_topic(MQTTInfo *info, const boost::string_ref &topic);
	void handle_publish_message(MQTTInfo *info, const uint8_t *payload, int length);

	const mqtt_header *header_;
        int32_t total_events_;

	static std::vector<MqttControlPacketType> commands_;
	
	int32_t total_mqtt_client_commands_;
	int32_t total_mqtt_server_responses_;

	int8_t length_offset_;

        Cache<MQTTInfo>::CachePtr info_cache_;
        Cache<StringCache>::CachePtr topic_cache_;

	GenericMapType topic_map_;

	FlowManagerPtrWeak flow_mng_;
	Flow *current_flow_;	
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
	SharedPointer<AnomalyManager> anomaly_;
};

typedef std::shared_ptr<MQTTProtocol> MQTTProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_MQTT_MQTTPROTOCOL_H_
