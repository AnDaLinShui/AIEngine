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
#include "MQTTProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr MQTTProtocol::logger(log4cxx::Logger::getLogger("aiengine.mqtt"));
#endif

// List of support operations
std::vector<MqttControlPacketType> MQTTProtocol::commands_ {
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_RESERVED1),	"reserveds",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT),		"connects",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNACK),		"connects ack",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH),		"publishs",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBACK),		"publishs ack",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBREC),		"publishs rec",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBREL),		"publishs rel",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBCOMP),		"publishs comp",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_SUBSCRIBE),	"subscribes",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_SUBACK),		"subscribes ack",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_UNSUBSCRIBE),	"unsubscribes",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_UNSUBACK),		"unsubscribes aAk",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PINGREQ),		"pings req",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PINGRESP),		"pings res",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_DISCONNECT),	"disconnects",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_RESERVED2),	"reserveds",	0)
};

MQTTProtocol::MQTTProtocol():
	Protocol("MQTTProtocol", "mqtt", IPPROTO_TCP),
	header_(nullptr),
	total_events_(0),
	total_mqtt_client_commands_(0),
	total_mqtt_server_responses_(0),
	length_offset_(0),
	info_cache_(new Cache<MQTTInfo>("MQTT Info cache")),
	topic_cache_(new Cache<StringCache>("MQTT Topic cache")),
	topic_map_(),
	flow_mng_(),
	current_flow_(nullptr),
	anomaly_() {}

MQTTProtocol::~MQTTProtocol() { 

	anomaly_.reset(); 
}

bool MQTTProtocol::mqttChecker(Packet &packet) {

	int length = packet.getLength();

	if (length >= header_size) {
		const uint8_t *payload = packet.getPayload();
		setHeader(payload);
		if (getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT)) {
			if (length >= header_size + (int)sizeof(mqtt_connect_header)) {
				const mqtt_connect_header *conn_hdr = reinterpret_cast<const mqtt_connect_header*>(&payload[header_size]);

				if((conn_hdr->proto_name[0] == 'M')and(conn_hdr->proto_name[1] == 'Q')) {
					++total_valid_packets_;
					return true;
				}
			}
		}
	}
	++total_invalid_packets_;
	return false;
}

int32_t MQTTProtocol::getLength() { 

	// Specific way of manage the lengths
	if (header_->length >= 0x80) {
		int8_t tok = header_->data[0];
		if ((tok & 0x80) == 0) { // For two bytes
			int8_t val = (header_->length & 0x7F); 
			int16_t value = val + (128 * tok); 
			length_offset_ = 2;
			return value;	
		}	
	}
	length_offset_ = 1;
	return header_->length;
}

void MQTTProtocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);	
	topic_cache_->setDynamicAllocatedMemory(value);	
}

bool MQTTProtocol::isDynamicAllocatedMemory() const {

	return info_cache_->isDynamicAllocatedMemory();
}	

int64_t MQTTProtocol::getCurrentUseMemory() const {

	int64_t mem = sizeof(MQTTProtocol);

	mem += info_cache_->getCurrentUseMemory();
	mem += topic_cache_->getCurrentUseMemory();

	return mem;
}

int64_t MQTTProtocol::getAllocatedMemory() const {

	int64_t mem = sizeof(MQTTProtocol);

        mem += info_cache_->getAllocatedMemory();
        mem += topic_cache_->getAllocatedMemory();

        return mem;
}

int64_t MQTTProtocol::getTotalAllocatedMemory() const {

        int64_t mem = getAllocatedMemory();

	mem += compute_memory_used_by_maps();

	return mem;
}

int64_t MQTTProtocol::compute_memory_used_by_maps() const {

	int64_t bytes = topic_map_.size() * sizeof(StringCacheHits);

	std::for_each (topic_map_.begin(), topic_map_.end(), [&bytes] (PairStringCacheHits const &f) {
		bytes += f.first.size();
	});
	return bytes;
}

int32_t MQTTProtocol::getTotalCacheMisses() const {

	int32_t miss = 0;

	miss = info_cache_->getTotalFails();
	miss += topic_cache_->getTotalFails();

	return miss;
}

void MQTTProtocol::releaseCache() {

	FlowManagerPtr fm = flow_mng_.lock();

	if (fm) {
		auto ft = fm->getFlowTable();

		std::ostringstream msg;
        	msg << "Releasing " << getName() << " cache";

		infoMessage(msg.str());

		int64_t total_bytes_released = compute_memory_used_by_maps();
		int64_t total_bytes_released_by_flows = 0;
		int32_t release_flows = 0;

                for (auto &flow: ft) {
                       	SharedPointer<MQTTInfo> info = flow->getMQTTInfo();
			if (info) {
				total_bytes_released_by_flows += releaseStringToCache(topic_cache_, info->topic);
                                total_bytes_released_by_flows += sizeof(info);
                               
                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(info);
                        }
                }

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
	}
}

void MQTTProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getMQTTInfo();
	if (info) {
		info_cache_->release(info);
	}
}

void MQTTProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	const uint8_t *payload = flow->packet->getPayload();
	total_bytes_ += length;
	++total_packets_;

       	SharedPointer<MQTTInfo> info = flow->getMQTTInfo();

       	if (!info) {
               	info = info_cache_->acquire();
               	if (!info) {
#ifdef HAVE_LIBLOG4CXX
			LOG4CXX_WARN (logger, "No memory on '" << info_cache_->getName() << "' for flow:" << *flow);
#endif
			return;
               	}
        	flow->layer7info = info;
	}

	current_flow_ = flow;

	if (info->getHaveData() == true) {
		int32_t left_length = info->getDataChunkLength() - length;
		if (left_length > 0) {
			info->setDataChunkLength(left_length);
		} else {
			info->setDataChunkLength(0);
			info->setHaveData(false);
		}
		return;
	}
        
	if (length >= header_size) {
		setHeader(payload);

		int8_t type = (int)getCommandType();
		if ((type > static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_RESERVED1))
			and(type < static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_RESERVED2))) {
				
			auto &command = commands_[type];

			int32_t *hits = &std::get<2>(command);
                        ++(*hits);
			info->setCommand(type);

			if (flow->getFlowDirection() == FlowDirection::FORWARD) { // client side
				++total_mqtt_client_commands_;
				info->incClientCommands();

				// The getLength also update the header_size with the variable length_offset_
				if (getLength() > length - header_size) {
					info->setDataChunkLength(getLength() - (length + header_size));
					info->setHaveData(true);
				}

				// The message publish message contains the topic and the information
				if (type == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH)) {
					handle_publish_message(info.get(), &payload[header_size], length - header_size);
				}
			} else { // Server side
				++ total_mqtt_server_responses_;
				info->incServerCommands();
			}
		}
	}
	return;
} 

void MQTTProtocol::handle_publish_message(MQTTInfo *info, const uint8_t *payload, int length) {

	int16_t msglen = 0;

	if (length_offset_ == 2) {
		msglen = ntohs((payload[2] << 8) + payload[1]);
	} else {
		msglen = payload[1];
	}
	
	if (msglen < length) {
		boost::string_ref topic((char*)&payload[length_offset_ + 1], msglen);

		attach_topic(info, topic);
	} else {
		++total_events_;
                if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        current_flow_->setPacketAnomaly(PacketAnomalyType::MQTT_BOGUS_HEADER);
                }
                anomaly_->incAnomaly(PacketAnomalyType::MQTT_BOGUS_HEADER);
	}
}

void MQTTProtocol::attach_topic(MQTTInfo *info, const boost::string_ref &topic) {

        if (!info->topic) {
                GenericMapType::iterator it = topic_map_.find(topic);
                if (it == topic_map_.end()) {
                        SharedPointer<StringCache> topic_ptr = topic_cache_->acquire();
                        if (topic_ptr) {
                                topic_ptr->setName(topic.data(), topic.size());
                                info->topic = topic_ptr;
                                topic_map_.insert(std::make_pair(topic_ptr->getName(), topic_ptr));
                        }
                } else {
                        ++ (it->second).hits;
                        info->topic = (it->second).sc;
                }
        }
}

void MQTTProtocol::statistics(std::basic_ostream<char> &out, int level) {

	if (level > 0) {
                int64_t alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";
		const char *dynamic_memory = (isDynamicAllocatedMemory() ? "yes":"no");

                unitConverter(alloc_memory, unit);

                out << getName() << "(" << this <<") statistics" << std::dec << "\n";
		out << "\t" << "Dynamic memory alloc:   " << std::setw(10) << dynamic_memory << "\n";
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << "\n";
        	out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << "\n";
        	out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ << std::endl;
		if (level > 1) {
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << "\n";
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << "\n";	
                        if (level > 3) {
                                out << "\t" << "Total client commands:  " << std::setw(10) << total_mqtt_client_commands_ << "\n";
                                out << "\t" << "Total server responses: " << std::setw(10) << total_mqtt_server_responses_ << "\n";

                                for (auto &command: commands_) {
                                        const char *label = std::get<1>(command);
                                        int32_t hits = std::get<2>(command);
                                        out << "\t" << "Total " << label << ":" << std::right << std::setfill(' ') << std::setw(27 - strlen(label)) << hits << "\n";
                                }
				out.flush();
			}
			if (level > 2) {	
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
                                if (level > 3) {
                                        info_cache_->statistics(out);
                                        topic_cache_->statistics(out);
                                        if (level > 4) {
                                                showCacheMap(out, "\t", topic_map_, "MQTT Topics", "Topic");
                                        }
                                }
			}
		}
	}
}


void MQTTProtocol::increaseAllocatedMemory(int value) { 

	info_cache_->create(value);
	topic_cache_->create(value);
}

void MQTTProtocol::decreaseAllocatedMemory(int value) { 

	info_cache_->destroy(value);
	topic_cache_->destroy(value);
}

CounterMap MQTTProtocol::getCounters() const { 
	CounterMap cm;

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
        cm.addKeyValue("commands", total_mqtt_client_commands_);
        cm.addKeyValue("responses", total_mqtt_server_responses_);

        for (auto &command: commands_) {
                const char *label = std::get<1>(command);

                cm.addKeyValue(label, std::get<2>(command));
        }

       	return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
#if defined(PYTHON_BINDING)
boost::python::dict MQTTProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE MQTTProtocol::getCache() const {
#endif
        return addMapToHash(topic_map_);
}

#if defined(PYTHON_BINDING)
void MQTTProtocol::showCache(std::basic_ostream<char> &out) const {

        showCacheMap(out, "", topic_map_, "MQTT Topics", "Topic");
}
#endif

#endif

} // namespace aiengine

