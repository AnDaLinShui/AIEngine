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
#include "NetbiosProtocol.h"
#include <iomanip>

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr NetbiosProtocol::logger(log4cxx::Logger::getLogger("aiengine.netbios"));
#endif

NetbiosProtocol::NetbiosProtocol():
	Protocol("NetbiosProtocol", "netbios", IPPROTO_UDP),
	header_(nullptr),
	total_events_(0),
	info_cache_(new Cache<NetbiosInfo>("Netbios Info cache")),
	name_cache_(new Cache<StringCache>("Name cache")),
	name_map_(),
	flow_mng_(),
	current_flow_(nullptr),
	anomaly_() {} 

NetbiosProtocol::~NetbiosProtocol() {

	anomaly_.reset();
}

bool NetbiosProtocol::netbiosChecker(Packet &packet){

	int length = packet.getLength();

	if (length >= header_size) {
		if ((packet.getSourcePort() == 137)or(packet.getDestinationPort() == 137)or
			(packet.getSourcePort() == 138)or(packet.getDestinationPort() == 138)) {
			++total_valid_packets_;
			return true;
		}
	}
	++total_invalid_packets_;
	return false;
}

void NetbiosProtocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);	
	name_cache_->setDynamicAllocatedMemory(value);	
}

bool NetbiosProtocol::isDynamicAllocatedMemory() const {

	return info_cache_->isDynamicAllocatedMemory();
}

int64_t NetbiosProtocol::getCurrentUseMemory() const {

	int64_t mem = sizeof(NetbiosProtocol);

	mem += info_cache_->getCurrentUseMemory();
	mem += name_cache_->getCurrentUseMemory();

	return mem;
}

int64_t NetbiosProtocol::getAllocatedMemory() const {

	int64_t mem = sizeof(NetbiosProtocol);

        mem += info_cache_->getAllocatedMemory();
        mem += name_cache_->getAllocatedMemory();

        return mem;
}

int64_t NetbiosProtocol::getTotalAllocatedMemory() const {

        int64_t mem = getAllocatedMemory();

	mem += compute_memory_used_by_maps();

	return mem;
}

int32_t NetbiosProtocol::release_netbios_info(NetbiosInfo *info) {

        int32_t bytes_released = 0;

	bytes_released = releaseStringToCache(name_cache_, info->netbios_name);

        return bytes_released;
}

int64_t NetbiosProtocol::compute_memory_used_by_maps() const {

	int64_t bytes = name_map_.size() * sizeof(StringCacheHits);

	std::for_each (name_map_.begin(), name_map_.end(), [&bytes] (PairStringCacheHits const &f) {
		bytes += f.first.size();
	});
	return bytes;
}

int32_t NetbiosProtocol::getTotalCacheMisses() const {

	int32_t miss = 0;

	miss = info_cache_->getTotalFails();
	miss += name_cache_->getTotalFails();

	return miss;
}

void NetbiosProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

                int64_t total_bytes_released = compute_memory_used_by_maps();
                int64_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;
                int32_t release_name = name_map_.size();

                for (auto &flow: ft) {
                        SharedPointer<NetbiosInfo> info = flow->getNetbiosInfo();
                        if (info) {
                                total_bytes_released_by_flows = release_netbios_info(info.get());
                                total_bytes_released_by_flows += sizeof(info);

                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(info);
                        }
                }
                name_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_name << " netbios names, " << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}

void NetbiosProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getNetbiosInfo();
	if (info) {
		info_cache_->release(info);
	}
}

void NetbiosProtocol::attach_netbios_name(NetbiosInfo *info, const boost::string_ref &name) {

        if (!info->netbios_name) {
                GenericMapType::iterator it = name_map_.find(name);
                if (it == name_map_.end()) {
                        SharedPointer<StringCache> name_ptr = name_cache_->acquire();
                        if (name_ptr) {
                                name_ptr->setName(name.data(), name.length());
                                info->netbios_name = name_ptr;
                                name_map_.insert(std::make_pair(name_ptr->getName(), name_ptr));
                        }
                } else {
                        ++ (it->second).hits;
                        info->netbios_name = (it->second).sc;
                }
        }
}

void NetbiosProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ +=  length;
	++total_packets_;
	current_flow_ = flow;

       	SharedPointer<NetbiosInfo> info = flow->getNetbiosInfo();
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

	// A minimum header is :
	//   - header_size , simmilar to a dns.
	//   - 32 bytes of the netbios name.
	//   - 4 bytes of type and class.

	if (length <= header_size + 36) {
		++total_events_;
		// Malformed header packet
	        if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                       	current_flow_->setPacketAnomaly(PacketAnomalyType::NETBIOS_BOGUS_HEADER);
               	}
               	anomaly_->incAnomaly(PacketAnomalyType::NETBIOS_BOGUS_HEADER);
               	return;
	}

	setHeader(flow->packet->getPayload());
	int offset = 0;	
	for (int i = 0; i < 32; i = i + 2) {
		uint8_t ptr1 = header_->data[i + 1];
		uint8_t ptr2 = header_->data[i + 2];

		if (ptr1 < 'A' or ptr1 > 'P' or ptr2 < 'A' or ptr2 > 'P') 
			break;

		uint8_t value = ((ptr1 - 'A') << 4) + (ptr2 - 'A');

		if (value == 32) { // space that we dont want
			netbios_name_[offset] = 0x00;
			break;
		}

		if ((int)value <= 20) // skip the strange nb characters 
			continue;

		netbios_name_[offset] = value;
		++offset;
	}

	if (offset > 0) { // There is something to attach
		boost::string_ref nb_name(reinterpret_cast<char*>(netbios_name_), offset);
		attach_netbios_name(info.get(), nb_name);
	}
}

void NetbiosProtocol::statistics(std::basic_ostream<char> &out, int level){ 

	if (level > 0) {
                int64_t alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";
		const char *dynamic_memory = (isDynamicAllocatedMemory() ? "yes":"no");

                unitConverter(alloc_memory, unit);

                out << getName() << "(" << this <<") statistics" << std::dec << "\n";
		out << "\t" << "Dynamic memory alloc:   " << std::setw(10) << dynamic_memory << "\n";
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << "\n";
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << "\n";
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ << std::endl;
		if (level > 1) {
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << std::endl;
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << std::endl;
			if (level > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
                                if (level > 3) {
                                        info_cache_->statistics(out);
                                        name_cache_->statistics(out);
                                        if (level > 4) {
                                                showCacheMap(out, "\t", name_map_, "Netbios names", "Name");
                                        }
                                }
			}
		}
	}
}

void NetbiosProtocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
        name_cache_->create(value);
}

void NetbiosProtocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
        name_cache_->destroy(value);
}

CounterMap NetbiosProtocol::getCounters() const { 
	CounterMap cm;

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
	
        return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
#if defined(PYTHON_BINDING)
boost::python::dict NetbiosProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE NetbiosProtocol::getCache() const {
#endif
        return addMapToHash(name_map_);
}

#if defined(PYTHON_BINDING)
void NetbiosProtocol::showCache(std::basic_ostream<char> &out) const {

        showCacheMap(out, "", name_map_, "Netbios names", "Name");
}
#endif

#endif

} // namespace aiengine
