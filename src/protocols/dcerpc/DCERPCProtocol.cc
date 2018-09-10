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
#include "DCERPCProtocol.h"
#include <iomanip>

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr DCERPCProtocol::logger(log4cxx::Logger::getLogger("aiengine.dcerpc"));
#endif

DCERPCProtocol::DCERPCProtocol():
	Protocol("DCERPCProtocol", "dcerpc", IPPROTO_TCP),
	header_(nullptr),
        total_requests_(0),
        total_pings_(0),
        total_responses_(0),
        total_faults_(0),
        total_workings_(0),
        total_nocalls_(0),
        total_rejects_(0),
        total_acks_(0),
        total_cl_cancels_(0),
        total_facks_(0),
        total_cancel_acks_(0),
        total_binds_(0),
        total_bind_acks_(0),
        total_bind_naks_(0),
        total_alter_contexts_(0),
        total_alter_context_resps_(0),
        total_auth3s_(0),
        total_shutdonws_(0),
        total_co_cancels_(0),
        total_orphaneds_(0),
        total_others_(0),
        current_flow_(nullptr),
        info_cache_(new Cache<DCERPCInfo>("DCERPC Info cache")),
        uuid_cache_(new Cache<StringCache>("UUID cache")),
        uuid_map_(),
        flow_mng_() {}

DCERPCProtocol::~DCERPCProtocol() {}

bool DCERPCProtocol::dcerpcChecker(Packet &packet) {

	int length = packet.getLength();

	if (length >= header_size) {
		setHeader(packet.getPayload());
		if ((header_->version == 0x05)and(header_->version_minor == 0x00)) { 
			if (length == header_->frag_length) {
				++total_valid_packets_;
				return true;
			}
		}
	}
	++total_invalid_packets_;
	return false;
}

void DCERPCProtocol::setDynamicAllocatedMemory(bool value) {

        info_cache_->setDynamicAllocatedMemory(value);
        uuid_cache_->setDynamicAllocatedMemory(value);
}

bool DCERPCProtocol::isDynamicAllocatedMemory() const {

        return info_cache_->isDynamicAllocatedMemory();
}

int64_t DCERPCProtocol::getCurrentUseMemory() const {

        int64_t mem = sizeof(DCERPCProtocol);

        mem += info_cache_->getCurrentUseMemory();
        mem += uuid_cache_->getCurrentUseMemory();

        return mem;
}

int64_t DCERPCProtocol::getAllocatedMemory() const {

        int64_t mem = sizeof(DCERPCProtocol);

        mem += info_cache_->getAllocatedMemory();
        mem += uuid_cache_->getAllocatedMemory();

        return mem;
}

int64_t DCERPCProtocol::getTotalAllocatedMemory() const {

	int64_t mem = getAllocatedMemory();

        mem += compute_memory_used_by_maps();

	return mem;
}

int64_t DCERPCProtocol::compute_memory_used_by_maps() const {

        int64_t bytes = uuid_map_.size() * sizeof(StringCacheHits);

        std::for_each (uuid_map_.begin(), uuid_map_.end(), [&bytes] (PairStringCacheHits const &f) {
                bytes += f.first.size();
        });
        return bytes;
}

void DCERPCProtocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
        uuid_cache_->create(value);
}

void DCERPCProtocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
        uuid_cache_->destroy(value);
}

int32_t DCERPCProtocol::release_dcerpc_info(DCERPCInfo *info) {

        int32_t bytes_released = 0;

        bytes_released = releaseStringToCache(uuid_cache_, info->uuid);

        return bytes_released;
}

void DCERPCProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getDCERPCInfo();
	if (info) {
                info_cache_->release(info);
	}
}

void DCERPCProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

                int64_t total_bytes_released = compute_memory_used_by_maps();
                int64_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;
                int32_t release_uuids = uuid_map_.size();

                for (auto &flow: ft) {
                        SharedPointer<DCERPCInfo> info = flow->getDCERPCInfo();
                        if (info) {
                                total_bytes_released_by_flows = release_dcerpc_info(info.get());
                                total_bytes_released_by_flows += sizeof(info);

                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(info);
                        }
                }
                uuid_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_uuids << " uuids, " << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}

void DCERPCProtocol::update_unit_type(uint8_t type) {

	if (type <= DCERPC_UNIT_ORPHANED) {
		if (type == DCERPC_UNIT_REQUEST) 
			++total_requests_;
		else if (type == DCERPC_UNIT_PING) 
			++total_pings_;
		else if (type == DCERPC_UNIT_RESPONSE)
			++total_responses_;
		else if (type == DCERPC_UNIT_FAULT) 
			++total_faults_;
		else if (type == DCERPC_UNIT_WORKING)
			++total_workings_;
		else if (type == DCERPC_UNIT_NOCALL)
			++total_nocalls_;
		else if (type == DCERPC_UNIT_REJECT)
			++total_rejects_;
		else if (type == DCERPC_UNIT_ACK)
			++total_acks_;
		else if (type == DCERPC_UNIT_CL_CANCEL)
			++total_cl_cancels_;
		else if (type == DCERPC_UNIT_FACK)
			++total_facks_;
		else if (type == DCERPC_UNIT_CANCEL_ACK)
			++total_cancel_acks_;
		else if (type == DCERPC_UNIT_BIND)
			++total_binds_;
		else if (type == DCERPC_UNIT_BIND_ACK)
			++total_bind_acks_;
		else if (type == DCERPC_UNIT_BIND_NAK)
			++total_bind_naks_;
		else if (type == DCERPC_UNIT_ALTER_CONTEXT)
			++total_alter_contexts_;
		else if (type == DCERPC_UNIT_ALTER_CONTEXT_RESP)
			++total_alter_context_resps_;
		else if (type == DCERPC_UNIT_AUTH3)
			++total_auth3s_;
		else if (type == DCERPC_UNIT_SHUTDOWN)
			++total_shutdonws_;
		else if (type == DCERPC_UNIT_CO_CANCEL)
			++total_co_cancels_;
		else if (type == DCERPC_UNIT_ORPHANED)
			++total_orphaneds_;
		else
			++total_others_; 
	}
}

void DCERPCProtocol::attach_uuid(DCERPCInfo *info, const boost::string_ref &uuid) {

        GenericMapType::iterator it = uuid_map_.find(uuid);
        if (it == uuid_map_.end()) {
                SharedPointer<StringCache> uuid_ptr = uuid_cache_->acquire();
                if (uuid_ptr) {
                        uuid_ptr->setName(uuid.data(), uuid.length());
                        info->uuid = uuid_ptr;
                        uuid_map_.insert(std::make_pair(uuid_ptr->getName(), uuid_ptr));
                }
        } else {
                ++ (it->second).hits;
                info->uuid = (it->second).sc;
        }
}

void DCERPCProtocol::process_bind_message(DCERPCInfo *info, const uint8_t *payload, int length) {

	if (length > sizeof(dcerpc_header) + 12 + sizeof(dcerpc_context_item_header)) {
		const dcerpc_context_item_header *hdr = reinterpret_cast<const dcerpc_context_item_header*>(&header_->data[12]);

		if (hdr->items > 0) {	
			char buffer[64] = { 0 };

			std::snprintf(buffer, 64, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", 
				hdr->uuid[3], hdr->uuid[2], hdr->uuid[1], hdr->uuid[0],
				hdr->uuid[5], hdr->uuid[4], 
				hdr->uuid[7], hdr->uuid[6],
				hdr->uuid[8], hdr->uuid[9], 
				hdr->uuid[10], hdr->uuid[11], hdr->uuid[12], hdr->uuid[13], hdr->uuid[14], hdr->uuid[15]);

			boost::string_ref uuid(buffer, strlen(buffer));

			attach_uuid(info, uuid);
		}
	}
}

void DCERPCProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;
	++flow->total_packets_l7;

	current_flow_ = flow;

        if (length >= header_size) {
                SharedPointer<DCERPCInfo> info = flow->getDCERPCInfo();
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

		setHeader(flow->packet->getPayload());

		if ((header_->version == 0x05)and(header_->version_minor == 0x00)) {
			
			if (header_->packet_type == DCERPC_UNIT_BIND) 
				process_bind_message(info.get(), flow->packet->getPayload(), length);

			update_unit_type(header_->packet_type);
		}
	}
}

void DCERPCProtocol::statistics(std::basic_ostream<char>& out, int level) { 

	if (level > 0) {
                int64_t alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory, unit);

                out << getName() << "(" << this <<") statistics" << std::dec << "\n";
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << "\n";
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << "\n";
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ << std::endl;
		if (level > 1) {
			out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << "\n";
			out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << "\n";
                        if (level > 3) {
                                out << "\t" << "Total requests:         " << std::setw(10) << total_requests_ << "\n";
                                out << "\t" << "Total pings:            " << std::setw(10) << total_pings_ << "\n";
                                out << "\t" << "Total responses:        " << std::setw(10) << total_responses_ << "\n";
                                out << "\t" << "Total faults:           " << std::setw(10) << total_faults_ << "\n";
                                out << "\t" << "Total workings:         " << std::setw(10) << total_workings_ << "\n";
                                out << "\t" << "Total nocalls:          " << std::setw(10) << total_nocalls_ << "\n";
                                out << "\t" << "Total rejects:          " << std::setw(10) << total_rejects_ << "\n";
                                out << "\t" << "Total acks:             " << std::setw(10) << total_acks_ << "\n";
                                out << "\t" << "Total cl cancels:       " << std::setw(10) << total_cl_cancels_ << "\n";
                                out << "\t" << "Total facks:            " << std::setw(10) << total_facks_ << "\n";
                                out << "\t" << "Total cancel acks:      " << std::setw(10) << total_cancel_acks_ << "\n";
                                out << "\t" << "Total binds:            " << std::setw(10) << total_binds_ << "\n";
                                out << "\t" << "Total bind acks:        " << std::setw(10) << total_bind_acks_ << "\n";
                                out << "\t" << "Total bind naks:        " << std::setw(10) << total_bind_naks_ << "\n";
                                out << "\t" << "Total alter ctxs:       " << std::setw(10) << total_alter_contexts_ << "\n";
                                out << "\t" << "Total alter ctx resps:  " << std::setw(10) << total_alter_context_resps_ << "\n";
                                out << "\t" << "Total auth3s:           " << std::setw(10) << total_auth3s_ << "\n";
                                out << "\t" << "Total shutdowns:        " << std::setw(10) << total_shutdonws_ << "\n";
                                out << "\t" << "Total co cancels:       " << std::setw(10) << total_co_cancels_ << "\n";
                                out << "\t" << "Total orphaneds:        " << std::setw(10) << total_orphaneds_ << "\n";
                        	out << "\t" << "Total others:           " << std::setw(10) << total_others_ << std::endl;
                        }
                        if (level > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
                                if (level > 3) {
                                        info_cache_->statistics(out);
                                        uuid_cache_->statistics(out);
                                        if (level > 4) {
                                                showCacheMap(out, "\t", uuid_map_, "UUIDs", "UUID");
                                        }
                                }
                        }
		}
	}
}

CounterMap DCERPCProtocol::getCounters() const {
       	CounterMap cm;
 
        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);

	// Specific from DCERPC
	cm.addKeyValue("requests", total_requests_);
	cm.addKeyValue("pings", total_pings_);
	cm.addKeyValue("responses", total_responses_);
	cm.addKeyValue("faults", total_faults_);
	cm.addKeyValue("workings", total_workings_);
	cm.addKeyValue("nocalls", total_nocalls_);
	cm.addKeyValue("rejects", total_rejects_);
	cm.addKeyValue("acks", total_acks_);
	cm.addKeyValue("cl cancels", total_cl_cancels_);
	cm.addKeyValue("facks", total_facks_);
	cm.addKeyValue("cancel acks", total_cancel_acks_);
	cm.addKeyValue("binds", total_binds_);
	cm.addKeyValue("bind acks", total_bind_acks_);
	cm.addKeyValue("bind naks", total_bind_naks_);
	cm.addKeyValue("alter ctxs", total_alter_contexts_);
	cm.addKeyValue("alter ctx resps", total_alter_context_resps_);
	cm.addKeyValue("auth3s", total_auth3s_);
	cm.addKeyValue("shutdowns", total_shutdonws_);
	cm.addKeyValue("co cancels", total_co_cancels_);
	cm.addKeyValue("orphaneds", total_orphaneds_);
	cm.addKeyValue("others", total_others_);

        return cm;
}

#if defined(PYTHON_BINDING)
void DCERPCProtocol::showCache(std::basic_ostream<char> &out) const {

        showCacheMap(out, "", uuid_map_, "UUIDs", "UUID");
}
#endif

} // namespace aiengine
