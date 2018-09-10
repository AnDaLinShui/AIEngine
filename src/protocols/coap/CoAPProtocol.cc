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
#include "CoAPProtocol.h"
#include <iomanip>

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr CoAPProtocol::logger(log4cxx::Logger::getLogger("aiengine.coap"));
#endif

CoAPProtocol::CoAPProtocol():
	Protocol("CoAPProtocol", "coap", IPPROTO_UDP),
	header_(nullptr),
	info_cache_(new Cache<CoAPInfo>("CoAP Info cache")),
	host_cache_(new Cache<StringCache>("Host cache")),
	uri_cache_(new Cache<StringCache>("Uri cache")),
	host_map_(),
	uri_map_(),
	domain_mng_(),
	ban_domain_mng_(),
	total_events_(0),
	total_allow_hosts_(0),
	total_ban_hosts_(0),
	total_coap_gets_(0),
	total_coap_posts_(0),
	total_coap_puts_(0),
	total_coap_deletes_(0),
	total_coap_others_(0),
	flow_mng_(),
	current_flow_(nullptr),
	anomaly_() {}

CoAPProtocol::~CoAPProtocol() {

	anomaly_.reset();
}

bool CoAPProtocol::coapChecker(Packet &packet) {

	int length = packet.getLength();

	if (length >= header_size) {
		if ((packet.getSourcePort() == 5683)||(packet.getDestinationPort() == 5683)) {
			setHeader(packet.getPayload());
			++total_valid_packets_;
			return true;
		}
	}
	++total_invalid_packets_;
        return false;
}

void CoAPProtocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);
	uri_cache_->setDynamicAllocatedMemory(value);
	host_cache_->setDynamicAllocatedMemory(value);
}

bool CoAPProtocol::isDynamicAllocatedMemory() const {

	return info_cache_->isDynamicAllocatedMemory();
}

int64_t CoAPProtocol::getCurrentUseMemory() const {

        int64_t mem = sizeof(CoAPProtocol);

        mem += info_cache_->getCurrentUseMemory();
        mem += uri_cache_->getCurrentUseMemory();
        mem += host_cache_->getCurrentUseMemory();

        return mem;
}

int64_t CoAPProtocol::getAllocatedMemory() const {

        int64_t mem = sizeof(CoAPProtocol);

        mem += host_cache_->getAllocatedMemory();
        mem += uri_cache_->getAllocatedMemory();
        mem += info_cache_->getAllocatedMemory();

        return mem;
}

int64_t CoAPProtocol::getTotalAllocatedMemory() const {

        int64_t mem = getAllocatedMemory();

	mem += compute_memory_used_by_maps();

	return mem;
}

int32_t CoAPProtocol::release_coap_info(CoAPInfo *info) {

        int32_t bytes_released = 0;

        bytes_released = releaseStringToCache(host_cache_, info->host_name);
        bytes_released += releaseStringToCache(uri_cache_, info->uri);

        return bytes_released;
}

int64_t CoAPProtocol::compute_memory_used_by_maps() const {

	int64_t bytes = (host_map_.size() + uri_map_.size()) * sizeof(StringCacheHits);

	// Compute the size of the strings used as keys on the map
	std::for_each (host_map_.begin(), host_map_.end(), [&bytes] (PairStringCacheHits const &dt) {
		bytes += dt.first.size();
	});
	std::for_each (uri_map_.begin(), uri_map_.end(), [&bytes] (PairStringCacheHits const &dt) {
		bytes += dt.first.size();
	});
	return bytes;
}

int32_t CoAPProtocol::getTotalCacheMisses() const {

	int32_t miss = 0;

	miss = info_cache_->getTotalFails();
	miss += host_cache_->getTotalFails();
	miss += uri_cache_->getTotalFails();
	
	return miss;
}

void CoAPProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

                int64_t total_bytes_released = compute_memory_used_by_maps();
                int64_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;
                int32_t release_hosts = host_map_.size();
                int32_t release_uris = uri_map_.size();

                for (auto &flow: ft) {
                        SharedPointer<CoAPInfo> info = flow->getCoAPInfo();
                        if (info) {
				total_bytes_released_by_flows += release_coap_info(info.get());
				total_bytes_released_by_flows += sizeof(info);

                                ++release_flows;
                                flow->layer7info.reset();
                                info_cache_->release(info);
                        }
                }

                uri_map_.clear();
                host_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_hosts << " hosts, " << release_uris << " uris, ";
                msg << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}

void CoAPProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getCoAPInfo();
	if (info) {
		info_cache_->release(info);
	}
}

void CoAPProtocol::processFlow(Flow *flow) {

	setHeader(flow->packet->getPayload());	
	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;
	++flow->total_packets_l7;

	if (length >= header_size) {
		setHeader(flow->packet->getPayload());	
		if (getVersion() == 1) {
                	SharedPointer<CoAPInfo> info = flow->getCoAPInfo();
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

			if (info->isBanned()) {
				return;
			}

			uint8_t type __attribute__((unused)) = getType();
			uint8_t code = getCode();
			const uint8_t *payload = (uint8_t*)header_;
			int offset = sizeof(coap_header) + getTokenLength();

			boost::string_ref header(reinterpret_cast<const char*>(&payload[offset]), length - offset);

			// TODO anomaly for the size of the getTokenLength()
			if (code == COAP_CODE_GET) {
				++ total_coap_gets_;
				process_common_header(info.get(), &payload[offset], length - offset);
			} else if (code == COAP_CODE_POST) {
				++ total_coap_posts_;
				process_common_header(info.get(), &payload[offset], length - offset);
			} else if (code == COAP_CODE_PUT) {
				++ total_coap_puts_;
				process_common_header(info.get(), &payload[offset], length - offset);
			} else if (code == COAP_CODE_DELETE) {
				++ total_coap_deletes_;
				process_common_header(info.get(), &payload[offset], length - offset);
			} else {
				++ total_coap_others_;
			}
		}
	} else {
		++total_events_;
                if (flow->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        flow->setPacketAnomaly(PacketAnomalyType::COAP_BOGUS_HEADER);
                }
                anomaly_->incAnomaly(PacketAnomalyType::COAP_BOGUS_HEADER);
	}
}

void CoAPProtocol::process_common_header(CoAPInfo *info, const uint8_t *payload, int length) {

	int offset = 0;
	int buffer_offset = 0;	
	uint8_t type = 0;

	do {
		int data_offset = 0;
		const coap_ext_header *extension = reinterpret_cast <const coap_ext_header*> (&payload[offset]);
		int delta = (extension->deltalength >> 4); 
		type += delta;	
		int extension_length = (extension->deltalength & 0x0F) ; 	
		if (extension_length > 12 ) {
			extension_length += extension->data[0];
			++data_offset;
		}
		const char *dataptr = reinterpret_cast <const char*> (&(extension->data[data_offset]));
		if (type == COAP_OPTION_URI_HOST) { // The hostname 
			boost::string_ref hostname(dataptr, extension_length);

        		if (ban_domain_mng_) {
                		auto host_candidate = ban_domain_mng_->getDomainName(hostname);
                		if (host_candidate) {
#ifdef HAVE_LIBLOG4CXX
                        		LOG4CXX_INFO (logger, "Flow:" << *current_flow_ << " matchs with ban host " << host_candidate->getName());
#endif
                        		++total_ban_hosts_;
					info->setIsBanned(true);
                        		return;
                		}
        		}
        		++total_allow_hosts_;

			attach_host_to_flow(info, hostname);
		} else {
			if ((type == COAP_OPTION_LOCATION_PATH)or(type == COAP_OPTION_URI_PATH)) {
				// Copy the parts of the uri on a temp buffer
				if ((buffer_offset + extension_length + 1) < MAX_URI_BUFFER) {
					std::memcpy(uri_buffer_ + buffer_offset, "/", 1); 
					++buffer_offset;
					std::memcpy(uri_buffer_ + buffer_offset, dataptr, extension_length);
					buffer_offset += extension_length;
				}
			}	
		}
		if (extension->data[0] == 0xFF) { // End of options marker
			break;
		}

		offset += extension_length + data_offset + 1;
	} while (offset + (int)sizeof(coap_ext_header) < length);

	if (buffer_offset > 0) { // There is a uri
		boost::string_ref uri(uri_buffer_, buffer_offset);

		attach_uri(info, uri);	
	}	

	// Just verify the hostname on the first coap request
        if (current_flow_->total_packets_l7 == 1) {
        	if ((domain_mng_)and(info->host_name)) {
                	auto host_candidate = domain_mng_->getDomainName(info->host_name->getName());
                        if (host_candidate) {
				++total_events_;
                               	info->matched_domain_name = host_candidate;
#if defined(BINDING)
#ifdef HAVE_LIBLOG4CXX
                                LOG4CXX_INFO (logger, "Flow:" << *current_flow_ << " matchs with " << host_candidate->getName());
#endif
                              	if (host_candidate->call.haveCallback()) {
                               		host_candidate->call.executeCallback(current_flow_);
                                }
#endif
    			}
  		}
	}	

	if ((info->matched_domain_name)and(buffer_offset > 0)) {
        	SharedPointer<HTTPUriSet> uset = info->matched_domain_name->getHTTPUriSet();
                if (uset) {
                	if (uset->lookupURI(info->uri->getName())) {
				++total_events_;
#if defined(BINDING)
                        	if (uset->call.haveCallback()) {
                                	uset->call.executeCallback(current_flow_);
                                }
#endif
			}
		}
	}
}

void CoAPProtocol::attach_host_to_flow(CoAPInfo *info, const boost::string_ref &hostname) {

        SharedPointer<StringCache> host_ptr = info->host_name;

        if (!host_ptr) { // There is no Hostname attached
                GenericMapType::iterator it = host_map_.find(hostname);
                if (it == host_map_.end()) {
                        host_ptr = host_cache_->acquire();
                        if (host_ptr) {
                                host_ptr->setName(hostname.data(), hostname.length());
                                info->host_name = host_ptr;
                                host_map_.insert(std::make_pair(host_ptr->getName(), host_ptr));
                        }
                } else {
                        ++ (it->second).hits;
                        info->host_name = (it->second).sc;
                }
        }
}

// The URI should be updated on every request
void CoAPProtocol::attach_uri(CoAPInfo *info, const boost::string_ref &uri) {

        GenericMapType::iterator it = uri_map_.find(uri);
        if (it == uri_map_.end()) {
                SharedPointer<StringCache> uri_ptr = uri_cache_->acquire();
                if (uri_ptr) {
                        uri_ptr->setName(uri.data(), uri.length());
                        info->uri = uri_ptr;
                        uri_map_.insert(std::make_pair(uri_ptr->getName(), uri_ptr));
                }
        } else {
                // Update the URI of the flow
                info->uri = (it->second).sc;
        }
}

void CoAPProtocol::setDomainNameManager(const SharedPointer<DomainNameManager>& dnm) {

	if (domain_mng_) {
               	domain_mng_->setPluggedToName("");
	}
	if (dnm) {
       		domain_mng_ = dnm;
        	domain_mng_->setPluggedToName(getName());
	} else {
		domain_mng_.reset();
	}
}

void CoAPProtocol::statistics(std::basic_ostream<char>& out, int level){ 

	if (level > 0) {
                int64_t alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";
		const char *dynamic_memory = (isDynamicAllocatedMemory() ? "yes":"no");

                unitConverter(alloc_memory, unit);

                out << getName() << "(" << this <<") statistics" << std::dec << "\n";

                if (ban_domain_mng_) out << "\t" << "Plugged banned domains from:" << ban_domain_mng_->getName() << "\n";
                if (domain_mng_) out << "\t" << "Plugged domains from:" << domain_mng_->getName() << "\n";

		out << "\t" << "Dynamic memory alloc:   " << std::setw(10) << dynamic_memory << "\n";
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << "\n";
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << "\n";
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ << std::endl;
		if (level > 1) {
			out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << "\n";
			out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << "\n";
                        if (level > 3) {
                        	out << "\t" << "Total gets:             " << std::setw(10) << total_coap_gets_ << "\n";
                        	out << "\t" << "Total posts:            " << std::setw(10) << total_coap_posts_ << "\n";
                        	out << "\t" << "Total puts:             " << std::setw(10) << total_coap_puts_ << "\n";
                        	out << "\t" << "Total delete:           " << std::setw(10) << total_coap_deletes_ << "\n";
                        	out << "\t" << "Total others:           " << std::setw(10) << total_coap_others_ << std::endl;
                        }
			if (level > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
                                if (level > 3) {
                                        info_cache_->statistics(out);
                                        host_cache_->statistics(out);
                                        uri_cache_->statistics(out);
                                        if (level > 4) {
                                                showCacheMap(out, "\t", host_map_, "CoAP Host", "Hostname");
                                                showCacheMap(out, "\t", uri_map_, "CoAP Uri", "Uri");
                                        }
                                }
			}
		}
	}
}


void CoAPProtocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
        host_cache_->create(value);
        uri_cache_->create(value);
}

void CoAPProtocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
        host_cache_->destroy(value);
        uri_cache_->destroy(value);
}

CounterMap CoAPProtocol::getCounters() const {
	CounterMap cm;

        cm.addKeyValue("packets",total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
        cm.addKeyValue("gets", total_coap_gets_);
        cm.addKeyValue("posts", total_coap_posts_);
        cm.addKeyValue("puts", total_coap_puts_);
        cm.addKeyValue("deletes", total_coap_deletes_);
        cm.addKeyValue("others", total_coap_others_);

	return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
#if defined(PYTHON_BINDING)
boost::python::dict CoAPProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE CoAPProtocol::getCache() const {
#endif
        return addMapToHash(host_map_);
}

#if defined(PYTHON_BINDING)
void CoAPProtocol::showCache(std::basic_ostream<char> &out) const {

        showCacheMap(out, "", host_map_, "CoAP Hosts", "Hostname");
}
#endif

#endif

} // namespace aiengine
