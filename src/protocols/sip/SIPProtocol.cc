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
#include "SIPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr SIPProtocol::logger(log4cxx::Logger::getLogger("aiengine.sip"));
#endif

SIPProtocol::SIPProtocol():
	Protocol("SIPProtocol", "sip", IPPROTO_UDP),
	sip_from_(new Regex("From expression", "From: .*?\r\n")),
	sip_to_(new Regex("To expression", "To: .*?\r\n")),
	sip_via_(new Regex("Via expression", "Via: .*?\r\n")),
	header_(nullptr),
	total_events_(0),
	total_requests_(0),
	total_responses_(0),
        total_registers_(0),
        total_invites_(0),
        total_publishs_(0),
        total_byes_(0),
        total_acks_(0),
        total_subscribes_(0),
        total_messages_(0),
        total_cancels_(0),
        total_refers_(0),
        total_infos_(0),
        total_options_(0),
        total_notifies_(0),
        total_pings_(0),
	total_sip_others_(0),
	info_cache_(new Cache<SIPInfo>("SIP Info cache")),
	uri_cache_(new Cache<StringCache>("Uri cache")),
	via_cache_(new Cache<StringCache>("Via cache")),
	from_cache_(new Cache<StringCache>("From cache")),
	to_cache_(new Cache<StringCache>("To cache")),
	uri_map_(),
	via_map_(),
	from_map_(),
	to_map_(),
	flow_mng_(),
	current_flow_(nullptr) {}

/*      
 * The function get_sip_request_method are optimized, compare with the predecessor memcmp implementation
 * results shows that by checking on this way there is a big performance improvement
 * however the functions are not pleasant to view but sometimes..... 
 */     
        
std::tuple<bool, int> SIPProtocol::get_sip_request_method(const boost::string_ref &hdr) {
        
        if ((hdr[0] == 'R')and(hdr[1] == 'E')) {
                if ((hdr[2] == 'G')and(hdr[3] == 'I')) {
                	if ((hdr[4] == 'S')and(hdr[5] == 'T')) {
                		if ((hdr[6] == 'E')and(hdr[7] == 'R')) {
                        		++total_registers_;
                        		return std::tuple<bool, int>(true, 8);
				}
			}
                } else if ((hdr[2] == 'F')and(hdr[3] == 'E')) {
			if (hdr[4] == 'R') {
				++total_refers_;
                        	return std::tuple<bool, int>(true, 5);
			}
		}
        } else if ((hdr[0] == 'I')and(hdr[1] == 'N')) {                 
                if ((hdr[2] == 'V')and(hdr[3] == 'I')) {
                	if ((hdr[4] == 'T')and(hdr[5] == 'E')) {
                        	++total_invites_;
                        	return std::tuple<bool, int>(true, 6);         
			} 
                } else if ((hdr[2] == 'F')and(hdr[3] == 'O')) {
                       	++total_infos_;
                       	return std::tuple<bool, int>(true, 4);          
		}
        } else if ((hdr[0] == 'A')and(hdr[1] == 'C')) {   
                if (hdr[2] == 'K') {
                	++total_acks_;
                        return std::tuple<bool, int>(true, 3);
		}
        } else if ((hdr[0] == 'C')and(hdr[1] == 'A')) {
                if ((hdr[2] == 'N')and(hdr[3] == 'C')) {
                	if ((hdr[4] == 'E')and(hdr[5] == 'L')) {
                		++total_cancels_;
                        	return std::tuple<bool, int>(true, 6);
			}
		}
        } else if ((hdr[0] == 'P')and(hdr[1] == 'U')) {
                if ((hdr[2] == 'B')and(hdr[3] == 'L')) {
                	if ((hdr[4] == 'I')and(hdr[5] == 'S')) {
				if (hdr[6] == 'H') {
                			++total_publishs_;
                        		return std::tuple<bool, int>(true, 7);
				}
			}
		}
        } else if ((hdr[0] == 'S')and(hdr[1] == 'U')) {
                if ((hdr[2] == 'B')and(hdr[3] == 'S')) {
                	if ((hdr[4] == 'C')and(hdr[5] == 'R')) {
                		if ((hdr[6] == 'I')and(hdr[7] == 'B')) {
					if (hdr[8] == 'E') {
                				++total_subscribes_;
                        			return std::tuple<bool, int>(true, 9);
					}
				}
			}
		}
        } else if ((hdr[0] == 'M')and(hdr[1] == 'E')) {
                if ((hdr[2] == 'S')and(hdr[3] == 'S')) {
                	if ((hdr[4] == 'A')and(hdr[5] == 'G')) {
				if (hdr[6] == 'E') {
                			++total_messages_;
                        		return std::tuple<bool, int>(true, 7);
				}
			}
		}
        } else if ((hdr[0] == 'O')and(hdr[1] == 'P')) {
                if ((hdr[2] == 'T')and(hdr[3] == 'I')) {
                	if ((hdr[4] == 'O')and(hdr[5] == 'N')) {
				if (hdr[6] == 'S') {
                			++total_options_;
                        		return std::tuple<bool, int>(true, 7);
				}
			}
		}
        } else if ((hdr[0] == 'N')and(hdr[1] == 'O')) {
                if ((hdr[2] == 'T')and(hdr[3] == 'I')) {
                	if ((hdr[4] == 'F')and(hdr[5] == 'Y')) {
                		++total_notifies_;
                        	return std::tuple<bool, int>(true, 6);
			}
		}
        } else if ((hdr[0] == 'P')and(hdr[1] == 'I')) {
                if ((hdr[2] == 'N')and(hdr[3] == 'G')) {
                	++total_pings_;
                       	return std::tuple<bool, int>(true, 4);
		}
        } else if ((hdr[0] == 'B')and(hdr[1] == 'Y')) {
                if (hdr[2] == 'E') {
                	++total_byes_;
                       	return std::tuple<bool, int>(true, 3);
		}
	}
	return std::tuple<bool, int>(false, 0);
}


bool SIPProtocol::sipChecker(Packet &packet) {

	// TODO: I dont like this idea of ports but...
	if ((packet.getSourcePort() == 5060)||(packet.getDestinationPort() == 5060)) {

		setHeader(packet.getPayload());
		++total_valid_packets_;
		return true;
	} else {
		++total_invalid_packets_;
		return false;
	}
}

void SIPProtocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);
	uri_cache_->setDynamicAllocatedMemory(value);
	via_cache_->setDynamicAllocatedMemory(value);
	from_cache_->setDynamicAllocatedMemory(value);
	to_cache_->setDynamicAllocatedMemory(value);
}

bool SIPProtocol::isDynamicAllocatedMemory() const {

	return info_cache_->isDynamicAllocatedMemory();
}	

int64_t SIPProtocol::getCurrentUseMemory() const {

	int64_t mem = sizeof(SIPProtocol);

	mem += info_cache_->getCurrentUseMemory();
	mem += uri_cache_->getCurrentUseMemory();
	mem += via_cache_->getCurrentUseMemory();
	mem += from_cache_->getCurrentUseMemory();
	mem += to_cache_->getCurrentUseMemory();
	
	return mem;
}

int64_t SIPProtocol::getAllocatedMemory() const {

        int64_t mem = sizeof(SIPProtocol);

        mem += info_cache_->getAllocatedMemory();
        mem += uri_cache_->getAllocatedMemory();
        mem += via_cache_->getAllocatedMemory();
        mem += from_cache_->getAllocatedMemory();
        mem += to_cache_->getAllocatedMemory();

        return mem;
}

int32_t SIPProtocol::release_sip_info(SIPInfo *info) {

        int32_t bytes_released = 0;

        bytes_released = releaseStringToCache(uri_cache_, info->uri);
        bytes_released += releaseStringToCache(via_cache_, info->via);
        bytes_released += releaseStringToCache(from_cache_, info->from);
        bytes_released += releaseStringToCache(to_cache_, info->to);

        return bytes_released;
}

int64_t SIPProtocol::getTotalAllocatedMemory() const {

        int64_t mem = getAllocatedMemory();
	
	mem += compute_memory_used_by_maps();

	return mem;
}

int64_t SIPProtocol::compute_memory_used_by_maps() const {

	int64_t bytes = (from_map_.size() + uri_map_.size() + to_map_.size() + via_map_.size());
	
	bytes = bytes * sizeof(StringCacheHits);
	
	// Compute the size of the strings used as keys on the map
	std::for_each (from_map_.begin(), from_map_.end(), [&bytes] (PairStringCacheHits const &f) {
		bytes += f.first.size();
	});
	std::for_each (uri_map_.begin(), uri_map_.end(), [&bytes] (PairStringCacheHits const &u) {
		bytes += u.first.size();
	});
	std::for_each (to_map_.begin(), to_map_.end(), [&bytes] (PairStringCacheHits const &t) {
		bytes += t.first.size();
	});
	std::for_each (via_map_.begin(), via_map_.end(), [&bytes] (PairStringCacheHits const &t) {
		bytes += t.first.size();
	});
	return bytes;
}

int32_t SIPProtocol::getTotalCacheMisses() const {

	int32_t miss = 0;

	miss = info_cache_->getTotalFails();
	miss += uri_cache_->getTotalFails();
	miss += via_cache_->getTotalFails();
	miss += from_cache_->getTotalFails();
	miss += to_cache_->getTotalFails();

	return miss;
}

void SIPProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

                int64_t total_bytes_released = compute_memory_used_by_maps();
                int64_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;
                int32_t release_from = from_map_.size();
                int32_t release_uris = uri_map_.size();
                int32_t release_to = to_map_.size();
                int32_t release_via = via_map_.size();

                for (auto &flow: ft) {
			SharedPointer<SIPInfo> info = flow->getSIPInfo();
			if (info) {
				total_bytes_released_by_flows += release_sip_info(info.get());
                		total_bytes_released_by_flows += sizeof(info);        
	
                        	++release_flows;
				flow->layer7info.reset();
				info_cache_->release(info);
			}
                } 
                uri_map_.clear();
                from_map_.clear();
                to_map_.clear();
                via_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);
                }
        
        	msg.str("");
                msg << "Release " << release_uris << " uris, " << release_via << " vias, " << release_from;
                msg << " froms, " << release_to << " tos, " << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}

void SIPProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getSIPInfo();
	if (info) {
		info_cache_->release(info);
	}
}

void SIPProtocol::extract_via_value(SIPInfo *info, const boost::string_ref &header) {

        if (sip_via_->matchAndExtract(header)) {

		boost::string_ref via_raw(sip_via_->getExtract());
		boost::string_ref via(via_raw.substr(5, via_raw.size() - 7)); // remove also the \r\n
                
                attach_via_to_flow(info, via);
        }
}

void SIPProtocol::extract_from_value(SIPInfo *info, const boost::string_ref &header) {

	if (sip_from_->matchAndExtract(header)) {

		boost::string_ref from_raw(sip_from_->getExtract());
		boost::string_ref from(from_raw.substr(6, from_raw.size() - 8)); // remove also the \r\n
 
		attach_from_to_flow(info, from);
	}
}


void SIPProtocol::attach_from_to_flow(SIPInfo *info, const boost::string_ref &from) {

	if (!info->from) {
		GenericMapType::iterator it = from_map_.find(from);
		if (it == from_map_.end()) {
			SharedPointer<StringCache> from_ptr = from_cache_->acquire();
			if (from_ptr) {
				from_ptr->setName(from.data(), from.length());
				info->from = from_ptr;
				from_map_.insert(std::make_pair(from_ptr->getName(), from_ptr));
			}
		} else {
			++ (it->second).hits;
			info->from = (it->second).sc;
		}
	}
}

void SIPProtocol::extract_to_value(SIPInfo *info, const boost::string_ref &header) {

	if (sip_to_->matchAndExtract(header)) {

		boost::string_ref to_raw(sip_to_->getExtract());
		boost::string_ref to(to_raw.substr(4, to_raw.size() - 6)); // remove also the \r\n

		attach_to_to_flow(info, to);
	}
}

void SIPProtocol::attach_to_to_flow(SIPInfo *info, const boost::string_ref &to) {

	if (!info->to) {
		GenericMapType::iterator it = to_map_.find(to);
		if (it == to_map_.end()) {
			SharedPointer<StringCache> to_ptr = to_cache_->acquire();
			if (to_ptr) {
				to_ptr->setName(to.data(), to.length());
				info->to = to_ptr;
				to_map_.insert(std::make_pair(to_ptr->getName(), to_ptr));
			}	
		} else {
			++ (it->second).hits;
			info->to = (it->second).sc;	
		}
	}

}

void SIPProtocol::attach_via_to_flow(SIPInfo *info, const boost::string_ref &via) {

	if (!info->via) {
                GenericMapType::iterator it = via_map_.find(via);
                if (it == via_map_.end()) {
                        SharedPointer<StringCache> via_ptr = via_cache_->acquire();
                        if (via_ptr) {
                                via_ptr->setName(via.data(), via.length());
                                info->via = via_ptr;
                                via_map_.insert(std::make_pair(via_ptr->getName(), via_ptr));
                        }
                } else {
                        ++ (it->second).hits;
                        info->via = (it->second).sc;
                }
        }
}


void SIPProtocol::attach_uri_to_flow(SIPInfo *info, const boost::string_ref &uri) {

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
                ++ (it->second).hits;
		info->uri = (it->second).sc;
	}
}


void SIPProtocol::extract_uri_value(SIPInfo *info, const boost::string_ref &header) {

	int offset = 0;
	bool found = false;

	// Check if is a response 
        if ((header[0] == 'S')and(header[1] == 'I')and(header[2] == 'P')and
		(header[3] == '/')and(header[4] == '2')and(header[5] == '.')) {
                ++total_responses_;

                // No uri to extract
		return;
	} 

	std::tuple<bool, int> value = get_sip_request_method(header);
	found = std::get<0>(value);
	offset = std::get<1>(value);

	++offset;

	if ((found)and(offset > 0)) {
		int end = header.find("SIP/2.");
		if (end > 0) {
			boost::string_ref uri(header.substr(offset, (end - offset) - 1));
	
			++total_requests_;	
			attach_uri_to_flow(info, uri);	
		}
	}else{
		++total_sip_others_;
	}
}

std::tuple<uint32_t, uint16_t> SIPProtocol::extract_ip_and_port_from_sdp(const boost::string_ref &sdp) {

	uint32_t ipaddress = 0;
	uint16_t port = 0;

	int end = sdp.find("c=IN IP4 ");
	if (end > 0) {
		boost::string_ref param(sdp.substr(end + 9, sdp.length() - (end + 9)));

		int endl = param.find("\r\n");
		if (endl > 0) {
			std::string value(param.substr(0, endl));
        		struct sockaddr_in sa;

        		if (inet_pton(AF_INET, value.c_str(), &(sa.sin_addr))) {
                		ipaddress = sa.sin_addr.s_addr;
			}
		}
	}
	end = sdp.find("m=audio ");
	if (end > 0) {
		boost::string_ref param(sdp.substr(end + 8, sdp.length() - (end + 8)));

		int endl = param.find(" ");
		if (endl > 0) {
			boost::string_ref value(param.substr(0, endl));

			port = std::atoi(value.data());
		}
	}
	return std::tuple<uint32_t, int16_t>(ipaddress, port);
}

void SIPProtocol::handle_invite(SIPInfo *info, const boost::string_ref &header) {

	int end = header.find("Content-Type: application/sdp");
	if (end > 0) {
		// Now find the end of the header
		int endh = header.find("\r\n\r\n");
		if (endh > 0) {
			boost::string_ref sdp(header.substr(endh, header.length() - endh));

			std::tuple<uint32_t, uint16_t> values = extract_ip_and_port_from_sdp(sdp);

			uint32_t ipaddress = std::get<0>(values);
        		uint16_t port = std::get<1>(values);

			if ((ipaddress > 0)and(port > 0)) {
				info->setState(SIP_TRYING_CALL);
				info->src_addr.s_addr = ipaddress;
				info->src_port = port;
			}
		}
	}
}

void SIPProtocol::handle_ok(SIPInfo *info, const boost::string_ref &header) {

	if (info->getState() == SIP_TRYING_CALL) {

		int end = header.find("Content-Type: application/sdp");
		if (end > 0) {
			// Now find the end of the header
			int endh = header.find("\r\n\r\n");
			if (endh > 0) {
				boost::string_ref sdp(header.substr(endh, header.length() - endh));

				std::tuple<uint32_t, uint16_t> values = extract_ip_and_port_from_sdp(sdp);

				uint32_t ipaddress = std::get<0>(values);
				uint16_t port = std::get<1>(values);

				if ((ipaddress > 0)and(port > 0)) {
					info->setState(SIP_CALL_ESTABLISHED);
					info->dst_addr.s_addr = ipaddress;
					info->dst_port = port;
				}
			}
		}
	} else if (info->getState() == SIP_FINISH_CALL) {
		info->setState(SIP_NONE);
	}
}

void SIPProtocol::handle_bye(SIPInfo *info, const boost::string_ref &header) {

	if (info->getState() == SIP_CALL_ESTABLISHED) {
		info->setState(SIP_FINISH_CALL);
	}
}

void SIPProtocol::processFlow(Flow *flow) {

	int32_t prev_total_byes = total_byes_;
	int32_t prev_total_invites = total_invites_;
	int32_t prev_total_resps = total_responses_;
	++total_packets_;	
	int length = flow->packet->getLength();
	total_bytes_ += length;
	++flow->total_packets_l7;

	SharedPointer<SIPInfo> info = flow->getSIPInfo();

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

	boost::string_ref header(reinterpret_cast <const char*> (flow->packet->getPayload()), length);

	extract_uri_value(info.get(),header);
	
	extract_via_value(info.get(),header);
		
	extract_from_value(info.get(),header);	

	extract_to_value(info.get(),header);

	/* A Small SIP transition states */
	if(total_invites_ > prev_total_invites) {
		handle_invite(info.get(), header);
	} else if (total_byes_ > prev_total_byes) {
		handle_bye(info.get(), header);
	} else if (total_responses_ > prev_total_resps) {
		handle_ok(info.get(), header);
	}
}


void SIPProtocol::increaseAllocatedMemory(int value) {

	info_cache_->create(value);
	uri_cache_->create(value);
	from_cache_->create(value);
	to_cache_->create(value);
	via_cache_->create(value);
}


void SIPProtocol::decreaseAllocatedMemory(int value) {

	info_cache_->destroy(value);
	uri_cache_->destroy(value);
	from_cache_->destroy(value);
	to_cache_->destroy(value);
	via_cache_->destroy(value);
}

void SIPProtocol::statistics(std::basic_ostream<char> &out, int level) {

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
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << "\n";
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << "\n";
			if (level > 3) { 
				out << "\t" << "Total requests:         " << std::setw(10) << total_requests_ << "\n";
				out << "\t" << "Total responses:        " << std::setw(10) << total_responses_ << "\n";
				out << "\t" << "SIP Methods" << "\n";
				out << "\t" << "Total registers:        " << std::setw(10) << total_registers_ << "\n";
				out << "\t" << "Total invites:          " << std::setw(10) << total_invites_ << "\n";
				out << "\t" << "Total acks:             " << std::setw(10) << total_acks_ << "\n";
				out << "\t" << "Total cancels:          " << std::setw(10) << total_cancels_ << "\n";
				out << "\t" << "Total byes:             " << std::setw(10) << total_byes_ << "\n";
				out << "\t" << "Total messages:         " << std::setw(10) << total_messages_ << "\n";
				out << "\t" << "Total options:          " << std::setw(10) << total_options_ << "\n";
				out << "\t" << "Total publishs:         " << std::setw(10) << total_publishs_ << "\n";
				out << "\t" << "Total subscribes:       " << std::setw(10) << total_subscribes_ << "\n";
				out << "\t" << "Total notifies:         " << std::setw(10) << total_notifies_ << "\n";
				out << "\t" << "Total refers:           " << std::setw(10) << total_refers_ << "\n";
				out << "\t" << "Total infos:            " << std::setw(10) << total_infos_ << "\n";
				out << "\t" << "Total pings:            " << std::setw(10) << total_pings_ << "\n";
				out << "\t" << "Total others:           " << std::setw(10) << total_sip_others_ << std::endl;
			}
			if (level > 2) {
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
				if (level > 3) {
					info_cache_->statistics(out);
					uri_cache_->statistics(out);
					via_cache_->statistics(out);
					from_cache_->statistics(out);
					to_cache_->statistics(out);
					if (level > 4) {
						showCacheMap(out, "\t", uri_map_, "SIP Uris", "Uri");
						showCacheMap(out, "\t", via_map_, "SIP Vias", "Via");
						showCacheMap(out, "\t", from_map_, "SIP Froms", "From");
						showCacheMap(out, "\t", to_map_, "SIP Tos", "To");
					}
				}
			}
		}
	}
}

CounterMap SIPProtocol::getCounters() const {
        CounterMap cm;

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
        cm.addKeyValue("requests", total_requests_);
        cm.addKeyValue("responses", total_requests_);
	cm.addKeyValue("registers", total_registers_);
	cm.addKeyValue("invites", total_invites_);
	cm.addKeyValue("acks", total_acks_);
	cm.addKeyValue("cancels", total_cancels_);
	cm.addKeyValue("byes", total_byes_);
	cm.addKeyValue("messages", total_messages_);
	cm.addKeyValue("options", total_options_);
	cm.addKeyValue("publishs", total_publishs_);
	cm.addKeyValue("subscribes", total_subscribes_);
	cm.addKeyValue("notifies", total_notifies_);
	cm.addKeyValue("refers", total_refers_);
	cm.addKeyValue("infos", total_infos_);
	cm.addKeyValue("pings", total_pings_);
        cm.addKeyValue("others", total_sip_others_);
        return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
#if defined(PYTHON_BINDING)
boost::python::dict SIPProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE SIPProtocol::getCache() const {
#endif
        return addMapToHash(uri_map_);
}

#if defined(PYTHON_BINDING)
void SIPProtocol::showCache(std::basic_ostream<char> &out) const {

	showCacheMap(out, "", uri_map_, "SIP Uris", "Uri");
}
#endif

#endif

} // namespace aiengine 
