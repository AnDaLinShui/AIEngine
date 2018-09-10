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
#include "POPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr POPProtocol::logger(log4cxx::Logger::getLogger("aiengine.pop"));
#endif

// List of support commands
std::vector<PopCommandType> POPProtocol::commands_ {
        std::make_tuple("STAT"          ,4,     "stats"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_STAT)),
        std::make_tuple("LIST"          ,4,     "lists"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_LIST)),
        std::make_tuple("RETR"          ,4,     "retrs"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_RETR)),
        std::make_tuple("DELE"          ,4,     "deletes"       ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_DELE)),
        std::make_tuple("NOOP"          ,4,     "noops"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_NOOP)),
        std::make_tuple("RSET"          ,4,     "resets"        ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_RSET)),
        std::make_tuple("TOP"           ,3,     "tops"          ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_TOP)),
        std::make_tuple("UIDL"          ,4,     "uidls"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_UIDL)),
        std::make_tuple("USER"          ,4,     "users"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_USER)),
        std::make_tuple("PASS"          ,4,     "passes"        ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_PASS)),
        std::make_tuple("APOP"          ,4,     "apops"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_APOP)),
        std::make_tuple("STLS"          ,4,     "stlss"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_STLS)),
        std::make_tuple("QUIT"          ,4,     "quits"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_QUIT))
};

POPProtocol::POPProtocol():
	Protocol("POPProtocol", "pop", IPPROTO_TCP),
	header_(nullptr),
	total_events_(0),
	total_allow_domains_(0),
	total_ban_domains_(0),
	total_pop_client_commands_(0),
	total_pop_server_responses_(0),
	domain_mng_(),
	ban_domain_mng_(),
	info_cache_(new Cache<POPInfo>("POP Info cache")),
	user_cache_(new Cache<StringCache>("Name cache")),
	user_map_(),
	flow_mng_(),
	current_flow_(nullptr),
	anomaly_() {}

POPProtocol::~POPProtocol() { 
	
	anomaly_.reset(); 
}

bool POPProtocol::popChecker(Packet &packet) {

        const uint8_t *payload = packet.getPayload();

        if ((payload[0] == '+')and(payload[1] == 'O')and(payload[2] == 'K')and
                (payload[3] == ' ')and(packet.getSourcePort() == 110)) {

		++total_valid_packets_;
		return true;
	} else {
		++total_invalid_packets_;
		return false;
	}
}

void POPProtocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);
	user_cache_->setDynamicAllocatedMemory(value);
}

bool POPProtocol::isDynamicAllocatedMemory() const {

	return info_cache_->isDynamicAllocatedMemory();	
}

int64_t POPProtocol::getCurrentUseMemory() const {

	int64_t mem = sizeof(POPProtocol);

	mem += info_cache_->getCurrentUseMemory();
	mem += user_cache_->getCurrentUseMemory();

	return mem;
}

int64_t POPProtocol::getAllocatedMemory() const {

	int64_t mem = sizeof(POPProtocol);

        mem += info_cache_->getAllocatedMemory();
        mem += user_cache_->getAllocatedMemory();

        return mem;
}

int64_t POPProtocol::getTotalAllocatedMemory() const {

        int64_t mem = getAllocatedMemory();

	mem += compute_memory_used_by_maps();

	return mem;
}

// Removes or decrements the hits of the maps.
/* LCOV_EXCL_START */
__attribute__ ((unused)) void POPProtocol::release_pop_info_cache(POPInfo *info) {

        SharedPointer<StringCache> user_ptr = info->user_name;

        if (user_ptr) { // There is no from attached
                GenericMapType::iterator it = user_map_.find(user_ptr->getName());
                if (it != user_map_.end()) {
                        int *hits = &(it->second).hits;
                        --(*hits);

                        if ((*hits) <= 0) {
                                user_map_.erase(it);
                        }
                }
        }

        release_pop_info(info);
}
/* LCOV_EXCL_STOP */


int32_t POPProtocol::release_pop_info(POPInfo *info) {

        int32_t bytes_released = 0;

	bytes_released = releaseStringToCache(user_cache_, info->user_name);

        info->resetStrings();

        return bytes_released;
}

int64_t POPProtocol::compute_memory_used_by_maps() const {

	int64_t bytes = user_map_.size() * sizeof(StringCacheHits);

	// Compute the size of the strings used as keys on the map
	std::for_each (user_map_.begin(), user_map_.end(), [&bytes] (PairStringCacheHits const &f) {
		bytes += f.first.size();
	});
	return bytes;
}

int32_t POPProtocol::getTotalCacheMisses() const {

	int32_t miss = 0;

	miss = info_cache_->getTotalFails();
	miss += user_cache_->getTotalFails();

	return miss;
}

void POPProtocol::releaseCache() {

	FlowManagerPtr fm = flow_mng_.lock();

	if (fm) {
		auto ft = fm->getFlowTable();

		std::ostringstream msg;
        	msg << "Releasing " << getName() << " cache";

		infoMessage(msg.str());

		int64_t total_bytes_released = compute_memory_used_by_maps();
		int64_t total_bytes_released_by_flows = 0;
		int32_t release_flows = 0;
                int32_t release_user = user_map_.size();

                for (auto &flow: ft) {
                       	SharedPointer<POPInfo> info = flow->getPOPInfo();
			if (info) {
				total_bytes_released_by_flows += release_pop_info(info.get());
                                total_bytes_released_by_flows += sizeof(info);
                              
                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(info);
                        }
                }
		user_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_user << " user names ," << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
	}
}

void POPProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getPOPInfo();
	if (info) {
		info_cache_->release(info);
	}
}

void POPProtocol::attach_user_name(POPInfo *info, const boost::string_ref &name) {

	if (!info->user_name) {
                GenericMapType::iterator it = user_map_.find(name);
                if (it == user_map_.end()) {
                        SharedPointer<StringCache> user_ptr = user_cache_->acquire();
                        if (user_ptr) {
                                user_ptr->setName(name.data(), name.length());
                                info->user_name = user_ptr;
                                user_map_.insert(std::make_pair(user_ptr->getName(), user_ptr));
                        }
                } else {
                        ++ (it->second).hits;
                        info->user_name = (it->second).sc;
                }
        }
}


void POPProtocol::handle_cmd_user(POPInfo *info, const boost::string_ref &header) {

	// The user could be a email address or just a string that identifies the mailbox
        size_t token = header.find_first_of("@");
        size_t end = header.find_first_of("\x0d\x0a");
	boost::string_ref user_name;
	boost::string_ref domain;

	if (token != std::string::npos) {
	
		if (end == std::string::npos) {	
			++total_events_;
                	if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        	current_flow_->setPacketAnomaly(PacketAnomalyType::POP_BOGUS_HEADER);
                	}
			anomaly_->incAnomaly(current_flow_, PacketAnomalyType::POP_BOGUS_HEADER);
			return;
		}

		user_name = header.substr(5, token - 5);
        	domain = header.substr(token + 1, end - token - 1);
	} else { // No domain
		user_name = header.substr(5, end - 5);
        	domain = user_name; // the domain is the user 
	}

	if (ban_domain_mng_) {
                auto dom_candidate = ban_domain_mng_->getDomainName(domain);
                if (dom_candidate) {
#ifdef HAVE_LIBLOG4CXX
                        LOG4CXX_INFO (logger, "Flow:" << *current_flow_ << " matchs with ban host " << dom_candidate->getName());
#endif
                        ++total_ban_domains_;
                        info->setIsBanned(true);
                        return;
                }
        }
        ++total_allow_domains_;

        attach_user_name(info, user_name);

	if (domain_mng_) {
                auto dom_candidate = domain_mng_->getDomainName(domain);
                if (dom_candidate) {
			++total_events_;
#if defined(BINDING)
#ifdef HAVE_LIBLOG4CXX
                        LOG4CXX_INFO (logger, "Flow:" << *current_flow_ << " matchs with " << dom_candidate->getName());
#endif
                        if (dom_candidate->call.haveCallback()) {
                                dom_candidate->call.executeCallback(current_flow_);
                        }
#endif
                }
        }
}

void POPProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;

	setHeader(flow->packet->getPayload());

        SharedPointer<POPInfo> info = flow->getPOPInfo();

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

        if (info->isBanned() == true) {
		// No need to process the POP pdu.
                return;
        }

	current_flow_ = flow;

	if (flow->getFlowDirection() == FlowDirection::FORWARD) {
		
                // Commands send by the client
                for (auto &command: commands_) {
                        const char *c = std::get<0>(command);
                        int offset = std::get<1>(command);

                        if (std::memcmp(c, &header_[0], offset) == 0) {
                                int32_t *hits = &std::get<3>(command);
                                int8_t cmd __attribute__((unused)) = std::get<4>(command);

                                ++(*hits);
                                ++total_pop_client_commands_;
				info->incClientCommands();	
                
				if ( cmd == static_cast<int8_t>(POPCommandTypes::POP_CMD_USER)) {
					boost::string_ref header(reinterpret_cast<const char*>(header_), length);
					handle_cmd_user(info.get(), header);
				} else if (cmd == static_cast<int8_t>(POPCommandTypes::POP_CMD_STLS)) {
					info->setStartTLS(true);

					// Force to write on the databaseAdaptor update method
                                        flow->packet->setForceAdaptorWrite(true);
				}
		                return;
                        }
                }
	} else {
		// Responses from the server
		++total_pop_server_responses_;
		info->incServerCommands();
		if (info->isStartTLS() and header_[0] == '+' and header_[1] == 'O' and header_[2] == 'K') {
                	// Release the attached POPInfo object
                        releaseFlowInfo(flow);
                        // Reset the number of l7 packets, check SSLProtocol.cc
                        flow->total_packets_l7 = 0;
                        // Reset the forwarder so the next time will be a SSL flow
                        flow->forwarder.reset();
		}
	}
	return;
} 

void POPProtocol::setDomainNameManager(const SharedPointer<DomainNameManager> &dm) {

	if (domain_mng_) {
		domain_mng_->setPluggedToName("");
	}
	if (dm) {
		domain_mng_ = dm;
		domain_mng_->setPluggedToName(getName());
	} else {
		domain_mng_.reset();
	}
}

void POPProtocol::statistics(std::basic_ostream<char> &out, int level) {

	if (level > 0) {
                int64_t alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";
		const char *dynamic_memory = (isDynamicAllocatedMemory() ? "yes":"no");

                unitConverter(alloc_memory, unit);

                out << getName() << "(" << this <<") statistics" << std::dec << std::endl;

                if (ban_domain_mng_) out << "\t" << "Plugged banned domains from:" << ban_domain_mng_->getName() << std::endl;
                if (domain_mng_) out << "\t" << "Plugged domains from:" << domain_mng_->getName() << std::endl;

		out << "\t" << "Dynamic memory alloc:   " << std::setw(10) << dynamic_memory << std::endl;
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << std::endl;	
        	out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << std::endl;
        	out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ << std::endl;
		if (level > 1) {
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << std::endl;
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << std::endl;	
                        if (level > 3) {
                                out << "\t" << "Total client commands:  " << std::setw(10) << total_pop_client_commands_ << "\n";
                                out << "\t" << "Total server responses: " << std::setw(10) << total_pop_server_responses_ << "\n";
                                for (auto &command: commands_) {
                                        const char *label = std::get<2>(command);
                                        int32_t hits = std::get<3>(command);
                                        out << "\t" << "Total " << label << ":" << std::right << std::setfill(' ') << std::setw(27 - strlen(label)) << hits << "\n";
                                }
				out.flush();
			}
			if (level > 2) {	
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
				if (level > 3) {
                                        info_cache_->statistics(out);
                                        user_cache_->statistics(out);
                                        if (level > 4) {
                                                showCacheMap(out, "\t", user_map_, "POP users", "Users");
                                        }
				}
			}
		}
	}
}

void POPProtocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
        user_cache_->create(value);
}

void POPProtocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
        user_cache_->destroy(value);
}

CounterMap POPProtocol::getCounters() const {
	CounterMap cm;

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
        cm.addKeyValue("commands", total_pop_client_commands_);
        cm.addKeyValue("responses", total_pop_server_responses_);

	return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
#if defined(PYTHON_BINDING)
boost::python::dict POPProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE POPProtocol::getCache() const {
#endif
        return addMapToHash(user_map_);
}

#if defined(PYTHON_BINDING)
void POPProtocol::showCache(std::basic_ostream<char> &out) const {

	showCacheMap(out, "", user_map_, "POP users", "Users");
}
#endif

#endif

} // namespace aiengine

