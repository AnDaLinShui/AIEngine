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
#include "IMAPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr IMAPProtocol::logger(log4cxx::Logger::getLogger("aiengine.imap"));
#endif

// List of support command from the client
std::vector<ImapCommandType> IMAPProtocol::commands_ {
        std::make_tuple("CAPABILITY"    ,10,    "capabilities"  ,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_CAPABILITY)),
        std::make_tuple("STARTTLS"      ,8,     "starttls"      ,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_STARTTLS)),
        std::make_tuple("AUTHENTICATE"  ,12,    "authenticates" ,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_AUTHENTICATE)),
        std::make_tuple("UID"           ,3,     "uids"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_UID)),
        std::make_tuple("LOGIN"      	,5,     "logins"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_LOGIN)),
        std::make_tuple("SELECT"      	,6,     "selects"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_SELECT)),
        std::make_tuple("EXAMINE"      	,7,     "examines"      ,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_EXAMINE)),
        std::make_tuple("CREATE"      	,6,     "createss"      ,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_CREATE)),
        std::make_tuple("DELETE"      	,6,     "deletes"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_DELETE)),
        std::make_tuple("RENAME"      	,6,     "renames"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_RENAME)),
	std::make_tuple("SUBSCRIBE"    	,9,     "subscribes"   	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_SUBSCRIBE)),
        std::make_tuple("UNSUBSCRIBE"  	,11,    "unsubscribes" 	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_UNSUBSCRIBE)),
        std::make_tuple("LIST"      	,4,     "lists"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_LIST)),
        std::make_tuple("LSUB"      	,4,     "lsub"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_LSUB)),
        std::make_tuple("STATUS"      	,6,     "status"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_STATUS)),
        std::make_tuple("APPEND"      	,6,     "appends"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_APPEND)),
        std::make_tuple("CHECK"      	,5,     "checks"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_CHECK)),
        std::make_tuple("CLOSE"      	,5,     "closes"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_CLOSE)),
	std::make_tuple("EXPUNGE"      	,7,     "expunges"     	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_EXPUNGE)),
	std::make_tuple("SEARCH"      	,6,     "searches"     	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_SEARCH)),
	std::make_tuple("FETCH"      	,5,     "fetchs"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_FETCH)),
	std::make_tuple("STORE"      	,5,     "stores"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_STORE)),
	std::make_tuple("COPY"      	,4,     "copies"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_COPY)),
	std::make_tuple("NOOP"      	,4,     "noops"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_NOOP)),
	std::make_tuple("LOGOUT"      	,6,     "logouts"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_LOGOUT))
};

IMAPProtocol::IMAPProtocol():
	Protocol("IMAPProtocol", "imap", IPPROTO_TCP),
	header_(nullptr),
	total_events_(0),
	total_allow_domains_(0),
	total_ban_domains_(0),
	total_imap_client_commands_(0),
	total_imap_server_responses_(0),
	domain_mng_(),ban_domain_mng_(),
	info_cache_(new Cache<IMAPInfo>("IMAP Info cache")),
	user_cache_(new Cache<StringCache>("Name cache")),
	user_map_(),
	flow_mng_(),
	current_flow_(nullptr),
	anomaly_() {}

IMAPProtocol::~IMAPProtocol() { 

	anomaly_.reset(); 
}

bool IMAPProtocol::imapChecker(Packet &packet) {

	const uint8_t *payload = packet.getPayload();

	if ((payload[0] == '*')and(payload[1] == ' ')and(payload[2] == 'O')and
		(payload[3] == 'K')and(payload[4] == ' ')and
		(packet.getSourcePort() == 143)) {

		++total_valid_packets_;
		return true;
	} else {
		++total_invalid_packets_;
		return false;
	}
}

void IMAPProtocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);
	user_cache_->setDynamicAllocatedMemory(value);
}

bool IMAPProtocol::isDynamicAllocatedMemory() const {

	return info_cache_->isDynamicAllocatedMemory();
}

int64_t IMAPProtocol::getCurrentUseMemory() const {

        int64_t mem = sizeof(IMAPProtocol);

        mem += info_cache_->getCurrentUseMemory();
        mem += user_cache_->getCurrentUseMemory();

        return mem;
}

int64_t IMAPProtocol::getAllocatedMemory() const {

        int64_t mem = sizeof(IMAPProtocol);

        mem += info_cache_->getAllocatedMemory();
        mem += user_cache_->getAllocatedMemory();

        return mem;
}

int64_t IMAPProtocol::getTotalAllocatedMemory() const {

        int64_t mem = getAllocatedMemory();

	mem += compute_memory_used_by_maps();

	return mem;
}

// Removes or decrements the hits of the maps.
/* LCOV_EXCL_START */
__attribute__((unused)) void IMAPProtocol::release_imap_info_cache(IMAPInfo *info) {

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
        release_imap_info(info);
}
/* LCOV_EXCL_STOP */

int32_t IMAPProtocol::release_imap_info(IMAPInfo *info) {

        int32_t bytes_released = 0;

	bytes_released = releaseStringToCache(user_cache_, info->user_name);

        return bytes_released;
}

int64_t IMAPProtocol::compute_memory_used_by_maps() const {

	int64_t bytes = user_map_.size() * sizeof(StringCacheHits);

	// Compute the size of the strings used as keys on the map
	std::for_each (user_map_.begin(), user_map_.end(), [&bytes] (PairStringCacheHits const &f) {
		bytes += f.first.size();
	});
	return bytes;
}

int32_t IMAPProtocol::getTotalCacheMisses() const {

	int32_t miss = 0;

	miss = info_cache_->getTotalFails();
	miss += user_cache_->getTotalFails();

	return miss;
}

void IMAPProtocol::setDomainNameManager(const SharedPointer<DomainNameManager> &dm) {

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

void IMAPProtocol::releaseCache() {

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
                       	SharedPointer<IMAPInfo> info = flow->getIMAPInfo();
			if (info) {
				total_bytes_released_by_flows = release_imap_info(info.get()); 
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
                msg << "Release " << release_user << " user names, " << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
	}
}

void IMAPProtocol::releaseFlowInfo(Flow *flow) {

     	auto info = flow->getIMAPInfo();
	if (info) {
                info_cache_->release(info);
	}
}

void IMAPProtocol::attach_user_name(IMAPInfo *info, const boost::string_ref &name) {

	if (!info->user_name) {
                GenericMapType::iterator it = user_map_.find(name);
                if (it == user_map_.end()) {
                        SharedPointer<StringCache> user_ptr = user_cache_->acquire();
                        if (user_ptr) {
                                user_ptr->setName(name.data(),name.length());
                                info->user_name = user_ptr;
                                user_map_.insert(std::make_pair(user_ptr->getName(), user_ptr));
                        }
                } else {
                        ++ (it->second).hits;
                        info->user_name = (it->second).sc;
                }
        }
}

void IMAPProtocol::handle_cmd_login(IMAPInfo *info, const boost::string_ref &header) {

	boost::string_ref domain;
	boost::string_ref user_name;

        size_t token = header.find("@");
   	size_t end = header.find(" "); 

	if (end < header.length()) {
		domain = header.substr(0, end);
		user_name = header.substr(0, end);
	} else {
		++total_events_;
	       	if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        current_flow_->setPacketAnomaly(PacketAnomalyType::IMAP_BOGUS_HEADER);
                }
		anomaly_->incAnomaly(PacketAnomalyType::IMAP_BOGUS_HEADER);
		return;
	}

	if (token < header.length()) {
		// The name have the domain
		if (end < header.length()) {
			domain = header.substr(token + 1, end - token - 1);
		}	
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


void IMAPProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;

	setHeader(flow->packet->getPayload());
	current_flow_ = flow;

        SharedPointer<IMAPInfo> info = flow->getIMAPInfo();
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
		// No need to process the IMAP pdu.
                return;
        }

	boost::string_ref header(reinterpret_cast<const char*>(header_), length);

	if (flow->getFlowDirection() == FlowDirection::FORWARD) {
		// bypass the tag
		boost::string_ref client_cmd(header);
		size_t endtag = client_cmd.find(" ");
		
		client_cmd = client_cmd.substr(endtag + 1, length - (endtag));

                // Commands send by the client
                for (auto &command: commands_) {
                        const char *c = std::get<0>(command);
                        int offset = std::get<1>(command);

                        if (std::memcmp(c, client_cmd.data(), offset) == 0) {
                                int32_t *hits = &std::get<3>(command);
                                int8_t cmd = std::get<4>(command);

                                ++(*hits);
                                ++total_imap_client_commands_;

				if (cmd == static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_LOGIN)) {
					int cmdoff = offset + endtag + 2;
                                        boost::string_ref header_cmd(header.substr(cmdoff, length - cmdoff));
                                        handle_cmd_login(info.get(), header_cmd);
                                } else if (cmd == static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_STARTTLS)) {
					info->setStartTLS(true);
					// Force to write on the databaseAdaptor update method
                                        flow->packet->setForceAdaptorWrite(true);
				}
				info->incClientCommands();	
                                return;
                        }
                }
	} else {
		++total_imap_server_responses_;
		info->incServerCommands();
		// Responses from the server

		// bypass the tag
		boost::string_ref server_cmd(header);
		size_t endtag = server_cmd.find(" ");
		
		server_cmd = server_cmd.substr(endtag + 1, length - (endtag));

		if (info->isStartTLS() and server_cmd[0] == 'O' and server_cmd[1] == 'K') {
                        // Release the attached IMAPInfo object
			releaseFlowInfo(flow);
                        // Reset the number of l7 packets, check SSLProtocol.cc
                        flow->total_packets_l7 = 0;
                        // Reset the forwarder so the next time will be a SSL flow
                        flow->forwarder.reset();
		}
	}
	return;
} 

void IMAPProtocol::statistics(std::basic_ostream<char> &out, int level) {

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
                                out << "\t" << "Total client commands:  " << std::setw(10) << total_imap_client_commands_ << "\n";
                                out << "\t" << "Total server responses: " << std::setw(10) << total_imap_server_responses_ << "\n";

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
                                                showCacheMap(out, "\t", user_map_, "IMAP Users", "User");
                                        }
				}
			}
		}
	}
}

void IMAPProtocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
        user_cache_->create(value);
}

void IMAPProtocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
        user_cache_->destroy(value);
}

CounterMap IMAPProtocol::getCounters() const {
	CounterMap cm;

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
        cm.addKeyValue("commands", total_imap_client_commands_);
        cm.addKeyValue("responses", total_imap_server_responses_);

        for (auto &command: commands_) {
                const char *label = std::get<2>(command);

		cm.addKeyValue(label, std::get<3>(command));
        }

	return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
#if defined(PYTHON_BINDING)
boost::python::dict IMAPProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE IMAPProtocol::getCache() const {
#endif
        return addMapToHash(user_map_);
}

#if defined(PYTHON_BINDING)
void IMAPProtocol::showCache(std::basic_ostream<char> &out) const {

	showCacheMap(out, "", user_map_,"IMAP Users","User");
}
#endif

#endif

} // namespace aiengine

