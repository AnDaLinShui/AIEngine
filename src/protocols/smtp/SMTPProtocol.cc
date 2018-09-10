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
#include "SMTPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr SMTPProtocol::logger(log4cxx::Logger::getLogger("aiengine.smtp"));
#endif

// List of support commands 
std::vector<SmtpCommandType> SMTPProtocol::commands_ {
        std::make_tuple("EHLO"      	,4,     "hellos"     	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_EHLO)),
        std::make_tuple("AUTH LOGIN"  	,10,    "auth logins"  	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_AUTH)),
        std::make_tuple("MAIL FROM:"    ,10,    "mail froms"	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_MAIL)),
        std::make_tuple("RCPT TO:"      ,8,     "rcpt tos"      ,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_RCPT)),
        std::make_tuple("DATA"       	,4,     "datas"       	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_DATA)),
        std::make_tuple("EXPN"         	,4,     "expandss"     	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_EXPN)),
        std::make_tuple("VRFY"        	,4,     "verifys"       ,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_VRFY)),
        std::make_tuple("RSET"         	,4,     "resets"        ,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_RSET)),
        std::make_tuple("HELP"         	,4,     "helps"        	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_HELP)),
        std::make_tuple("NOOP"         	,4,     "noops"        	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_NOOP)),	
        std::make_tuple("STARTTLS"    	,8,     "starttls"      ,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_STARTTLS)),	
        std::make_tuple("QUIT"         	,4,     "quits"        	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_QUIT))	
};

SMTPProtocol::SMTPProtocol():
	Protocol("SMTPProtocol", "smtp", IPPROTO_TCP),
	header_(nullptr),
	total_events_(0),
	total_allow_domains_(0),
	total_ban_domains_(0),
	total_smtp_client_commands_(0),
	total_smtp_server_responses_(0),
	domain_mng_(),
	ban_domain_mng_(),
	info_cache_(new Cache<SMTPInfo>("SMTP Info cache")),
	from_cache_(new Cache<StringCache>("From cache")),
	to_cache_(new Cache<StringCache>("To cache")),
	from_map_(),
	to_map_(),
	flow_mng_(),
	current_flow_(nullptr),
	anomaly_(),
	eval_() {}

SMTPProtocol::~SMTPProtocol() { 

	anomaly_.reset(); 
}

bool SMTPProtocol::smtpChecker(Packet &packet) {

	// The first message comes from the server and have code 220
	const uint8_t *payload = packet.getPayload();

	if ((payload[0] == '2')and(payload[1] == '2')and(payload[2] == '0')and
		((packet.getSourcePort() == 25) or
		(packet.getSourcePort() == 2525) or
		(packet.getSourcePort() == 587))) {

		++total_valid_packets_;
		return true;
	} else {
		++total_invalid_packets_;
		return false;
	}
}

void SMTPProtocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);	
	from_cache_->setDynamicAllocatedMemory(value);	
	to_cache_->setDynamicAllocatedMemory(value);	
}

bool SMTPProtocol::isDynamicAllocatedMemory() const {

	return info_cache_->isDynamicAllocatedMemory();
}

int64_t SMTPProtocol::getCurrentUseMemory() const {

	int64_t mem = sizeof(SMTPProtocol);

	mem += info_cache_->getCurrentUseMemory();
	mem += from_cache_->getCurrentUseMemory();
	mem += to_cache_->getCurrentUseMemory();

	return mem;
}

int64_t SMTPProtocol::getAllocatedMemory() const {

	int64_t mem = sizeof(SMTPProtocol);

        mem += info_cache_->getAllocatedMemory();
        mem += from_cache_->getAllocatedMemory();
        mem += to_cache_->getAllocatedMemory();

        return mem;
}

int64_t SMTPProtocol::getTotalAllocatedMemory() const {

        int64_t mem = getAllocatedMemory();

	mem += compute_memory_used_by_maps();

	return mem;
}

// Removes or decrements the hits of the maps.
/* LCOV_EXCL_START */
__attribute__ ((unused)) void SMTPProtocol::release_smtp_info_cache(SMTPInfo *info) {

        SharedPointer<StringCache> from_ptr = info->from;

        if (from_ptr) { // There is no from attached
                GenericMapType::iterator it = from_map_.find(from_ptr->getName());
                if (it != from_map_.end()) {
                        int *hits = &(it->second).hits;
                        --(*hits);

                        if ((*hits) <= 0) {
                                from_map_.erase(it);
                        }
                }
        }

        SharedPointer<StringCache> to_ptr = info->to;

        if (to_ptr) { // There is a to attached 
                GenericMapType::iterator it = to_map_.find(to_ptr->getName());
                if (it != to_map_.end()) {
                        int *hits = &(it->second).hits;
                        --(*hits);

                        if ((*hits) <= 0) {
                                to_map_.erase(it);
                        }
                }
        }

        release_smtp_info(info);
}
/* LCOV_EXCL_STOP */

int32_t SMTPProtocol::release_smtp_info(SMTPInfo *info) {

        int32_t bytes_released = 0;

	bytes_released = releaseStringToCache(from_cache_, info->from);
	bytes_released += releaseStringToCache(to_cache_, info->to);

        info->resetStrings();

        return bytes_released;
}

int64_t SMTPProtocol::compute_memory_used_by_maps() const {

	int64_t bytes = (from_map_.size() + to_map_.size()) * sizeof(StringCacheHits);

	// Compute the size of the strings used as keys on the map
	std::for_each (from_map_.begin(), from_map_.end(), [&bytes] (PairStringCacheHits const &f) {
		bytes += f.first.size();
	});
	std::for_each (to_map_.begin(), to_map_.end(), [&bytes] (PairStringCacheHits const &t) {
		bytes += t.first.size();
	});
	return bytes;
}

int32_t SMTPProtocol::getTotalCacheMisses() const {

	int32_t miss = 0;

	miss = info_cache_->getTotalFails();
	miss += from_cache_->getTotalFails();
	miss += to_cache_->getTotalFails();
	
	return miss;
}

void SMTPProtocol::releaseCache() {

	FlowManagerPtr fm = flow_mng_.lock();

	if (fm) {
		auto ft = fm->getFlowTable();

		std::ostringstream msg;
        	msg << "Releasing " << getName() << " cache";

		infoMessage(msg.str());

		int64_t total_bytes_released = compute_memory_used_by_maps();
		int64_t total_bytes_released_by_flows = 0;
		int32_t release_flows = 0;
		int32_t release_froms = from_map_.size();
		int32_t release_tos = to_map_.size();

                for (auto &flow: ft) {
                    	SharedPointer<SMTPInfo> info = flow->getSMTPInfo();
			if (info) {
                                total_bytes_released_by_flows += release_smtp_info(info.get());
                                total_bytes_released_by_flows += sizeof(info);
                               
                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(info);
                        }
                }
                from_map_.clear();
                to_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_froms;
                msg << " froms, " << release_tos << " tos, " << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
	}
}

void SMTPProtocol::releaseFlowInfo(Flow *flow) {

      	SharedPointer<SMTPInfo> info = flow->getSMTPInfo();
	if (info) {
		info_cache_->release(info);
	} 
}

void SMTPProtocol::attach_from(SMTPInfo *info, const boost::string_ref &from) {

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

void SMTPProtocol::handle_cmd_mail(SMTPInfo *info, const boost::string_ref &header) {

	SharedPointer<StringCache> from_ptr = info->from;

	size_t start = strlen("MAIL FROM:");
	size_t end = header.length() - 2;

	if (end - start >= MaxSMTPEmailLength) { 
		++total_events_;
                if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        current_flow_->setPacketAnomaly(PacketAnomalyType::SMTP_LONG_EMAIL);
                }
		anomaly_->incAnomaly(current_flow_, PacketAnomalyType::SMTP_LONG_EMAIL);
		return;
	}

	if (header[start + 1] == '<') ++start;
	if (header[end - 1] == '>') --end;

	boost::string_ref from(header.substr(start + 1, end - start - 1));

	size_t token = from.find_first_of("@");

	if (token > from.length()) {
		++total_events_;
                if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        current_flow_->setPacketAnomaly(PacketAnomalyType::SMTP_BOGUS_HEADER);
                }
		anomaly_->incAnomaly(current_flow_, PacketAnomalyType::SMTP_BOGUS_HEADER);
		return;
	}
	boost::string_ref domain(from.substr(token + 1, from.size()));

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

	attach_from(info, from);

	if (domain_mng_) {
        	auto dom_candidate = domain_mng_->getDomainName(domain);
                if (dom_candidate) {
			++total_events_;
			info->matched_domain_name = dom_candidate;
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

void SMTPProtocol::handle_cmd_rcpt(SMTPInfo *info, const boost::string_ref &header) {

	if (!info->to) {
        	size_t start = strlen("RCPT TO:"); 
        	size_t end = header.length() - 2;

        	if (end - start >= MaxSMTPEmailLength) {
                	++total_events_;
                	if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        	current_flow_->setPacketAnomaly(PacketAnomalyType::SMTP_LONG_EMAIL);
                	}
                	anomaly_->incAnomaly(current_flow_, PacketAnomalyType::SMTP_LONG_EMAIL);
                	return;
        	}

		if (header[start + 1] == '<') ++start;
		if (header[end - 1] == '>') --end;

		boost::string_ref to(header.substr(start + 1, end - start - 1));

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

void SMTPProtocol::process_payloadl7(Flow * flow, SMTPInfo *info, const boost::string_ref &payloadl7) {

        // The Flow have attached a mached DomainName
        if (info->matched_domain_name) {

                if (info->matched_domain_name->haveRegexManager()) {
                        if (!flow->regex_mng) {
                                flow->regex_mng = info->matched_domain_name->getRegexManager();
                        }
                }

                eval_.processFlowPayloadLayer7(flow, payloadl7);
        }
}

void SMTPProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	const uint8_t *payload = flow->packet->getPayload();
	total_bytes_ += length;
	++total_packets_;

	setHeader(payload);

       	SharedPointer<SMTPInfo> info = flow->getSMTPInfo();

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
		// No need to process the SMTP pdu.
                return;
        }

	current_flow_ = flow;

	if (flow->getFlowDirection() == FlowDirection::FORWARD) {
	
		if (info->isData()) { // The client is transfering the email
                        boost::string_ref payloadl7(reinterpret_cast<const char*>(payload), length);

			info->incTotalDataBytes(length); /* Update the bytes */

                        process_payloadl7(flow, info.get(), payloadl7);

			// Check if is the last data block
			int offset = length - 7;
			if (offset > 0) {
				if (std::memcmp(&payload[offset], "\x0d\x0a\x0d\x0a\x2e\x0d\x0a", 7) == 0) {
					info->incTotalDataBlocks();
					info->setIsData(false);
				}
			}	
		} else { // Commands send by the client
        		for (auto &command: commands_) {
                		const char *c = std::get<0>(command);
                		int offset = std::get<1>(command);

                		if (std::memcmp(c, &header_[0], offset) == 0) {
                        		int32_t *hits = &std::get<3>(command);
					int8_t cmd = std::get<4>(command);

                        		++(*hits);
					++total_smtp_client_commands_;

					// Check if the commands are MAIL or RCPT
					if ( cmd == static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_MAIL)) {
						boost::string_ref header(reinterpret_cast<const char*>(header_), length);
						handle_cmd_mail(info.get(), header);
					} else if ( cmd == static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_RCPT)) {
						boost::string_ref header(reinterpret_cast<const char*>(header_), length);
						handle_cmd_rcpt(info.get(), header);
					} else if ( cmd == static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_DATA)) {
						info->setIsData(true);
					} else if ( cmd == static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_STARTTLS)) {
						info->setStartTLS(true);
						// Force to write on the databaseAdaptor update method
                				flow->packet->setForceAdaptorWrite(true);
					}
					info->setCommand(cmd);
                        		return;
                		}
        		}
		}
	} else {
		// Responses from the server
        	try {
			const char *header = reinterpret_cast<const char*>(header_);
			std::string value(header, 3);

                	int code = std::stoi(value);
			
			++total_smtp_server_responses_;

			// The server agrees to start a SSL session for this Flow
			if ((info->isStartTLS()) and (code == 220)) {
				// Release the attached SMTPInfo object
				releaseFlowInfo(flow);
				// Reset the number of l7 packets, check SSLProtocol.cc
				flow->total_packets_l7 = 0;
				// Reset the forwarder so the next time will be a SSL flow
				flow->forwarder.reset();
			}
        	} catch(std::invalid_argument&) { //or catch(...) to catch all exceptions
                	// We dont really do nothing here with code;
        	}
	}
	
	return;
} 

void SMTPProtocol::setDomainNameManager(const SharedPointer<DomainNameManager> &dm) {

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

void SMTPProtocol::statistics(std::basic_ostream<char> &out, int level) {

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
                                out << "\t" << "Total allow domains:    " << std::setw(10) << total_allow_domains_ << std::endl;
                                out << "\t" << "Total banned domains:   " << std::setw(10) << total_ban_domains_ << std::endl;
                                out << "\t" << "Total client commands:  " << std::setw(10) << total_smtp_client_commands_ << std::endl;
                                out << "\t" << "Total server responses: " << std::setw(10) << total_smtp_server_responses_ << std::endl;

                                for (auto &command: commands_) {
                                        const char *label = std::get<2>(command);
                                        int32_t hits = std::get<3>(command);
                                        out << "\t" << "Total " << label << ":" << std::right << std::setfill(' ') << std::setw(27 - strlen(label)) << hits << std::endl;
                                }
                        }
	
			if (level > 2) {	
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
                                if (level > 3) {
                                        info_cache_->statistics(out);
                                        from_cache_->statistics(out);
                                        to_cache_->statistics(out);
                                        if (level > 4) {
                                                showCacheMap(out, "\t", from_map_, "SMTP Froms", "From");
                                                showCacheMap(out, "\t", to_map_, "SMTP Tos", "To");
                                        }
                                }
			}
		}
	}
}

void SMTPProtocol::increaseAllocatedMemory(int value) { 

	info_cache_->create(value);
	from_cache_->create(value);
	to_cache_->create(value);
}

void SMTPProtocol::decreaseAllocatedMemory(int value) { 

	info_cache_->destroy(value);
	from_cache_->destroy(value);
	to_cache_->destroy(value);
}

CounterMap SMTPProtocol::getCounters() const { 
	CounterMap cm;

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
        cm.addKeyValue("commands", total_smtp_client_commands_);
        cm.addKeyValue("responses", total_smtp_server_responses_);

        for (auto &command: commands_) {
                const char *label = std::get<2>(command);

                cm.addKeyValue(label, std::get<3>(command));
        }
        return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
#if defined(PYTHON_BINDING)
boost::python::dict SMTPProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE SMTPProtocol::getCache() const {
#endif
        return addMapToHash(from_map_);
}

#if defined(PYTHON_BINDING)
void SMTPProtocol::showCache(std::basic_ostream<char> &out) const {
	
	showCacheMap(out, "", from_map_, "SMTP Froms", "From");
}
#endif

#endif

} // namespace aiengine

