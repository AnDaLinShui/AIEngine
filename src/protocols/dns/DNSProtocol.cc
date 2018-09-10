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
#include "DNSProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr DNSProtocol::logger(log4cxx::Logger::getLogger("aiengine.dns"));
#endif

DNSProtocol::DNSProtocol():
	Protocol("DNSProtocol", "dns", IPPROTO_UDP),
	header_(nullptr),
	total_allow_queries_(0),
	total_ban_queries_(0),
	total_queries_(0),
	total_responses_(0),
	total_events_(0),
	total_dns_type_a_(0),
	total_dns_type_ns_(0),
	total_dns_type_cname_(0),
	total_dns_type_soa_(0),
	total_dns_type_ptr_(0),
	total_dns_type_mx_(0),
	total_dns_type_txt_(0),
	total_dns_type_aaaa_(0),
	total_dns_type_loc_(0),
	total_dns_type_srv_(0),
	total_dns_type_ds_(0),
	total_dns_type_sshfp_(0),
	total_dns_type_dnskey_(0),
	total_dns_type_ixfr_(0),
	total_dns_type_any_(0),
	total_dns_type_others_(0),
	current_length_(0),
	current_offset_(0),
	info_cache_(new Cache<DNSInfo>("DNS Info cache")),
	name_cache_(new Cache<StringCache>("Name cache")),
	domain_map_(),
	domain_mng_(),ban_domain_mng_(),
	flow_mng_(),
	current_flow_(nullptr),
        anomaly_() {}

DNSProtocol::~DNSProtocol() { 

	anomaly_.reset(); 
}

bool DNSProtocol::dnsChecker(Packet &packet) {

	// I dont like this idea of ports but...
	if (((packet.getSourcePort() == 53)||(packet.getDestinationPort() == 53))
		or((packet.getSourcePort() == 5353)||(packet.getDestinationPort() == 5353))) {
		if (packet.getLength() >= header_size) {
			setHeader(packet.getPayload());

			uint16_t questions = ntohs(header_->questions);
			if ((questions > 0)and(questions < 32)) { // Never see a query with no question, examples? 
				++total_valid_packets_;
				return true;
			}
		}
	}
	++total_invalid_packets_;
	return false;
}

void DNSProtocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);
	name_cache_->setDynamicAllocatedMemory(value);
}

bool DNSProtocol::isDynamicAllocatedMemory() const {

	return info_cache_->isDynamicAllocatedMemory();
}

int64_t DNSProtocol::getCurrentUseMemory() const {

        int64_t mem = sizeof(DNSProtocol);

        mem += info_cache_->getCurrentUseMemory();
        mem += name_cache_->getCurrentUseMemory();

        return mem;
}

int64_t DNSProtocol::getAllocatedMemory() const {

        int64_t mem = sizeof(DNSProtocol);

        mem += name_cache_->getAllocatedMemory();
        mem += info_cache_->getAllocatedMemory();

        return mem;
}

int64_t DNSProtocol::getTotalAllocatedMemory() const {

        int64_t mem = getAllocatedMemory();

        mem += compute_memory_used_by_maps();
	
	return mem;
}

int64_t DNSProtocol::compute_memory_used_by_maps() const {

	int64_t bytes = domain_map_.size() * sizeof(StringCacheHits);
	// Compute the size of the strings used as keys on the map
	std::for_each (domain_map_.begin(), domain_map_.end(), [&bytes] (PairStringCacheHits const &dt) {
		bytes += dt.first.size();
	});
	return bytes;
}

int32_t DNSProtocol::getTotalCacheMisses() const {

	int32_t miss = 0;

	miss = info_cache_->getTotalFails();
	miss += name_cache_->getTotalFails();

	return miss;
}

void DNSProtocol::releaseCache() {

	FlowManagerPtr fm = flow_mng_.lock();

	if (fm) {
		auto ft = fm->getFlowTable();

		std::ostringstream msg;
        	msg << "Releasing " << getName() << " cache";

		infoMessage(msg.str());

		int64_t total_bytes_released = compute_memory_used_by_maps();
		int64_t total_bytes_released_by_flows = 0;
		int32_t release_flows = 0;
		int32_t release_doms = domain_map_.size();

		for (auto &flow: ft) {
			SharedPointer<DNSInfo> info = flow->getDNSInfo();
			if (info) {
				total_bytes_released_by_flows += releaseStringToCache(name_cache_, info->name);
				total_bytes_released_by_flows += sizeof(info);
			
				++release_flows;
				flow->layer7info.reset();
				info_cache_->release(info);
			}
		} 
		domain_map_.clear();

		double cache_compression_rate = 0;

		if (total_bytes_released_by_flows > 0 ) {
			cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);	
		}

		msg.str("");
		msg << "Release " << release_doms << " domains, " << release_flows << " flows";
		msg << ", " << total_bytes_released + total_bytes_released_by_flows << " bytes";
		msg << ", compression rate " << cache_compression_rate << "%";	
		infoMessage(msg.str());
	}
}

void DNSProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getDNSInfo();
	if (info) {
		info_cache_->release(info);
	}
}
 
void DNSProtocol::attach_dns_to_flow(DNSInfo *info, boost::string_ref &domain, uint16_t qtype) {

	SharedPointer<StringCache> name = info->name;

	// Check if the domain is cache to attach
	GenericMapType::iterator it = domain_map_.find(domain);
        if (it == domain_map_.end()) {
              	name = name_cache_->acquire();
                if (name) {
                       	name->setName(domain.data(), domain.length());
			info->setQueryType(qtype);
                        info->name = name;
                        domain_map_.insert(std::make_pair(name->getName(), name));
                }
	} else {
		++ (it->second).hits;
		info->name = (it->second).sc;
	}
}

void DNSProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;

	current_flow_ = flow;
	current_length_ = length;
	current_offset_ = 0;

	if (length >= header_size) { // Minimum header size consider
		setHeader(flow->packet->getPayload());

        	SharedPointer<DNSInfo> info = flow->getDNSInfo();
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
                	return;
        	}
		current_offset_ += header_size;

		if (header_->qr == 0) { // Query
			++total_queries_;
			if (ntohs(header_->questions) > 0) {
				handle_standard_query(info.get(), length - header_size);
			}
		} else { // Responses
			++total_responses_; 
			if (ntohs(header_->answers) > 0) {
				handle_standard_response(info.get(), length - header_size);
			}
		}
	} else {
		++total_events_;
               	if (flow->getPacketAnomaly() == PacketAnomalyType::NONE) {
               		flow->setPacketAnomaly(PacketAnomalyType::DNS_BOGUS_HEADER);
		}
                anomaly_->incAnomaly(PacketAnomalyType::DNS_BOGUS_HEADER);
	}
	return;
} 

int DNSProtocol::parse_query_name(Flow *flow, int length) {

	int offset = extract_domain_name(&header_->data[0], length);

	if (offset >= MAX_DNS_BUFFER_NAME) {
		++total_events_;
        	if (flow->getPacketAnomaly() == PacketAnomalyType::NONE) {
                	flow->setPacketAnomaly(PacketAnomalyType::DNS_LONG_NAME);
                }
                anomaly_->incAnomaly(PacketAnomalyType::DNS_LONG_NAME);
	}
	return offset;
}

// INFO: http://www.tcpipguide.com/free/t_DNSNameNotationandMessageCompressionTechnique.htm
int DNSProtocol::extract_domain_name(const uint8_t *ptr, int length) {
        int offset = 1;
        int8_t next = (int8_t)ptr[0];
	int max_length = MAX_DNS_BUFFER_NAME - 1;

	if (length < max_length)
		max_length = length;

	dns_buffer_name_[0] = '0';

	while ((offset < max_length) and (next > 0)) {
		if (next + offset < max_length) {
			std::memcpy(&dns_buffer_name_[offset - 1], &ptr[offset], next);
			offset += next + 1;
			next = (int8_t)ptr[offset - 1];
			if (next > 0 ) {
				dns_buffer_name_[offset - 2] = '.';
			}
		} else { // There is buffer for copy but the name is too long
			int left = max_length - offset;

			std::memcpy(&dns_buffer_name_[offset - 1], &ptr[offset], left + 1);
			offset = max_length + 2;
			break;
		}
	}

	if (offset > 1)
	    	-- offset;

	return offset;
}

bool DNSProtocol::parse_response_answer(DNSInfo *info, const uint8_t *ptr, int answers) {

        // Extract the IP addresses or CNAME and store on the DNSDomain just when the domain have been matched
        for (int i = 0; i < answers; ++i) {
		int off = 0;
		if ((ptr[0] & 0xC0) == 0) { // is not a pointer
			off = (int)ptr[0] + 1;
		}
		const dns_common_resource_record *ans = reinterpret_cast <const dns_common_resource_record*> (&ptr[off]);
		uint16_t block_length = ntohs(ans->length);
                uint16_t type = ntohs(ans->type);
                uint16_t class_type = ntohs(ans->class_type);

		current_offset_ += sizeof(dns_common_resource_record);

		if (block_length > (current_length_ - current_offset_)) {
			// The block have more length than the packet
			return true;
		}

		if (class_type == 0x0001) { // class IN 
                        if ((type == 0x0001)and(block_length == 4)) { // IPv4
                                uint32_t ipv4addr =  ((ans->data[3] << 24) + (ans->data[2] << 16) + (ans->data[1] << 8) + ans->data[0]);
                                in_addr a;

                                a.s_addr = ipv4addr;
                                info->addIPAddress(inet_ntoa(a));
                        } else if ((type == 0x001C)and(block_length == 16)) { // IPv6
                                char ipv6addr[INET6_ADDRSTRLEN];
                                in6_addr *in6addr = (in6_addr*)&(ans->data[0]);

                                inet_ntop(AF_INET6, in6addr, ipv6addr, INET6_ADDRSTRLEN);

                                info->addIPAddress(ipv6addr);
                        } else if (type == 0x0005) { // CNAME
                                int value __attribute__((unused)) = extract_domain_name(&ans->data[0], block_length);

                                info->addName(&dns_buffer_name_[0]);
                        } else if (type == 0x0010) { // TXT record
				const dns_txt_record *txt = reinterpret_cast<const dns_txt_record*>(&ans->data[0]);
				char *data = (char*)&txt->data[0];
				
				if (txt->length < block_length) {	

					// Increment the current offset
					current_offset_ += txt->length;
	
					if (block_length == txt->length + 1) { // there is only one txt
						boost::string_ref txt_record(data, (int)txt->length);

						info->addName(txt_record.data(), txt_record.length());
					} else { // there is a txt record split in more, just process one more
						std::string temp_data(data, (int)txt->length);// copy the first block

						// Points to the second txt data record
						txt = reinterpret_cast<const dns_txt_record*>(&ans->data[txt->length + 1]);
						data = (char*)&txt->data[0];	
						
						// Verify that is not corrupted
						if (txt->length > (current_length_ - current_offset_)) {
							return true;
						}
						temp_data.append(data, (int)txt->length);
						info->addName(temp_data.c_str());
					}
				}
			}
		}
                // TODO: Check offset size lengths and possible anomalies       
                ptr = &(ans->data[block_length]);
        }
	return false; 
}

void DNSProtocol::handle_standard_query(DNSInfo *info, int length) {
	boost::string_ref domain;
	int offset = parse_query_name(current_flow_, length); 
	
	boost::string_ref dns_name(dns_buffer_name_, offset);

	if (offset == 1) { // There is no name, a root record
		offset = 0;
		domain = "<Root>";
	} else {
		domain = dns_name.substr(0, offset - 1);
	}

#ifdef DEBUG
	std::cout << __FILE__ << ":" << __func__ << ":length:" << length << " name:" << domain << " offset:" << offset << std::endl;
#endif

	// Check if the payload is malformed
	// The offset + 4 is because at the end of the domain 4 bytes should be present
	if (offset + 4 > length) {
		++total_events_;
               	if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
               		current_flow_->setPacketAnomaly(PacketAnomalyType::DNS_BOGUS_HEADER);
		}
               	anomaly_->incAnomaly(current_flow_, PacketAnomalyType::DNS_BOGUS_HEADER);
		return;
	}

	uint16_t qtype = ntohs((header_->data[offset + 2] << 8) + header_->data[offset + 1]);

	update_query_types(qtype);

	if (domain.length() > 0) { // The domain is valid
		if (ban_domain_mng_) {
			auto domain_candidate = ban_domain_mng_->getDomainName(domain);
			if (domain_candidate) {
#ifdef HAVE_LIBLOG4CXX
				LOG4CXX_INFO (logger, "Flow:" << *current_flow_ << " matchs with banned domain " << domain_candidate->getName());
#endif
				info->setIsBanned(true);	
				++total_ban_queries_;
				return;
			}
		}

		++total_allow_queries_;
		
		attach_dns_to_flow(info, domain, qtype);	
	}
}

void DNSProtocol::handle_standard_response(DNSInfo *info, int length) {
	boost::string_ref domain;

       	int offset = parse_query_name(current_flow_, length);

#ifdef DEBUG
	std::cout << __FILE__ << ":" << __func__ << ":no name attached, length:" << length << " offset:" << offset << std::endl;
#endif
       	SharedPointer<StringCache> name = info->name;
       	if (!name) {
        	// Check if the payload is malformed
        	// The offset + 4 is because at the end of the domain 4 bytes should be present
        	if (offset + 4 > length) {
                	++total_events_;
                	if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        	current_flow_->setPacketAnomaly(PacketAnomalyType::DNS_BOGUS_HEADER);
                	}
                	anomaly_->incAnomaly(current_flow_, PacketAnomalyType::DNS_BOGUS_HEADER);
                	return;
        	}
		// There is no name attached so lets try to extract from the response

        	boost::string_ref dns_name(dns_buffer_name_, offset);

        	if (offset == 1) { // There is no name, a root record
                	offset = 0;
                	domain = "<Root>";
        	} else {
                	domain = dns_name.substr(0, offset - 1);
        	}

	        uint16_t qtype = ntohs((header_->data[offset + 2] << 8) + header_->data[offset + 1]);

        	update_query_types(qtype);

		attach_dns_to_flow(info, domain, qtype);
	} else {
		domain = name->getName();
	}

#ifdef DEBUG
	std::cout << __FILE__ << ":" << __func__ << ":domain:" << domain << std::endl;
#endif

	// Check if the DNSProtocol have a DomainNameManager attached for match domains
        if (domain_mng_) {
        	auto domain_candidate = domain_mng_->getDomainName(domain);
                if (domain_candidate) {
			++total_events_;
			// Need to increase by 4 the generate offset due to the type and class dns fields
			offset = offset + 5;
			uint16_t answers = ntohs(header_->answers);
			const uint8_t *ptr = &(header_->data[offset]);
			current_offset_ += offset;

#ifdef HAVE_LIBLOG4CXX
                        LOG4CXX_INFO (logger, "Flow:" << *current_flow_ << " matchs with " << domain_candidate->getName());
#endif
			bool bogus = parse_response_answer(info, ptr, answers);
			if (bogus) {
                        	++total_events_;
                        	if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                                	current_flow_->setPacketAnomaly(PacketAnomalyType::DNS_BOGUS_HEADER);
                        	}
                        	anomaly_->incAnomaly(current_flow_, PacketAnomalyType::DNS_BOGUS_HEADER);
                	}
			info->matched_domain_name = domain_candidate;
#if defined(BINDING)
			current_flow_->packet->setForceAdaptorWrite(true); // The udp layer will call the databaseAdaptor update method
                        if (domain_candidate->call.haveCallback()) {
                                domain_candidate->call.executeCallback(current_flow_);
                        }
#endif
                }
	}
}

void DNSProtocol::update_query_types(uint16_t type) {

	if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_A))
		++ total_dns_type_a_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_NS))
		++ total_dns_type_ns_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_CNAME))
		++ total_dns_type_cname_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_SOA))
		++ total_dns_type_soa_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_PTR))
		++ total_dns_type_ptr_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_MX))
		++ total_dns_type_mx_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_TXT))
		++ total_dns_type_txt_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_AAAA))
		++ total_dns_type_aaaa_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_LOC))
		++ total_dns_type_loc_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_SRV))
		++ total_dns_type_srv_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_DS))
		++ total_dns_type_ds_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_SSHFP))
		++ total_dns_type_sshfp_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_DNSKEY))
		++ total_dns_type_dnskey_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_IXFR))
		++ total_dns_type_ixfr_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_ANY))
		++ total_dns_type_any_;
	else {
		++ total_dns_type_others_;
	}

}

void DNSProtocol::setDomainNameManager(const SharedPointer<DomainNameManager> &dm) {

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

void DNSProtocol::statistics(std::basic_ostream<char> &out, int level) {

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
        	out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ << std::endl;
		if (level > 1) {
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << "\n";
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << "\n";	
			if (level > 3) {
				out << "\t" << "Total allow queries:    " << std::setw(10) << total_allow_queries_ << "\n";
				out << "\t" << "Total banned queries:   " << std::setw(10) << total_ban_queries_ << "\n";
				out << "\t" << "Total queries:          " << std::setw(10) << total_queries_ << "\n";
				out << "\t" << "Total responses:        " << std::setw(10) << total_responses_ << "\n";
				out << "\t" << "Total type A:           " << std::setw(10) << total_dns_type_a_ << "\n";
				out << "\t" << "Total type NS:          " << std::setw(10) << total_dns_type_ns_ << "\n";
				out << "\t" << "Total type CNAME:       " << std::setw(10) << total_dns_type_cname_ << "\n";
				out << "\t" << "Total type SOA:         " << std::setw(10) << total_dns_type_soa_ << "\n";
				out << "\t" << "Total type PTR:         " << std::setw(10) << total_dns_type_ptr_ << "\n";
				out << "\t" << "Total type MX:          " << std::setw(10) << total_dns_type_mx_ << "\n";
				out << "\t" << "Total type TXT:         " << std::setw(10) << total_dns_type_txt_ << "\n";
				out << "\t" << "Total type AAAA:        " << std::setw(10) << total_dns_type_aaaa_ << "\n";
				out << "\t" << "Total type LOC:         " << std::setw(10) << total_dns_type_loc_ << "\n";
				out << "\t" << "Total type SRV:         " << std::setw(10) << total_dns_type_srv_ << "\n";
				out << "\t" << "Total type DS:          " << std::setw(10) << total_dns_type_ds_ << "\n";
				out << "\t" << "Total type SSHFP:       " << std::setw(10) << total_dns_type_sshfp_ << "\n";
				out << "\t" << "Total type DNSKEY:      " << std::setw(10) << total_dns_type_dnskey_ << "\n";
				out << "\t" << "Total type IXFR:        " << std::setw(10) << total_dns_type_ixfr_ << "\n";
				out << "\t" << "Total type ANY:         " << std::setw(10) << total_dns_type_any_ << "\n";
				out << "\t" << "Total type others:      " << std::setw(10) << total_dns_type_others_ << std::endl;
			}
			if (level > 2) {	
			
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
                                if (level > 3) {
                               
					info_cache_->statistics(out); 
                                        name_cache_->statistics(out);
                                        if (level > 4) {
                                              	showCacheMap(out, "\t", domain_map_, "DNS Name", "Domain"); 
                                        }
                                }
			}
		}
	}
}


void DNSProtocol::increaseAllocatedMemory(int value) { 

	info_cache_->create(value);
	name_cache_->create(value);
}

void DNSProtocol::decreaseAllocatedMemory(int value) { 

	info_cache_->destroy(value);
	name_cache_->destroy(value);
}

CounterMap DNSProtocol::getCounters() const {
	CounterMap cm;

        cm.addKeyValue("allow queries", total_allow_queries_);
        cm.addKeyValue("banned queries", total_ban_queries_);
        cm.addKeyValue("queries", total_queries_);
        cm.addKeyValue("responses", total_responses_);

        cm.addKeyValue("type A", total_dns_type_a_);
        cm.addKeyValue("type NS", total_dns_type_ns_);
        cm.addKeyValue("type CNAME", total_dns_type_cname_);
        cm.addKeyValue("type SOA", total_dns_type_soa_);
        cm.addKeyValue("type PTR", total_dns_type_ptr_);
        cm.addKeyValue("type MX", total_dns_type_mx_);
        cm.addKeyValue("type TXT", total_dns_type_txt_);
        cm.addKeyValue("type AAAA", total_dns_type_aaaa_);
        cm.addKeyValue("type LOC", total_dns_type_loc_);
        cm.addKeyValue("type SRV", total_dns_type_srv_);
        cm.addKeyValue("type DS", total_dns_type_ds_);
        cm.addKeyValue("type SSHFP", total_dns_type_sshfp_);
        cm.addKeyValue("type DNSKEY", total_dns_type_dnskey_);
        cm.addKeyValue("type IXFR", total_dns_type_ixfr_);
        cm.addKeyValue("type ANY", total_dns_type_any_);
        cm.addKeyValue("type others", total_dns_type_others_);

        return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
#if defined(PYTHON_BINDING)
boost::python::dict DNSProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE DNSProtocol::getCache() const {
#endif
	return addMapToHash(domain_map_);
}

#if defined(PYTHON_BINDING)
void DNSProtocol::showCache(std::basic_ostream<char> &out) const {

        showCacheMap(out, "", domain_map_, "DNS Names", "Domain");
}
#endif

#endif

} // namespace aiengine

