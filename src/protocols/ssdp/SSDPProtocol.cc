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
#include "SSDPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr SSDPProtocol::logger(log4cxx::Logger::getLogger("aiengine.ssdp"));
#endif

// Responses according the RFC 2616, the same of HTTP1.1 
std::unordered_map<int,SsdpResponseType> SSDPProtocol::responses_ {
        { 0, std::make_tuple("unknown code",                            0) },
        // Informational
        { 100, std::make_tuple("continue",                              0) },
        { 101, std::make_tuple("switching protocols",                   0) },
        { 102, std::make_tuple("processing",                            0) },
        // Success
        { 200, std::make_tuple("ok",                                    0) },
        { 201, std::make_tuple("created",                               0) },
        { 202, std::make_tuple("accepted",                              0) },
        { 203, std::make_tuple("non-authoritative information",         0) },
        { 204, std::make_tuple("no content",                            0) },
        { 205, std::make_tuple("reset content",                         0) },
        { 206, std::make_tuple("partial content",                       0) },
        { 207, std::make_tuple("multi-status",                          0) },
        { 208, std::make_tuple("already reported",                      0) },
        { 226, std::make_tuple("im used",                               0) },
        // Redirection
        { 300, std::make_tuple("multiple choices",                      0) },
        { 301, std::make_tuple("moved permanently",                     0) },
        { 302, std::make_tuple("found",                                 0) },
        { 303, std::make_tuple("see other",                             0) },
        { 304, std::make_tuple("not modified",                          0) },
        { 305, std::make_tuple("use proxy",                             0) },
        { 306, std::make_tuple("switch proxy",                          0) },
        { 307, std::make_tuple("temporary redirect",                    0) },
        { 308, std::make_tuple("permanent redirect",                    0) },
        // Client Error
        { 400, std::make_tuple("bad request",                           0) },
        { 401, std::make_tuple("unauthorized",                          0) },
        { 402, std::make_tuple("payment required",                      0) },
        { 403, std::make_tuple("forbidden",                             0) },
        { 404, std::make_tuple("not found",                             0) },
        { 405, std::make_tuple("method not allowed",                    0) },
        { 406, std::make_tuple("not acceptable",                        0) },
        { 407, std::make_tuple("proxy authentication required",         0) },
        { 408, std::make_tuple("request timeout",                       0) },
        { 409, std::make_tuple("conflict",                              0) },
        { 410, std::make_tuple("gone",                                  0) },
        { 411, std::make_tuple("length required",                       0) },
        { 412, std::make_tuple("precondition failed",                   0) },
        { 413, std::make_tuple("request entity too large",              0) },
        { 414, std::make_tuple("request-URI too long",                  0) },
        { 415, std::make_tuple("unsupported media type",                0) },
        { 416, std::make_tuple("requested range not satisfiable",       0) },
        { 417, std::make_tuple("expectation failed",                    0) },
        { 418, std::make_tuple("i'm a teapot",                          0) },
        { 419, std::make_tuple("authentication timeout",                0) },
        { 420, std::make_tuple("method failure",                        0) },
        { 421, std::make_tuple("misdirected request",                   0) },
        { 422, std::make_tuple("unprocessable entity",                  0) },
        { 423, std::make_tuple("locked",                                0) },
        { 424, std::make_tuple("failed dependency",                     0) },
        { 426, std::make_tuple("upgrade required",                      0) },
        { 428, std::make_tuple("precondition required",                 0) },
        { 429, std::make_tuple("too many requests",                     0) },
        { 431, std::make_tuple("request header fields too large",       0) },
        { 440, std::make_tuple("login timeout",                         0) },
        { 444, std::make_tuple("no response",                           0) },
        { 449, std::make_tuple("retry with",                            0) },
        { 450, std::make_tuple("blocked by windows parental",           0) },
        { 451, std::make_tuple("unavailable for legal reasons",         0) },
        { 494, std::make_tuple("request header too large",              0) },
        { 495, std::make_tuple("cert error",                            0) },
        { 496, std::make_tuple("no cert",                               0) },
        { 497, std::make_tuple("HTTP to HTTPS",                         0) },
        { 498, std::make_tuple("token expired/invalid",                 0) },
        { 499, std::make_tuple("client closed request",                 0) },
        // Server Error
        { 500, std::make_tuple("internal server error",                 0) },
        { 501, std::make_tuple("not implemented",                       0) },
        { 502, std::make_tuple("bad gateway",                           0) },
        { 503, std::make_tuple("service unavailable",                   0) },
        { 504, std::make_tuple("gateway timeout",                       0) },
        { 505, std::make_tuple("HTTP version not supported",            0) },
        { 506, std::make_tuple("variant also negotiates",               0) },
        { 507, std::make_tuple("insufficient storage",                  0) },
        { 508, std::make_tuple("loop detected",                         0) },
        { 509, std::make_tuple("bandwidth limit exceeded",              0) },
        { 510, std::make_tuple("not extended",                          0) },
        { 511, std::make_tuple("network authentication required",       0) },
        { 598, std::make_tuple("network read timeout error",            0) },
        { 599, std::make_tuple("network connect timeout error",         0) }
};

SSDPProtocol::SSDPProtocol():
	Protocol("SSDPProtocol", "ssdp", IPPROTO_UDP),
	header_(nullptr),
	ssdp_header_size_(0),
	total_events_(0),
	total_ban_hosts_(0),
	total_allow_hosts_(0),
	total_requests_(0),
	total_responses_(0),
	total_notifies_(0),
	total_searchs_(0),
	total_subscribes_(0),
	total_ssdpcs_(0),
	total_ssdp_others_(0),
	info_cache_(new Cache<SSDPInfo>("SSDP Info cache")),
	uri_cache_(new Cache<StringCache>("Uri cache")),
	host_cache_(new Cache<StringCache>("Host cache")),
	uri_map_(),
	host_map_(),
	domain_mng_(),
	ban_domain_mng_(),
	flow_mng_(),
	current_flow_(nullptr),
	header_field_(),
	header_parameter_() {

	 // Add the parameters that wants to be process by the SSDPProtocol
	parameters_.insert(std::make_pair<boost::string_ref, SsdpParameterHandler>(boost::string_ref("Host"),
		std::bind(&SSDPProtocol::process_host_parameter, this, std::placeholders::_1, std::placeholders::_2)));
	parameters_.insert(std::make_pair<boost::string_ref, SsdpParameterHandler>(boost::string_ref("HOST"),
	     	std::bind(&SSDPProtocol::process_host_parameter, this, std::placeholders::_1, std::placeholders::_2)));

	// TODO: Parameters as Server, Man, NT should be implemented
        // http://www.upnp-hacks.org/upnp.html
}

/*      
 * The function get_ssdp_request_method are optimized, compare with the predecessor memcmp implementation
 * results shows that by checking on this way there is a big performance improvement
 * however the functions are not pleasant to view but sometimes..... 
 */

std::tuple<bool, int> SSDPProtocol::get_ssdp_request_method(const boost::string_ref &hdr) {

        if ((hdr[0] == 'N')and(hdr[1] == 'O')) {
                if ((hdr[2] == 'T')and(hdr[3] == 'I')) {
                        if ((hdr[4] == 'F')and(hdr[5] == 'Y')) {
                        	++total_notifies_;
                                return std::tuple<bool, int>(true, 6);
                        }
                }
        } else if ((hdr[0] == 'M')and(hdr[1] == '-')) {
                if ((hdr[2] == 'S')and(hdr[3] == 'E')) {
                        if ((hdr[4] == 'A')and(hdr[5] == 'R')) {
                                if ((hdr[6] == 'C')and(hdr[7] == 'H')) {
                                	++total_searchs_;
					return std::tuple<bool, int>(true, 8);
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
        } else if ((hdr[0] == 'S')and(hdr[1] == 'S')) {
                if ((hdr[2] == 'D')and(hdr[3] == 'P')) {
                        if (hdr[4] == 'C') {
                        	++total_ssdpcs_;
				return std::tuple<bool, int>(true, 5);
			}
		}
	}
	return std::tuple<bool, int>(false, 0);
}


bool SSDPProtocol::ssdpChecker(Packet &packet) {

	// I dont like this idea of ports but...
	if ((packet.getSourcePort() == 1900)||(packet.getDestinationPort() == 1900)) {
		// setHeader(packet.getPayload());
		++total_valid_packets_;
		return true;
	} else {
		++total_invalid_packets_;
		return false;
	}
}

void SSDPProtocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);	
	host_cache_->setDynamicAllocatedMemory(value);	
	uri_cache_->setDynamicAllocatedMemory(value);	
}

bool SSDPProtocol::isDynamicAllocatedMemory() const {

	return info_cache_->isDynamicAllocatedMemory();
}	

int64_t SSDPProtocol::getCurrentUseMemory() const {

	int64_t mem = sizeof(SSDPProtocol);

	mem += info_cache_->getCurrentUseMemory();
	mem += host_cache_->getCurrentUseMemory();
	mem += uri_cache_->getCurrentUseMemory();
	
	return mem;
}

int64_t SSDPProtocol::getAllocatedMemory() const {

	int64_t mem = sizeof(SSDPProtocol);

        mem += info_cache_->getAllocatedMemory();
        mem += host_cache_->getAllocatedMemory();
        mem += uri_cache_->getAllocatedMemory();

        return mem;
}

int64_t SSDPProtocol::getTotalAllocatedMemory() const {

	int64_t mem = getAllocatedMemory();

	mem += compute_memory_used_by_maps();

        return mem;
}

int32_t SSDPProtocol::release_ssdp_info(SSDPInfo *info) {

        int32_t bytes_released = 0;

	bytes_released = releaseStringToCache(host_cache_, info->host_name);
	bytes_released += releaseStringToCache(uri_cache_, info->uri);
        
        info->resetStrings();

        return bytes_released;
}

int64_t SSDPProtocol::compute_memory_used_by_maps() const {

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

int32_t SSDPProtocol::getTotalCacheMisses() const {

	int32_t miss = 0;

	miss = info_cache_->getTotalFails();
	miss += host_cache_->getTotalFails();
	miss += uri_cache_->getTotalFails();

	return miss;
}

void SSDPProtocol::releaseCache() {

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
			SharedPointer<SSDPInfo> info = flow->getSSDPInfo();
			if (info) {
                                total_bytes_released_by_flows += release_ssdp_info(info.get());
                                total_bytes_released_by_flows += sizeof(info);
                                
                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(info);
			}
		} 
		host_map_.clear();
		uri_map_.clear();

		double cache_compression_rate = 0;

		if (total_bytes_released_by_flows > 0 ) {
			cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);	
		}

		msg.str("");
		msg << "Release " << release_hosts << " domains, " << release_uris << " uris, " << release_flows << " flows";
		msg << ", " << total_bytes_released + total_bytes_released_by_flows << " bytes";
		msg << ", compression rate " << cache_compression_rate << "%";	
		infoMessage(msg.str());
	}
}

void SSDPProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getSSDPInfo();
	if (info) {
		info_cache_->release(info);
	}
}

void SSDPProtocol::attach_host(SSDPInfo *info, const boost::string_ref &host) {

        // There is no host attached to the SSDPInfo
        if (!info->host_name) {
                GenericMapType::iterator it = host_map_.find(host);
                if (it == host_map_.end()) {
                        SharedPointer<StringCache> host_ptr = host_cache_->acquire();
                        if (host_ptr) {
                                host_ptr->setName(host.data(), host.size());
                                info->host_name = host_ptr;
                                host_map_.insert(std::make_pair(host_ptr->getName(), host_ptr));
                        }
                } else {
                        ++ (it->second).hits;
                        info->host_name = (it->second).sc;
                }
        }
}

void SSDPProtocol::attach_uri(SSDPInfo *info, const boost::string_ref &uri) {

        GenericMapType::iterator it = uri_map_.find(uri);
        if (it == uri_map_.end()) {
                SharedPointer<StringCache> uri_ptr = uri_cache_->acquire();
                if (uri_ptr) {
                        uri_ptr->setName(uri.data(), uri.length());
                        info->uri = uri_ptr;
                        uri_map_.insert(std::make_pair(uri_ptr->getName(), uri_ptr));
                        ++total_requests_;
                }
        } else {
                // Update the URI of the flow
                info->uri = (it->second).sc;
                ++total_requests_;
        }
}

bool SSDPProtocol::process_host_parameter(SSDPInfo *info, const boost::string_ref &host) {

        if (ban_domain_mng_) {
                auto host_candidate = ban_domain_mng_->getDomainName(host);
                if (host_candidate) {
#ifdef HAVE_LIBLOG4CXX
                        LOG4CXX_INFO (logger, "Flow:" << *current_flow_ << " matchs with ban host " << host_candidate->getName());
#endif
			info->setIsBanned(true);
                        ++total_ban_hosts_;
                        return false;
                }
        }

        ++total_allow_hosts_;
        attach_host(info,host);
        return true;
}

int SSDPProtocol::extract_uri(SSDPInfo *info, const boost::string_ref &header) {

        int offset = 0;
        bool found = false;
        int method_size = 0;

        // Check if is a response
        if ((header[0] == 'H')and(header[1] == 'T')and(header[2] == 'T')and(header[3] == 'P')and
                (header[4] =='/')and(header[5] == '1')and(header[6] == '.')) {
                ++total_responses_;
                info->incTotalResponses();

                int end = header.find("\r\n");
                if (end > 0) {
                        method_size = end + 2;
                }

                int response_code = std::atoi(&header[8]);
                auto rescode = responses_.find(response_code);
                if (rescode != responses_.end()) {
                        int32_t *hits = &std::get<1>(rescode->second);

                        info->setResponseCode(response_code);
                        ++(*hits);
                }

                // No uri to extract
                return method_size;
        }

        // Is not a response so check what request type is
	std::tuple<bool, int> value = get_ssdp_request_method(header);
       	found = std::get<0>(value);
	offset = std::get<1>(value);

	++offset; 

        if ((found)and(offset > 0)) {
                int end = header.find("HTTP/1.");
                if (end > 0) {
                        boost::string_ref uri(header.substr(offset, (end - offset) - 1));

                        info->incTotalRequests();
                        ++total_requests_;
                        attach_uri(info, uri);
                        method_size = end + 10;
                }
        }else{
                ++total_ssdp_others_;
        }
        return method_size;
}

void SSDPProtocol::parse_header(SSDPInfo *info, const boost::string_ref &header) {

        bool have_token = false;
        size_t i = 0;

        // Process the HTTP header
        int field_index = 0;
        int parameter_index = 0;

        header_field_.clear();
        header_parameter_.clear();

        for (i = 0; i< header.length(); ++i) {
                // Check if is end off line
		if ((header[i] == 0x0D)and(header[i + 1] == 0x0A)) {

                        if (header_field_.length()) {
                                auto it = parameters_.find(header_field_);
                                if (it != parameters_.end()) {
                                        auto callback = (*it).second;

                                        header_parameter_ = header.substr(parameter_index, i - parameter_index);

                                        bool sw = callback(info, header_parameter_);
                                        if (!sw) { // The flow have been marked as banned
                                                // TODO info->setIsBanned(true);
                                                // release_http_info_cache(info);
                                                break;
                                        }
                                }
                                header_field_.clear();
                                header_parameter_.clear();
                                field_index = i + 2;
                        }

			if ((header[i + 2] == 0x0D)and(header[i + 3] == 0x0A)) {
                                // end of the header
                                ssdp_header_size_ += 4;
                                break;
                        }
                        have_token = false;
                        ++i;
                } else {
                        if ((header[i] == ':')and(have_token == false)) {
                                header_field_ = header.substr(field_index, i - field_index);
                                parameter_index = i + 2;
                                field_index = i + 1;
                                have_token = true;
                                ++i;
                        }
                }
        }
        ssdp_header_size_ += i;
}

void SSDPProtocol::setDomainNameManager(const SharedPointer<DomainNameManager> &dm) {

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

void SSDPProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;

       	SharedPointer<SSDPInfo> info = flow->getSSDPInfo();

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

	// The flow have been banned by a DomainNameManager so there is no need
	// of continue analysing
        if (info->isBanned() == true) {
                return;
        }

	current_flow_ = flow;

	setHeader(flow->packet->getPayload());
	boost::string_ref header(reinterpret_cast <const char*> (header_), length);

        int offset = extract_uri(info.get(), header);
        if (offset > 0) {
        	ssdp_header_size_ = offset;
		boost::string_ref newheader(header.substr(offset, length - offset));
                parse_header(info.get(), newheader);
        }

	if (flow->getFlowDirection() == FlowDirection::FORWARD) {
        	// Just verify the Host on the first request
        	if (info->getTotalRequests() == 1) {
        		if ((domain_mng_)and(info->host_name)) {
                        	auto host_candidate = domain_mng_->getDomainName(info->host_name->getName());
                       	 	if (host_candidate) {
					++total_events_;
					info->matched_domain_name = host_candidate;
#if defined(BINDING)
#ifdef HAVE_LIBLOG4CXX
                               		LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with " << host_candidate->getName());
#endif
                               		if (host_candidate->call.haveCallback()) {
                               			host_candidate->call.executeCallback(flow);
                               		}
#endif
                        	}
                	}
		}
	}

	return;
} 

void SSDPProtocol::statistics(std::basic_ostream<char> &out, int level) {

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
                                out << "\t" << "Total allow hosts:      " << std::setw(10) << total_allow_hosts_ << "\n";
                                out << "\t" << "Total banned hosts:     " << std::setw(10) << total_ban_hosts_ << "\n";
                                out << "\t" << "Total requests:         " << std::setw(10) << total_requests_ << "\n";
                                out << "\t" << "Total responses:        " << std::setw(10) << total_responses_ <<"\n";
                                out << "\t" << "SSDP Methods" << "\n";
               			out << "\t" << "Total notifies:         " << std::setw(10) << total_responses_ << "\n"; 
               			out << "\t" << "Total m-searchs:        " << std::setw(10) << total_searchs_ << "\n"; 
               			out << "\t" << "Total subscribes:       " << std::setw(10) << total_subscribes_ << "\n"; 
               			out << "\t" << "Total ssdpcs:           " << std::setw(10) << total_ssdpcs_ << "\n"; 
                                out << "\t" << "Total others:           " << std::setw(10) << total_ssdp_others_ << std::endl;
                                if (level > 4) {
                                        out << "\t" << "SSDP Responses" << "\n";
                                        for (auto &res: responses_) {
                                                auto item = std::get<1>(res);
                                                const char *label = std::get<0>(item);
                                                int32_t hits = std::get<1>(item);

                                                out << "\t" << "Total " << label << ":" << std::right << std::setfill(' ') << std::setw(35 - strlen(label)) << hits << "\n";
                                        }
					out.flush();
                                }
                        }
                        if (level > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
                                if (level > 3) {
                                        info_cache_->statistics(out);
                                        uri_cache_->statistics(out);
                                        host_cache_->statistics(out);
                                        if (level > 4) {
                                                showCacheMap(out, "\t", uri_map_, "SSDP Uris", "Uri");
                                                showCacheMap(out, "\t", host_map_, "SSDP Hosts", "Host");
                                        }
                                }
                        }
                }
        }
}

void SSDPProtocol::increaseAllocatedMemory(int value) { 

	info_cache_->create(value);
	host_cache_->create(value);
	uri_cache_->create(value);
}

void SSDPProtocol::decreaseAllocatedMemory(int value) { 

	info_cache_->destroy(value);
	host_cache_->destroy(value);
	uri_cache_->destroy(value);
}

CounterMap SSDPProtocol::getCounters() const {
	CounterMap cm;

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
        cm.addKeyValue("allow hosts", total_allow_hosts_);
        cm.addKeyValue("banned hosts", total_ban_hosts_);
        cm.addKeyValue("requests", total_requests_);
        cm.addKeyValue("responses", total_responses_);
	cm.addKeyValue("notifies", total_notifies_);
	cm.addKeyValue("m-searchs", total_searchs_);
	cm.addKeyValue("subscribes", total_subscribes_);
	cm.addKeyValue("ssdpcs", total_ssdpcs_);
        cm.addKeyValue("others", total_ssdp_others_);

        return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
#if defined(PYTHON_BINDING)
boost::python::dict SSDPProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE SSDPProtocol::getCache() const {
#endif
	return addMapToHash(host_map_);
}

#if defined(PYTHON_BINDING)
void SSDPProtocol::showCache(std::basic_ostream<char> &out) const {

	showCacheMap(out, "", host_map_, "SSDP Hosts", "Host");
}
#endif

#endif

} // namespace aiengine

