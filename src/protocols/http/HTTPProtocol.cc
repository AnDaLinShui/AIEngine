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
#include "HTTPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr HTTPProtocol::logger(log4cxx::Logger::getLogger("aiengine.http"));
#endif

std::unordered_map<int,HttpResponseType> HTTPProtocol::responses_ {
	{ 0, std::make_tuple("unknown code",				0) },
	// Informational
	{ 100, std::make_tuple("continue",				0) },
	{ 101, std::make_tuple("switching protocols",			0) },
	{ 102, std::make_tuple("processing",				0) },
	// Success 
	{ 200, std::make_tuple("ok",					0) },
	{ 201, std::make_tuple("created",				0) },
	{ 202, std::make_tuple("accepted",				0) },
	{ 203, std::make_tuple("non-authoritative information",		0) },
	{ 204, std::make_tuple("no content",				0) },
	{ 205, std::make_tuple("reset content",				0) },
	{ 206, std::make_tuple("partial content",			0) },
	{ 207, std::make_tuple("multi-status",				0) },
	{ 208, std::make_tuple("already reported",			0) },
	{ 226, std::make_tuple("im used",				0) },
	// Redirection
	{ 300, std::make_tuple("multiple choices",			0) },
	{ 301, std::make_tuple("moved permanently",			0) },
	{ 302, std::make_tuple("found",					0) },
	{ 303, std::make_tuple("see other",				0) },
	{ 304, std::make_tuple("not modified",				0) },
	{ 305, std::make_tuple("use proxy",				0) },
	{ 306, std::make_tuple("switch proxy",				0) },
	{ 307, std::make_tuple("temporary redirect",			0) },
	{ 308, std::make_tuple("permanent redirect",			0) },
	// Client Error
	{ 400, std::make_tuple("bad request",				0) },
	{ 401, std::make_tuple("unauthorized",				0) },
	{ 402, std::make_tuple("payment required",			0) },
	{ 403, std::make_tuple("forbidden",				0) },
	{ 404, std::make_tuple("not found",				0) },
	{ 405, std::make_tuple("method not allowed",			0) },
	{ 406, std::make_tuple("not acceptable",			0) },
	{ 407, std::make_tuple("proxy authentication required",		0) },
	{ 408, std::make_tuple("request timeout",			0) },
	{ 409, std::make_tuple("conflict",				0) },
	{ 410, std::make_tuple("gone",					0) },
	{ 411, std::make_tuple("length required",			0) },
	{ 412, std::make_tuple("precondition failed",			0) },
	{ 413, std::make_tuple("request entity too large",		0) },
	{ 414, std::make_tuple("request-URI too long",			0) },
	{ 415, std::make_tuple("unsupported media type",		0) },
	{ 416, std::make_tuple("requested range not satisfiable",	0) },
	{ 417, std::make_tuple("expectation failed",			0) },
	{ 418, std::make_tuple("i'm a teapot",				0) },
	{ 419, std::make_tuple("authentication timeout",		0) },
	{ 420, std::make_tuple("method failure",			0) },
	{ 421, std::make_tuple("misdirected request",			0) },
	{ 422, std::make_tuple("unprocessable entity",			0) },
	{ 423, std::make_tuple("locked",				0) },
	{ 424, std::make_tuple("failed dependency",			0) },
	{ 426, std::make_tuple("upgrade required",			0) },
	{ 428, std::make_tuple("precondition required",			0) },
	{ 429, std::make_tuple("too many requests",			0) },
	{ 431, std::make_tuple("request header fields too large",	0) },
	{ 440, std::make_tuple("login timeout",				0) },
	{ 444, std::make_tuple("no response",				0) },
	{ 449, std::make_tuple("retry with",				0) },
	{ 450, std::make_tuple("blocked by windows parental",		0) },
	{ 451, std::make_tuple("unavailable for legal reasons",		0) },
	{ 494, std::make_tuple("request header too large",		0) },
	{ 495, std::make_tuple("cert error",				0) },
	{ 496, std::make_tuple("no cert",				0) },
	{ 497, std::make_tuple("HTTP to HTTPS",				0) },
	{ 498, std::make_tuple("token expired/invalid",			0) },
	{ 499, std::make_tuple("client closed request",			0) },
	// Server Error
	{ 500, std::make_tuple("internal server error",			0) },
	{ 501, std::make_tuple("not implemented",			0) },
	{ 502, std::make_tuple("bad gateway",				0) },
	{ 503, std::make_tuple("service unavailable",			0) },
	{ 504, std::make_tuple("gateway timeout",			0) },
	{ 505, std::make_tuple("HTTP version not supported",		0) },
	{ 506, std::make_tuple("variant also negotiates",		0) },
	{ 507, std::make_tuple("insufficient storage",			0) },
	{ 508, std::make_tuple("loop detected",				0) },
	{ 509, std::make_tuple("bandwidth limit exceeded",		0) },
	{ 510, std::make_tuple("not extended",				0) },
	{ 511, std::make_tuple("network authentication required",	0) },
	{ 598, std::make_tuple("network read timeout error",		0) },
	{ 599, std::make_tuple("network connect timeout error",		0) }
};

/*
 * The functions get_http_request_method and is_minimal_http_header
 * are optimized, compare with the predecessor memcmp implementation
 * results shows that by checking on this way there is a big performance improvement
 * however the functions are not pleasant to view but sometimes..... 
 */

std::tuple<bool, int> HTTPProtocol::get_http_request_method(const boost::string_ref &hdr) {

        if ((hdr[0] == 'G')and(hdr[1] == 'E')) {
                if (hdr[2] == 'T') {
			++total_gets_;
                        return std::tuple<bool, int>(true, 3);
                }
        } else if ((hdr[0] == 'P')and(hdr[1] == 'O')) {
                if ((hdr[2] == 'S')and(hdr[3] == 'T')) {
			++total_posts_;
                        return std::tuple<bool, int>(true, 4);
                }
        } else if ((hdr[0] == 'H')and(hdr[1] == 'E')) {
                if ((hdr[2] == 'A')and(hdr[3] == 'D')) {
			++total_heads_;
                        return std::tuple<bool, int>(true, 4);
                }
        } else if ((hdr[0] == 'C')and(hdr[1] == 'O')) {        
                if ((hdr[2] == 'N')and(hdr[3] == 'N')) {
                        if ((hdr[4] == 'E')and(hdr[5] == 'C')) {
                                if (hdr[6] == 'T') {
					++total_connects_;
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
        } else if ((hdr[0] == 'P')and(hdr[1] == 'U')) {
                if (hdr[2] == 'T') {
			++total_puts_;
                        return std::tuple<bool, int>(true, 3);
                }
        } else if ((hdr[0] == 'D')and(hdr[1] == 'E')) {
                if ((hdr[2] == 'L')and(hdr[3] == 'E')) {
                        if ((hdr[4] == 'T')and(hdr[5] == 'E')) {
				++total_deletes_;
                                return std::tuple<bool, int>(true, 6);
                        }
                }
        } else if ((hdr[0] == 'T')and(hdr[1] == 'R')) {
                if ((hdr[2] == 'A')and(hdr[3] == 'C')) {
                        if (hdr[4] == 'E') {
				++total_traces_;
                                return std::tuple<bool, int>(true, 5);
                        }
                }
        }
	return std::tuple<bool, int>(false, 0);
}

bool HTTPProtocol::is_minimal_http_header(const char *hdr) {

	if ((hdr[0] == 'G')and(hdr[1] == 'E')) {
		if (hdr[2] == 'T') {
			return true;
		}
	} else if ((hdr[0] == 'P')and(hdr[1] == 'O')) {
		if ((hdr[2] == 'S')and(hdr[3] == 'T')) {
			return true;
		}
	} else if ((hdr[0] == 'H')and(hdr[1] == 'E')) {
		if ((hdr[2] == 'A')and(hdr[3] == 'D')) {
			return true;
		}
	} else if ((hdr[0] == 'C')and(hdr[1] == 'O')) {
		if ((hdr[2] == 'N')and(hdr[3] == 'N')) {
			if ((hdr[4] == 'E')and(hdr[5] == 'C')) {
				if (hdr[6] == 'T') { 
					return true;
				}
			}
		}
	} else if ((hdr[0] == 'O')and(hdr[1] == 'P')) {
		if ((hdr[2] == 'T')and(hdr[3] == 'I')) {
			if ((hdr[4] == 'O')and(hdr[5] == 'N')) {
				if (hdr[6] == 'S') { 
					return true;
				}
			}
		}
	} else if ((hdr[0] == 'P')and(hdr[1] == 'U')) {
		if (hdr[2] == 'T') {
			return true;
		}
	} else if ((hdr[0] == 'D')and(hdr[1] == 'E')) {
		if ((hdr[2] == 'L')and(hdr[3] == 'E')) {
			if ((hdr[4] == 'T')and(hdr[5] == 'E')) {
				return true;
			}
		}
	} else if ((hdr[0] == 'T')and(hdr[1] == 'R')) {
		if ((hdr[2] == 'A')and(hdr[3] == 'C')) {
			if (hdr[4] == 'E') {
				return true;
			}
		} 
	}
	return false;
}

HTTPProtocol::HTTPProtocol():
	Protocol("HTTPProtocol", "http", IPPROTO_TCP),
	header_(nullptr),
	http_header_size_(0),
#if defined(STAND_ALONE_TEST) || defined(TESTING)
       	http_method_size_(0),
	http_parameters_size_(0),
#endif
	total_l7_bytes_(0),
	total_allow_hosts_(0),
	total_ban_hosts_(0),
	total_requests_(0),
	total_responses_(0),
	total_http_others_(0),
        total_gets_(0),
        total_posts_(0),
        total_heads_(0),
        total_connects_(0),
        total_options_(0),
        total_puts_(0),
        total_deletes_(0),
        total_traces_(0),
	total_events_(0),
	info_cache_(new Cache<HTTPInfo>("HTTP Info Cache")),
	uri_cache_(new Cache<StringCache>("Uri cache")),
	host_cache_(new Cache<StringCache>("Host cache")),
	ua_cache_(new Cache<StringCache>("UserAgent cache")),
	ct_cache_(new Cache<StringCache>("ContentType cache")),
	file_cache_(new Cache<StringCache>("File cache")),
	ua_map_(),
	host_map_(),
	uri_map_(),
	ct_map_(),
	file_map_(),
	domain_mng_(),
	ban_domain_mng_(),
	flow_mng_(),
	http_ref_header_(),
	header_field_(),
	header_parameter_(),
	current_flow_(nullptr),
	anomaly_(),
	eval_() {

	// Add the parameters that wants to be process by the HTTPProtocol              
	parameters_.insert(std::make_pair<boost::string_ref, HttpParameterHandler>(boost::string_ref("Host"),
        	std::bind(&HTTPProtocol::process_host_parameter, this, std::placeholders::_1, std::placeholders::_2)));
        parameters_.insert(std::make_pair<boost::string_ref, HttpParameterHandler>(boost::string_ref("User-Agent"),
        	std::bind(&HTTPProtocol::process_ua_parameter, this, std::placeholders::_1, std::placeholders::_2)));
        parameters_.insert(std::make_pair<boost::string_ref, HttpParameterHandler>(boost::string_ref("Content-Length"),
                std::bind(&HTTPProtocol::process_content_length_parameter, this, std::placeholders::_1, std::placeholders::_2)));
        parameters_.insert(std::make_pair<boost::string_ref, HttpParameterHandler>(boost::string_ref("Content-Type"),
                std::bind(&HTTPProtocol::process_content_type_parameter, this, std::placeholders::_1, std::placeholders::_2)));
        parameters_.insert(std::make_pair<boost::string_ref, HttpParameterHandler>(boost::string_ref("Content-disposition"),
                std::bind(&HTTPProtocol::process_content_disposition_parameter, this, std::placeholders::_1, std::placeholders::_2)));
}

HTTPProtocol::~HTTPProtocol() { 

	anomaly_.reset(); 
}

// Condition for say that a payload is HTTP
bool HTTPProtocol::httpChecker(Packet &packet) {

	const char * header = reinterpret_cast<const char*>(packet.getPayload());
	int16_t length = packet.getLength();

	// Just check the method of the header, the rest of the header should be
	// verified once the flow is accepted by the Protocol
	if (length >= header_size) {
		if (is_minimal_http_header(header)) {
			setHeader(packet.getPayload());
			++total_valid_packets_;
			return true;
		}
	}
	++total_invalid_packets_;
	return false;
}

void HTTPProtocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);
	uri_cache_->setDynamicAllocatedMemory(value);
	host_cache_->setDynamicAllocatedMemory(value);
	ua_cache_->setDynamicAllocatedMemory(value);
	ct_cache_->setDynamicAllocatedMemory(value);
	file_cache_->setDynamicAllocatedMemory(value);
}

bool HTTPProtocol::isDynamicAllocatedMemory() const { 

	return info_cache_->isDynamicAllocatedMemory();
}

int64_t HTTPProtocol::getCurrentUseMemory() const {

	int64_t mem = sizeof(HTTPProtocol);

	mem += info_cache_->getCurrentUseMemory();
	mem += uri_cache_->getCurrentUseMemory();
	mem += host_cache_->getCurrentUseMemory();
	mem += ua_cache_->getCurrentUseMemory();
	mem += ct_cache_->getCurrentUseMemory();
	mem += file_cache_->getCurrentUseMemory();

	return mem;
}

int64_t HTTPProtocol::getAllocatedMemory() const {

        int64_t mem = sizeof(HTTPProtocol);

	mem += info_cache_->getAllocatedMemory();
        mem += uri_cache_->getAllocatedMemory();
        mem += host_cache_->getAllocatedMemory();
        mem += ua_cache_->getAllocatedMemory();
        mem += ct_cache_->getAllocatedMemory();
        mem += file_cache_->getAllocatedMemory();

        return mem;
}

int64_t HTTPProtocol::getTotalAllocatedMemory() const {

        int64_t mem = getAllocatedMemory();

	mem += compute_memory_used_by_maps();

	return mem;
}

// Removes or decrements the hits of the maps.
// This method just decrements the uris and the useragents, the host map is not change
// because we want to keep a reference on the map of the host that have been processed.
//
// Notice that the call release_http_info frees all the values of the HTTPInfo but not 
// the references of the host_map_
//
void HTTPProtocol::release_http_info_cache(HTTPInfo *info) {

	if (info->ua) {
                auto it = ua_map_.find(info->ua->getName());
		if (it != ua_map_.end()) {
                        int *hits = &(it->second).hits;
                        --(*hits);

			if ((*hits) <= 0) {
				ua_map_.erase(it);
			}
		}
	}

	if (info->uri) {
                auto it = uri_map_.find(info->uri->getName());
                if (it != uri_map_.end()) {
                        int *hits = &(it->second).hits;
                        --(*hits);
                        
                        if ((*hits) <= 0) {
                                uri_map_.erase(it);
                        }
                }
        }

	release_http_info(info);
}


int32_t HTTPProtocol::release_http_info(HTTPInfo *info) {

	int32_t bytes_released = 0;

	bytes_released = releaseStringToCache(host_cache_, info->host_name);
	bytes_released += releaseStringToCache(ua_cache_, info->ua);
	bytes_released += releaseStringToCache(uri_cache_, info->uri);
	bytes_released += releaseStringToCache(ct_cache_, info->ct);
	bytes_released += releaseStringToCache(file_cache_, info->filename);

        info->resetStrings();

	return bytes_released;
}

void HTTPProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getHTTPInfo();
	if (info) {
		info_cache_->release(info);	
	}
}


int64_t HTTPProtocol::compute_memory_used_by_maps() const {

	int64_t bytes = (host_map_.size() + ua_map_.size() + ct_map_.size() + file_map_.size()) * sizeof(StringCacheHits);
	// Compute the size of the strings used as keys on the map
	std::for_each (host_map_.begin(), host_map_.end(), [&bytes] (PairStringCacheHits const &ht) {
		bytes += ht.first.size();
	});
	std::for_each (ua_map_.begin(), ua_map_.end(), [&bytes] (PairStringCacheHits const &ht) {
		bytes += ht.first.size();
	});
	std::for_each (uri_map_.begin(), uri_map_.end(), [&bytes] (PairStringCacheHits const &ht) {
		bytes += ht.first.size();
	});
	std::for_each (ct_map_.begin(), ct_map_.end(), [&bytes] (PairStringCacheHits const &ht) {
		bytes += ht.first.size();
	});
        std::for_each (file_map_.begin(), file_map_.end(), [&bytes] (PairStringCacheHits const &ht) {
                bytes += ht.first.size();
        });

	return bytes;
}

int32_t HTTPProtocol::getTotalEvents() const {

	return total_events_ + eval_.getTotalMatches();
}

int32_t HTTPProtocol::getTotalCacheMisses() const {

	int32_t miss = 0;

	miss = info_cache_->getTotalFails();
	miss += host_cache_->getTotalFails();
	miss += ua_cache_->getTotalFails();
	miss += uri_cache_->getTotalFails();
	miss += ct_cache_->getTotalFails();
	miss += file_cache_->getTotalFails();

	return miss;
}

void HTTPProtocol::releaseCache() {

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
                int32_t release_uas = ua_map_.size();
                int32_t release_cts = ct_map_.size();
                int32_t release_files = file_map_.size();

                for (auto &flow: ft) {
			auto info = flow->getHTTPInfo();
			if (info) {
				total_bytes_released_by_flows += release_http_info(info.get());
				total_bytes_released_by_flows += sizeof(info);
				
				flow->layer7info.reset();
				++ release_flows;
				info_cache_->release(info);	
                        }
                } 
                host_map_.clear();
		uri_map_.clear();
		ua_map_.clear();
		ct_map_.clear();
		file_map_.clear();

                double cache_compression_rate = 0;
                
		if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_hosts << " hosts, " << release_uas;
		msg << " useragents, " << release_uris << " uris, ";
		msg << release_files << " filenames, ";
		msg << release_cts << " contenttypes, " << release_flows << " flows";
		msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}


void HTTPProtocol::attach_host(HTTPInfo *info, const boost::string_ref &host) {

	// There is no host attached to the HTTPInfo
	if (!info->host_name) {
		auto it = host_map_.find(host);
		if (it == host_map_.end()) {
			auto host_ptr = host_cache_->acquire();
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

bool HTTPProtocol::process_host_parameter(HTTPInfo *info, const boost::string_ref &host) {

	if (ban_domain_mng_) {
        	auto host_candidate = ban_domain_mng_->getDomainName(host);
                if (host_candidate) {
#ifdef HAVE_LIBLOG4CXX
                	LOG4CXX_INFO (logger, "Flow:" << *current_flow_ << " matchs with ban host " << host_candidate->getName());
#endif
                        ++total_ban_hosts_;
                        return false;
                }
	}
        ++total_allow_hosts_;
	attach_host(info, host);
	return true;
}

bool HTTPProtocol::process_ua_parameter(HTTPInfo *info, const boost::string_ref &ua) {

	attach_useragent(info, ua);
	return true;
}

bool HTTPProtocol::process_content_length_parameter(HTTPInfo *info, const boost::string_ref &parameter) {

	int64_t length = std::atoll(parameter.data());

	info->setContentLength(length);
	info->setDataChunkLength(length);
	info->setHaveData(true);

	return true;
}

bool HTTPProtocol::process_content_disposition_parameter(HTTPInfo *info, const boost::string_ref &cd) {

        size_t end = cd.find("filename=");

        if (end != std::string::npos) {
		boost::string_ref filename = cd.substr(end + 9);
		if (filename.starts_with('"')) {
			filename.remove_prefix(1);
		}      
		if (filename.ends_with('"')) {
			filename.remove_suffix(1);
		} 
		if (filename.length() > 0) {
			attach_filename(info, filename);
		}
	}
        return true;
}

bool HTTPProtocol::process_content_type_parameter(HTTPInfo *info, const boost::string_ref &ct) {

	size_t ct_end = ct.find_first_of(";");

	boost::string_ref ctype = ct;
        if (ct_end != std::string::npos) {
        	ctype = ct.substr(0, ct_end);
        }

	attach_content_type(info, ctype);	
	return true;
}

void HTTPProtocol::attach_useragent(HTTPInfo *info, const boost::string_ref &ua) {

	if (!info->ua) {
		auto it = ua_map_.find(ua);
		if (it == ua_map_.end()) {
			auto ua_ptr = ua_cache_->acquire();
			if (ua_ptr) {
				ua_ptr->setName(ua.data(), ua.length());
				info->ua = ua_ptr;
				ua_map_.insert(std::make_pair(ua_ptr->getName(), ua_ptr));
			}	
		} else {
			++ (it->second).hits;
			info->ua = (it->second).sc;	
		}
	}
}

// The URI should be updated on every request
void HTTPProtocol::attach_uri(HTTPInfo *info, const boost::string_ref &uri) {

	auto it = uri_map_.find(uri);
        if (it == uri_map_.end()) {
        	auto uri_ptr = uri_cache_->acquire();
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

void HTTPProtocol::attach_content_type(HTTPInfo *info, const boost::string_ref &ct) {

        auto it = ct_map_.find(ct);
        if (it == ct_map_.end()) {
                auto ct_ptr = ct_cache_->acquire();
                if (ct_ptr) {
                        ct_ptr->setName(ct.data(), ct.length());
                        info->ct = ct_ptr;
                        ct_map_.insert(std::make_pair(ct_ptr->getName(), ct_ptr));
                }
        } else {
                // Update the ContentType of the flow
                info->ct = (it->second).sc;
	}
}

void HTTPProtocol::attach_filename(HTTPInfo *info, const boost::string_ref &name) {

        auto it = file_map_.find(name);
        if (it == file_map_.end()) {
                auto name_ptr = file_cache_->acquire();
                if (name_ptr) {
                        name_ptr->setName(name.data(), name.length());
                        info->filename = name_ptr;
                        file_map_.insert(std::make_pair(name_ptr->getName(), name_ptr));
                }
        } else {
                // Update the Filename of the flow
                info->filename = (it->second).sc;
	}
}

int HTTPProtocol::extract_uri(HTTPInfo *info, const boost::string_ref &header) {

        int offset = 0;
        bool found = false;
	int method_size = 0;
#ifdef DEBUG
        std::cout << __FILE__ << ":" << __func__ << ":header.len:" << header.length() << std::endl;
#endif

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

		// Extract the content-type
		size_t h_offset = header.find("Content-Type:");
		if ((h_offset != std::string::npos) and (h_offset + 14 < header.length())) {
			boost::string_ref ct_value(header.substr(h_offset + 14));
			size_t ct_end = ct_value.find_first_of("\r\n");

			ct_value = ct_value.substr(0, ct_end);
			process_content_type_parameter(info, ct_value);
	
			h_offset = header.find("Content-Disposition:");
			if (h_offset != std::string::npos) {
				boost::string_ref cd_value(header.substr(h_offset + 20));
				size_t ct_end = cd_value.find_first_of("\r\n");

				cd_value = cd_value.substr(0, ct_end);
				process_content_disposition_parameter(info, cd_value);
			}
                }
                // No uri to extract but needs to return where the data starts
                return method_size;
        }

	// Is not a response so check what request type is
	std::tuple<bool, int> value = get_http_request_method(header);

	found = std::get<0>(value);
	offset = std::get<1>(value);

        if ((found)and(offset > 0)) {
		++offset;
                int end = header.find("HTTP/1.");
                if (end > 0) {
                        boost::string_ref uri(header.substr(offset, (end - offset) - 1));

			info->incTotalRequests();
                        // ++total_requests_;
                        attach_uri(info, uri);
			method_size = end + 10;
                } else {
			// Anomaly on the URI header
			++total_events_;
			if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
				current_flow_->setPacketAnomaly(PacketAnomalyType::HTTP_BOGUS_URI_HEADER);
			}
			anomaly_->incAnomaly(current_flow_, PacketAnomalyType::HTTP_BOGUS_URI_HEADER);
		}
        } else {
                ++total_http_others_;
        }
	return method_size;
}

void HTTPProtocol::parse_header(HTTPInfo *info, const boost::string_ref &header) {

        bool have_token = false;
        size_t i = 0;
	// Process the HTTP header
	int field_index = 0;
	int parameter_index = 0;
	header_field_.clear();
	header_parameter_.clear(); 

	for (i = 0; i < header.length() - 1; ++i) {
       		// Check if is end off line
		if ((header[i] == 0x0D)and(header[i + 1] == 0x0A)) {

                	if (header_field_.length()) {
				auto it = parameters_.find(header_field_);
                                if (it != parameters_.end()) {
                                	auto callback = (*it).second;
					
					header_parameter_ = header.substr(parameter_index, i - parameter_index);
                                        
					bool sw = callback(info, header_parameter_);
					if (!sw) { // The flow have been marked as banned
                                                info->setIsBanned(true);
						release_http_info_cache(info);
					       	// The http_header_size_ is going to be with a wrong value
						// however, this flow is not going to be process any more
						http_header_size_ += header.length();
						return;
					}
                                }
                                header_field_.clear();
                                header_parameter_.clear();
				field_index = i + 2;
			}
			if (i + 3 < header.length()) {
				if ((header[i + 2] == 0x0D)and(header[i + 3] == 0x0A)) {
					// end of the header
					http_header_size_ += 3;
#if defined(STAND_ALONE_TEST) || defined(TESTING)
					http_parameters_size_ = 3;
#endif
					break;
				}
                       		i = i + 2;
			}
			have_token = false;
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

	http_header_size_ += i + 1;
#if defined(STAND_ALONE_TEST) || defined(TESTING)
       	http_parameters_size_ += i + 1;
#endif
}

void HTTPProtocol::process_payloadl7(Flow * flow, HTTPInfo *info, const boost::string_ref &payloadl7) {

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

int HTTPProtocol::process_requests_and_responses(HTTPInfo *info, const boost::string_ref &header) {

#ifdef DEBUG
        std::cout << __FILE__ << ":" << __func__ << ":header.len:" << header.length() << std::endl;
#endif

	int offset = extract_uri(info, header);
        if (offset > 0) {
#if defined(STAND_ALONE_TEST) || defined(TESTING)
        	http_method_size_ = offset;
#endif
        	http_header_size_ = offset;
		int length = header.length() - offset;

		// We expect a minimun of a header, bigger than \r\n\r\n for example	
		if (length > 4) {
			boost::string_ref newheader(header.substr(offset, length));
                	parse_header(info, newheader);
		} else {
			++total_events_;
                        if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                                current_flow_->setPacketAnomaly(PacketAnomalyType::HTTP_BOGUS_NO_HEADERS);
                        }
                        anomaly_->incAnomaly(current_flow_, PacketAnomalyType::HTTP_BOGUS_NO_HEADERS);

			// For requests that don't have any parameters, we create a fake host domain 
			// that allow us have the posibility of triger domains names with this
			// type of requests (security pentesting frameworks)
			boost::string_ref fake_hostname("*");
			attach_host(info, fake_hostname);
		}
        }

	return offset;
}

// This method verifies if the given URI exists on the HTTPUriSet or on a group of Regexs
void HTTPProtocol::process_matched_uris(Flow *flow, HTTPInfo *info) {

	// Check if the domain have a UriSet
	auto uset = info->matched_domain_name->getHTTPUriSet();
	if (uset) {
		if (uset->lookupURI(info->uri->getName())) {
			++total_events_;
			info->setWriteUri(true);
#if defined(BINDING)
			if (uset->call.haveCallback()) {
				uset->call.executeCallback(flow);	
			}
#endif
		}
	} else {
		auto rm = info->matched_domain_name->getHTTPUriRegexManager();
		if (rm) {
			bool result = false;
			boost::string_ref data(info->uri->getName());

			rm->evaluate(data,&result);
			if (result) {
				++total_events_;
				info->setWriteUri(true);
			}
#if defined(BINDING)
			auto regex = rm->getMatchedRegex();
			if (result) {
				if (regex->call.haveCallback()) {
					regex->call.executeCallback(flow);
				}
				// The regex could have a RegexManager attached for
				// analyse the payload of POST messages for example
				auto next_rm = regex->getNextRegexManager();
                		if (next_rm) {
                        		flow->regex_mng = next_rm;
                        		flow->regex.reset();
                		}	
			}
#endif
		}	
	}
}

void HTTPProtocol::processFlow(Flow *flow) {

	http_header_size_ = 0;
	int length = flow->packet->getLength();
	++total_packets_;	
	total_bytes_ += length;
	++flow->total_packets_l7;

	auto info = flow->getHTTPInfo();
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
#ifdef PYTHON_BINDING
		// The HTTP flow could be banned from the python side
		if (info->getIsRelease() == true) {
			release_http_info_cache(info.get());

			// The resouces have been released so there is no
			// need for call again the release_http_info_cache method
			info->setIsRelease(false); 
		}
#endif
		return;
	}

	current_flow_ = flow;
	boost::string_ref header(reinterpret_cast <const char*> (flow->packet->getPayload()), length);

#ifdef DEBUG
	std::cout << __FILE__ << ":" << __func__ << ":flow:" << *flow << " bytes:" << length << " l7packets:"<< flow->total_packets_l7; 
	std::cout << " havedata:" << info->getHaveData() << " data_chunk_length:" << info->getDataChunkLength() << std::endl;
	// showPayload(std::cout, flow->packet->getPayload(), length);
#endif

#if defined(STAND_ALONE_TEST) || defined(TESTING)
       	http_method_size_ = 0;
       	http_parameters_size_ = 0;
#endif
	if (info->getHTTPDataDirection() == flow->getFlowDirection()) {

		// The HTTPInfo says that the pdu have data
        	if (info->getHaveData() == true) {
                	total_l7_bytes_ += length;
                	int32_t left_length = info->getDataChunkLength() - length;

                	if (left_length > 0) {
                        	info->setDataChunkLength(left_length);
                	} else {
                        	info->setDataChunkLength(0);
                        	info->setHaveData(false);
                	}
                	boost::string_ref payloadl7(&header[0], length);

                	process_payloadl7(flow, info.get(), payloadl7);
	
			info->setHTTPDataDirection(flow->getFlowDirection());
                	return;
		}
	} else {
		// Requests and responses

		// If the offset is > 0 there is a HTTP header if not is l7 data
		int offset = process_requests_and_responses(info.get(), header);

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

			// Process the URIs on each request
			if ((info->matched_domain_name)and(offset > 0)) {
				process_matched_uris(flow, info.get());
			}
		}
	}

        if ((info->getHaveData() == true)or(http_header_size_ < length)) {

		int32_t data_size = length - http_header_size_;
		int32_t data_chunk = info->getDataChunkLength();
		int32_t delta = data_chunk - data_size;

		total_l7_bytes_ += data_size;
		
		if ((delta > 0)or(data_size > 0)) {
			info->setDataChunkLength(delta);
			boost::string_ref payloadl7(&header[http_header_size_], data_size);
	
			process_payloadl7(flow, info.get(), payloadl7);	
		} else {
			info->setDataChunkLength(0);
			info->setHaveData(false);
		}
	}            

	info->setHTTPDataDirection(flow->getFlowDirection());

	return;
}


void HTTPProtocol::increaseAllocatedMemory(int number) {

	info_cache_->create(number);
	uri_cache_->create(number);
	host_cache_->create(number);
	ua_cache_->create(number);
	ct_cache_->create(number);
	file_cache_->create(number);
}

void HTTPProtocol::decreaseAllocatedMemory(int number) {

	info_cache_->destroy(number);
	uri_cache_->destroy(number);
	host_cache_->destroy(number);
	ua_cache_->destroy(number);
	ct_cache_->destroy(number);
	file_cache_->destroy(number);
}

void HTTPProtocol::setDomainNameManager(const SharedPointer<DomainNameManager> &dm) { 

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

void HTTPProtocol::statistics(std::basic_ostream<char> &out, int level) {

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
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ << "\n";
		out << "\t" << "Total L7 bytes:     " << std::setw(14) << total_l7_bytes_ << std::endl;
		if (level > 1) {
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << std::endl;
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << std::endl;
			if (level > 3) { 
				out << "\t" << "Total allow hosts:      " << std::setw(10) << total_allow_hosts_ << "\n";
				out << "\t" << "Total banned hosts:     " << std::setw(10) << total_ban_hosts_ << "\n";
                                out << "\t" << "Total requests:         " << std::setw(10) << total_requests_ << "\n";
                                out << "\t" << "Total responses:        " << std::setw(10) << total_responses_ << "\n";
				out << "\t" << "HTTP Methods" << "\n";
				out << "\t" << "Total gets:             " << std::setw(10) << total_gets_ << "\n";
				out << "\t" << "Total post:             " << std::setw(10) << total_posts_ << "\n";
				out << "\t" << "Total heads:            " << std::setw(10) << total_heads_ << "\n";
				out << "\t" << "Total connects:         " << std::setw(10) << total_connects_ << "\n";
				out << "\t" << "Total options:          " << std::setw(10) << total_options_ << "\n";
				out << "\t" << "Total puts:             " << std::setw(10) << total_puts_ << "\n";
				out << "\t" << "Total deletes:          " << std::setw(10) << total_deletes_ << "\n";
				out << "\t" << "Total traces:           " << std::setw(10) << total_traces_ << "\n";
                                out << "\t" << "Total others:           " << std::setw(10) << total_http_others_ << std::endl;
				if (level > 4) {
					out << "\t" << "HTTP Responses" << std::endl;
					for (auto &res: responses_) {
						auto item = std::get<1>(res);
						const char *label = std::get<0>(item);
						int32_t hits = std::get<1>(item);
                                        
						out << "\t" << "Total " << label << ":" << std::right << std::setfill(' ') << std::setw(35 - strlen(label)) << hits << std::endl;
					}
				}
			}
			if (level > 2) {
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
				if (level > 3) {
					info_cache_->statistics(out);
					uri_cache_->statistics(out);
					host_cache_->statistics(out);
					ua_cache_->statistics(out);
					ct_cache_->statistics(out);
					file_cache_->statistics(out);

					if (level > 4) {
						showCacheMap(out, "\t", uri_map_, "HTTP Uris", "Uri");
						showCacheMap(out, "\t", host_map_, "HTTP Hosts", "Host");
						showCacheMap(out, "\t", ua_map_, "HTTP UserAgents", "UserAgent");
						showCacheMap(out, "\t", ct_map_, "HTTP ContentTypes", "ContentType");
						showCacheMap(out, "\t", file_map_, "HTTP Filenames", "Filename");
					}
				}
			}
		}
	}
}

CounterMap HTTPProtocol::getCounters() const {
	CounterMap cm;

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
        cm.addKeyValue("L7 bytes", total_l7_bytes_);
	cm.addKeyValue("allow hosts", total_allow_hosts_);
	cm.addKeyValue("banned hosts", total_ban_hosts_);
	cm.addKeyValue("requests", total_requests_);
	cm.addKeyValue("responses", total_responses_);

	cm.addKeyValue("gets", total_gets_);
	cm.addKeyValue("posts", total_posts_);
	cm.addKeyValue("heads", total_heads_);
	cm.addKeyValue("connects", total_connects_);
	cm.addKeyValue("options", total_options_);
	cm.addKeyValue("puts", total_puts_);
	cm.addKeyValue("deletes", total_deletes_);
	cm.addKeyValue("traces", total_traces_);
	cm.addKeyValue("others", total_http_others_);

        return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
#if defined(PYTHON_BINDING)
boost::python::dict HTTPProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE HTTPProtocol::getCache() const {
#endif
        return addMapToHash(host_map_);
}

#if defined(PYTHON_BINDING)
void HTTPProtocol::showCache(std::basic_ostream<char> &out) const {
	
	showCacheMap(out, "", host_map_, "HTTP Hosts", "Host");
}
#endif

#endif

} // namespace aiengine 
