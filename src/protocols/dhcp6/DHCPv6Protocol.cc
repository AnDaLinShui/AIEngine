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
#include "DHCPv6Protocol.h"
#include <iomanip>

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr DHCPv6Protocol::logger(log4cxx::Logger::getLogger("aiengine.dhcpv6"));
#endif

DHCPv6Protocol::DHCPv6Protocol():
	Protocol("DHCPv6Protocol", "dhcp6", IPPROTO_UDP),
        header_(nullptr),
        total_dhcpv6_solicit_(0),
        total_dhcpv6_advertise_(0),
        total_dhcpv6_request_(0),
        total_dhcpv6_confirm_(0),
        total_dhcpv6_renew_(0),
        total_dhcpv6_rebind_(0),
        total_dhcpv6_reply_(0),
        total_dhcpv6_release_(0),
        total_dhcpv6_decline_(0),
        total_dhcpv6_reconfigure_(0),
        total_dhcpv6_info_request_(0),
        total_dhcpv6_relay_forw_(0),
        total_dhcpv6_relay_repl_(0),
        info_cache_(new Cache<DHCPv6Info>("DHCPv6 Info cache")),
        host_cache_(new Cache<StringCache>("Host cache")),
        ip6_cache_(new Cache<StringCache>("IPv6 cache")),
        host_map_(),
        ip6_map_(),
	flow_mng_(),
        current_flow_(nullptr),
        anomaly_() {}

bool DHCPv6Protocol::dhcpv6Checker(Packet &packet) {

	int length = packet.getLength();

	if (length >= header_size) {
		if ((packet.getDestinationPort() == 547)||(packet.getDestinationPort() == 546)) {
			setHeader(packet.getPayload());
			++total_valid_packets_;
			return true;
		}
	}
	++total_invalid_packets_;
	return false;
}


void DHCPv6Protocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);
	host_cache_->setDynamicAllocatedMemory(value);
	ip6_cache_->setDynamicAllocatedMemory(value);
}

bool DHCPv6Protocol::isDynamicAllocatedMemory() const {

	return info_cache_->isDynamicAllocatedMemory();
}

int32_t DHCPv6Protocol::release_dhcp6_info(DHCPv6Info *info) {

        int32_t bytes_released = 0;

	bytes_released = releaseStringToCache(host_cache_, info->host_name);
	bytes_released += releaseStringToCache(ip6_cache_, info->ip6);

        return bytes_released;
}

int64_t DHCPv6Protocol::getCurrentUseMemory() const {

	int64_t mem = sizeof(DHCPv6Protocol);

	mem += info_cache_->getCurrentUseMemory();
	mem += host_cache_->getCurrentUseMemory();
	mem += ip6_cache_->getCurrentUseMemory();
	
	return mem;
}

int64_t DHCPv6Protocol::getAllocatedMemory() const {

        int64_t mem = sizeof(DHCPv6Protocol);

        mem += info_cache_->getAllocatedMemory();
        mem += host_cache_->getAllocatedMemory();
        mem += ip6_cache_->getAllocatedMemory();

        return mem;
}

int64_t DHCPv6Protocol::getTotalAllocatedMemory() const {

        return getAllocatedMemory();
}

int64_t DHCPv6Protocol::compute_memory_used_by_maps() const {

	int64_t bytes = host_map_.size() * sizeof(StringCacheHits);

	bytes += ip6_map_.size() * sizeof(StringCacheHits);

	std::for_each (host_map_.begin(), host_map_.end(), [&bytes] (PairStringCacheHits const &f) {
		bytes += f.first.size();
	});
	std::for_each (ip6_map_.begin(), ip6_map_.end(), [&bytes] (PairStringCacheHits const &f) {
		bytes += f.first.size();
	});

	return bytes;
}

int32_t DHCPv6Protocol::getTotalCacheMisses() const {

	int32_t miss = 0;

	miss = info_cache_->getTotalFails();
	miss += host_cache_->getTotalFails();
	miss += ip6_cache_->getTotalFails();

	return miss;
}

void DHCPv6Protocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

                int64_t total_bytes_released = compute_memory_used_by_maps();
                int64_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;
                int32_t release_host = host_map_.size();
                int32_t release_ips = ip6_map_.size();

                for (auto &flow: ft) {
                        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
                        if (info) {
                                total_bytes_released_by_flows = release_dhcp6_info(info.get());
                                total_bytes_released_by_flows += sizeof(info);

                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(info);
                        }
                }
                host_map_.clear();
		ip6_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_host << " host names, " << release_ips << " ips, "  << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}

void DHCPv6Protocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getDHCPv6Info();
	if (info) {
		info_cache_->release(info);
	}
}

void DHCPv6Protocol::attach_host_name(DHCPv6Info *info, const boost::string_ref &name) {

        if (!info->host_name) {
                GenericMapType::iterator it = host_map_.find(name);
                if (it == host_map_.end()) {
                        SharedPointer<StringCache> host_ptr = host_cache_->acquire();
                        if (host_ptr) {
                                host_ptr->setName(name.data(), name.length());
                                info->host_name = host_ptr;
                                host_map_.insert(std::make_pair(host_ptr->getName(), host_ptr));
                        }
                } else {
                        ++ (it->second).hits;
                        info->host_name = (it->second).sc;
                }
        }
}

void DHCPv6Protocol::attach_ip(DHCPv6Info *info, const boost::string_ref &ip) {

        if (!info->ip6) {
                GenericMapType::iterator it = ip6_map_.find(ip);
                if (it == ip6_map_.end()) {
                        SharedPointer<StringCache> ip_ptr = ip6_cache_->acquire();
                        if (ip_ptr) {
                                ip_ptr->setName(ip.data(), ip.length());
                                info->ip6 = ip_ptr;
                                ip6_map_.insert(std::make_pair(ip_ptr->getName(), ip_ptr));
                        }
                } else {
                        ++ (it->second).hits;
                        info->ip6 = (it->second).sc;
                }
        }
}

void DHCPv6Protocol::handle_request(DHCPv6Info *info, const uint8_t *payload, int length) {

        int idx = 0;
        while (idx < length) {
		const dhcpv6_option *opt = reinterpret_cast<const dhcpv6_option*>(&payload[idx]); 
        	uint16_t code = ntohs(opt->code);
                uint16_t len = ntohs(opt->len);

		if (idx + len < length) {
			//std::cout << "idx:" << idx << " code:" << code << " len:" << len << std::endl;
                	if (code == 39) { // Fully domain
				boost::string_ref name(reinterpret_cast<const char*>(&(opt->data[0]) + 2), len - 2);

                        	attach_host_name(info, name);
                        	break;
			} else if (code == 3) { // DHCPv6 identity association for non-temporary address
				const dhcpv6_ia_na_option *ia_hdr = reinterpret_cast<const dhcpv6_ia_na_option*>(&(opt->data[0]));
				uint32_t renew = ntohl(ia_hdr->renew);
				uint32_t rebind = ntohl(ia_hdr->rebind);

				if ((renew > 0)and(rebind > 0)) {
					info->setLifetime(renew, rebind);
				}

				const dhcpv6_option *opt = reinterpret_cast<const dhcpv6_option*>(&ia_hdr->options[0]);
				if (ntohs(opt->code) == 5) {	
					const dhcpv6_iaaddr_option *addr_hdr = reinterpret_cast<const dhcpv6_iaaddr_option*>(&opt->data[0]);
					char address6[INET6_ADDRSTRLEN];
                
					inet_ntop(AF_INET6, &(addr_hdr->address), address6, INET6_ADDRSTRLEN);
					
					boost::string_ref addr_ref(address6);

					attach_ip(info, addr_ref);
				}
			}
		}
                idx += sizeof(dhcpv6_option) + (int)len;
	}
}

void DHCPv6Protocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;

	current_flow_ = flow;

	++total_packets_;

        if (length >= header_size) {
                SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
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

		uint8_t type = getType();

		if (type == DHCPV6_SOLICIT) {
			handle_request(info.get(), (uint8_t*)&header_->options, length - header_size);
			++total_dhcpv6_solicit_; 
		} else if (type == DHCPV6_ADVERTISE) {
			++total_dhcpv6_advertise_;
		} else if (type == DHCPV6_REQUEST) {
			++total_dhcpv6_request_;
		} else if (type == DHCPV6_CONFIRM) {
			++total_dhcpv6_confirm_;
		} else if (type == DHCPV6_RENEW) {
			handle_request(info.get(), (uint8_t*)&header_->options, length - header_size);
			++total_dhcpv6_renew_;
		} else if (type == DHCPV6_REBIND) {
			++total_dhcpv6_rebind_;
		} else if (type == DHCPV6_REPLY) {
			handle_request(info.get(), (uint8_t*)&header_->options, length - header_size);
			++total_dhcpv6_reply_;
		} else if (type == DHCPV6_RELEASE) {
			++total_dhcpv6_release_;
		} else if (type == DHCPV6_DECLINE) {
			++total_dhcpv6_decline_;
		} else if (type == DHCPV6_RECONFIGURE) {
			++total_dhcpv6_reconfigure_;
		} else if (type == DHCPV6_INFO_REQUEST) {
			++total_dhcpv6_info_request_;
		} else if (type == DHCPV6_RELAY_FORW) {
			++total_dhcpv6_relay_forw_;
		} else if (type == DHCPV6_RELAY_REPL) {
			++total_dhcpv6_relay_repl_;
		}
	}
}

void DHCPv6Protocol::statistics(std::basic_ostream<char> &out, int level){ 

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
                                out << "\t" << "Total solicits:         " << std::setw(10) << total_dhcpv6_solicit_ << "\n";
                                out << "\t" << "Total advertises:       " << std::setw(10) << total_dhcpv6_advertise_ << "\n";
                                out << "\t" << "Total requests:         " << std::setw(10) << total_dhcpv6_request_ << "\n";
                                out << "\t" << "Total confirms:         " << std::setw(10) << total_dhcpv6_confirm_ << "\n";
                                out << "\t" << "Total renews:           " << std::setw(10) << total_dhcpv6_renew_ << "\n";
                                out << "\t" << "Total rebinds:          " << std::setw(10) << total_dhcpv6_rebind_ << "\n";
                                out << "\t" << "Total replys:           " << std::setw(10) << total_dhcpv6_reply_ << "\n";
                                out << "\t" << "Total releases:         " << std::setw(10) << total_dhcpv6_release_ << "\n";
                                out << "\t" << "Total declines:         " << std::setw(10) << total_dhcpv6_decline_ << "\n";
                                out << "\t" << "Total reconfigures:     " << std::setw(10) << total_dhcpv6_reconfigure_ << "\n";
                                out << "\t" << "Total info requests:    " << std::setw(10) << total_dhcpv6_info_request_ << "\n";
                                out << "\t" << "Total relay forws:      " << std::setw(10) << total_dhcpv6_relay_forw_ << "\n";
                                out << "\t" << "Total relay repls:      " << std::setw(10) << total_dhcpv6_relay_repl_ << std::endl;
                        }
			if (level > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
                                if (level > 3) {
                                        info_cache_->statistics(out);
                                        host_cache_->statistics(out);
                                        ip6_cache_->statistics(out);
                                        if (level > 4) {
                                                showCacheMap(out, "\t", host_map_, "Host names", "Host");
                                                showCacheMap(out, "\t", ip6_map_, "IPv6 Addresses", "IPv6");
                                        }
                                }
			}
		}
	}
}

void DHCPv6Protocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
        host_cache_->create(value);
        ip6_cache_->create(value);
}

void DHCPv6Protocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
        host_cache_->destroy(value);
        ip6_cache_->destroy(value);
}

CounterMap DHCPv6Protocol::getCounters() const {
	CounterMap cm; 

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);

        cm.addKeyValue("solicits", total_dhcpv6_solicit_);
        cm.addKeyValue("advertises", total_dhcpv6_advertise_);
        cm.addKeyValue("requests", total_dhcpv6_request_);
        cm.addKeyValue("confirms", total_dhcpv6_confirm_);
        cm.addKeyValue("renews", total_dhcpv6_renew_);
        cm.addKeyValue("rebinds", total_dhcpv6_rebind_);
        cm.addKeyValue("replys", total_dhcpv6_reply_);
        cm.addKeyValue("releases", total_dhcpv6_release_);
        cm.addKeyValue("declines", total_dhcpv6_decline_);
        cm.addKeyValue("reconfigures", total_dhcpv6_reconfigure_);
        cm.addKeyValue("info requests", total_dhcpv6_info_request_);
        cm.addKeyValue("relay forws", total_dhcpv6_relay_forw_);
        cm.addKeyValue("relay repls", total_dhcpv6_relay_repl_);

        return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
#if defined(PYTHON_BINDING)
boost::python::dict DHCPv6Protocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE DHCPv6Protocol::getCache() const {
#endif
        return addMapToHash(host_map_);
}

#if defined(PYTHON_BINDING)
void DHCPv6Protocol::showCache(std::basic_ostream<char> &out) const {

        showCacheMap(out, "", host_map_, "Host names", "Host");
}
#endif

#endif

} // namespace aiengine
