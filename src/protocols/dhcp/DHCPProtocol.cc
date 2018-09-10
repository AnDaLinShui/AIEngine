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
#include "DHCPProtocol.h"
#include <iomanip>

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr DHCPProtocol::logger(log4cxx::Logger::getLogger("aiengine.dhcp"));
#endif

DHCPProtocol::DHCPProtocol():
	Protocol("DHCPProtocol", "dhcp", IPPROTO_UDP),
        header_(nullptr),
        total_dhcp_discover_(0),
        total_dhcp_offer_(0),
        total_dhcp_request_(0),
        total_dhcp_decline_(0),
        total_dhcp_ack_(0),
        total_dhcp_nak_(0),
        total_dhcp_release_(0),
        total_dhcp_inform_(0), 
        info_cache_(new Cache<DHCPInfo>("DHCP Info cache")),
        host_cache_(new Cache<StringCache>("Host cache")),
        ip_cache_(new Cache<StringCache>("IP cache")),
        host_map_(),
        ip_map_(),
	flow_mng_(),
        current_flow_(nullptr),
        anomaly_() {}

bool DHCPProtocol::dhcpChecker(Packet &packet) {

	int length = packet.getLength();

	if (length >= header_size) {
		if ((packet.getSourcePort() == 67)||(packet.getDestinationPort() == 67)) {
			setHeader(packet.getPayload());
			++total_valid_packets_;
			return true;
		}
	}
	++total_invalid_packets_;
	return false;
}


void DHCPProtocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);
	host_cache_->setDynamicAllocatedMemory(value);
	ip_cache_->setDynamicAllocatedMemory(value);
}

bool DHCPProtocol::isDynamicAllocatedMemory() const {

	return info_cache_->isDynamicAllocatedMemory();
}

int32_t DHCPProtocol::release_dhcp_info(DHCPInfo *info) {

        int32_t bytes_released = 0;

	bytes_released = releaseStringToCache(host_cache_, info->host_name);
	bytes_released += releaseStringToCache(ip_cache_, info->ip);

        return bytes_released;
}

int64_t DHCPProtocol::getCurrentUseMemory() const {

	int64_t mem = sizeof(DHCPProtocol);

	mem += info_cache_->getCurrentUseMemory();
	mem += host_cache_->getCurrentUseMemory();
	mem += ip_cache_->getCurrentUseMemory();
	
	return mem;
}

int64_t DHCPProtocol::getAllocatedMemory() const {

        int64_t mem = sizeof(DHCPProtocol);

        mem += info_cache_->getAllocatedMemory();
        mem += host_cache_->getAllocatedMemory();
        mem += ip_cache_->getAllocatedMemory();

        return mem;
}

int64_t DHCPProtocol::getTotalAllocatedMemory() const {

        int64_t mem = getAllocatedMemory();

        mem += compute_memory_used_by_maps();

        return mem;
}

int64_t DHCPProtocol::compute_memory_used_by_maps() const {

	int64_t bytes = host_map_.size() * sizeof(StringCacheHits);

	bytes += ip_map_.size() * sizeof(StringCacheHits);

	std::for_each (host_map_.begin(), host_map_.end(), [&bytes] (PairStringCacheHits const &f) {
		bytes += f.first.size();
	});
	std::for_each (ip_map_.begin(), ip_map_.end(), [&bytes] (PairStringCacheHits const &f) {
		bytes += f.first.size();
	});

	return bytes;
}

int32_t DHCPProtocol::getTotalCacheMisses() const {

	int32_t miss = 0;

	miss = info_cache_->getTotalFails();
	miss += host_cache_->getTotalFails();
	miss += ip_cache_->getTotalFails();

	return miss;
}

void DHCPProtocol::releaseCache() {

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
		int32_t release_ips = ip_map_.size();

                for (auto &flow: ft) {
                        SharedPointer<DHCPInfo> info = flow->getDHCPInfo();
                        if (info) {
                                total_bytes_released_by_flows = release_dhcp_info(info.get());
                                total_bytes_released_by_flows += sizeof(info);

                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(info);
                        }
                }
                host_map_.clear();
		ip_map_.clear();

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

void DHCPProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getDHCPInfo();
	if (info) {
		info_cache_->release(info);
	}
}

void DHCPProtocol::attach_host_name(DHCPInfo *info, const boost::string_ref &name) {

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

void DHCPProtocol::attach_ip(DHCPInfo *info, const boost::string_ref &ip) {

        if (!info->ip) {
                GenericMapType::iterator it = ip_map_.find(ip);
                if (it == ip_map_.end()) {
                        SharedPointer<StringCache> ip_ptr = ip_cache_->acquire();
                        if (ip_ptr) {
                                ip_ptr->setName(ip.data(), ip.length());
                                info->ip = ip_ptr;
                                ip_map_.insert(std::make_pair(ip_ptr->getName(), ip_ptr));
                        }
                } else {
                        ++ (it->second).hits;
                        info->ip = (it->second).sc;
                }
        }
}

void DHCPProtocol::handle_request(DHCPInfo *info, const uint8_t *payload, int length) {

        int idx = 0;
        while (idx < length - 4) {
        	short type = payload[idx];
                short len = payload[idx + 1];

                if (type == 12) { // Hostname
			boost::string_ref name(reinterpret_cast<const char*>(&payload[idx + 2]), len);

                        attach_host_name(info, name);
                        break;
		}
                idx += 2 + (int)len;
	}
}

void DHCPProtocol::handle_reply(DHCPInfo *info, const uint8_t *payload, int length) {

        int idx = 0;
        while (idx < length - 8) {
                short type = payload[idx];
                short len = payload[idx + 1];
		
                if (type == 51) { // IP Lease time
			int32_t lease_time = (payload[idx + 2] << 24) | (payload[idx + 3] << 16) | (payload[idx + 4] << 8) | payload[idx + 5];

			info->setLeaseTime(lease_time);
                        break;
                }
                idx += 2 + (int)len;
        }
}

void DHCPProtocol::handle_ip_address(DHCPInfo *info) {

	in_addr a; 
	a.s_addr = header_->yiaddr;
	char *ipstr = inet_ntoa(a);
	boost::string_ref ipref(ipstr);

	attach_ip(info, ipref);
}

void DHCPProtocol::processFlow(Flow *flow) {

	setHeader(flow->packet->getPayload());	
	uint8_t msgtype = getType();
	int length = flow->packet->getLength();
	total_bytes_ += length;

	current_flow_ = flow;

	++total_packets_;

	// if there is no magic, then there is no request
	if ((length > header_size)and(header_->magic[0] == 0x63)and(header_->magic[1] == 0x82)and
		(header_->magic[2] == 0x53)and(header_->magic[3] == 0x63)) {

                SharedPointer<DHCPInfo> info = flow->getDHCPInfo();
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

		int options_length = length - header_size;
		const uint8_t *optpayload = &header_->opt[0];

		short otype = optpayload[0];
		if (otype == 53) { // Extract the dhcp message type
			short type = optpayload[2];

			if (type == DHCPDISCOVER) {
				++total_dhcp_discover_;
			} else if (type == DHCPOFFER) {
				++total_dhcp_offer_;
				// Extract the IP
				handle_ip_address(info.get());
			} else if (type == DHCPREQUEST) {
				++total_dhcp_request_;
			} else if (type == DHCPDECLINE) {
				++total_dhcp_decline_;
			} else if (type == DHCPACK) {
				++total_dhcp_ack_;
			} else if (type == DHCPNAK) {
				++total_dhcp_nak_;
			} else if (type == DHCPRELEASE) {
				++total_dhcp_release_;
			} else if (type == DHCPINFORM) {
				++total_dhcp_inform_;
                	}
		}	

		if (msgtype == DHCP_BOOT_REQUEST) {
			handle_request(info.get(), optpayload, options_length);
		} else {
			handle_reply(info.get(), optpayload, options_length);
		}
	} else {
		// Malformed DHCP packet
                if (flow->getPacketAnomaly() == PacketAnomalyType::NONE) {
                	flow->setPacketAnomaly(PacketAnomalyType::DHCP_BOGUS_HEADER);
                }
                anomaly_->incAnomaly(PacketAnomalyType::DHCP_BOGUS_HEADER);
	}
}

void DHCPProtocol::statistics(std::basic_ostream<char> &out, int level){ 

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
                                out << "\t" << "Total discovers:        " << std::setw(10) << total_dhcp_discover_ << "\n";
                                out << "\t" << "Total offers:           " << std::setw(10) << total_dhcp_offer_ << "\n";
                                out << "\t" << "Total requests:         " << std::setw(10) << total_dhcp_request_ << "\n";
                                out << "\t" << "Total declines:         " << std::setw(10) << total_dhcp_decline_ << "\n";
                                out << "\t" << "Total acks:             " << std::setw(10) << total_dhcp_ack_ << "\n";
                                out << "\t" << "Total naks:             " << std::setw(10) << total_dhcp_nak_ << "\n";
                                out << "\t" << "Total releases:         " << std::setw(10) << total_dhcp_release_ << "\n";
                                out << "\t" << "Total informs:          " << std::setw(10) << total_dhcp_inform_ << std::endl;
                        }
			if (level > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
                                if (level > 3) {
                                        info_cache_->statistics(out);
                                        host_cache_->statistics(out);
                                        ip_cache_->statistics(out);
                                        if (level > 4) {
                                                showCacheMap(out, "\t", host_map_, "Host names", "Host");
                                                showCacheMap(out, "\t", ip_map_, "IP Address", "IP");
                                        }
                                }
			}
		}
	}
}

void DHCPProtocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
        host_cache_->create(value);
        ip_cache_->create(value);
}

void DHCPProtocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
        host_cache_->destroy(value);
        ip_cache_->destroy(value);
}

CounterMap DHCPProtocol::getCounters() const {
	CounterMap cm; 

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
        cm.addKeyValue("discovers", total_dhcp_discover_);
        cm.addKeyValue("offers", total_dhcp_offer_);
        cm.addKeyValue("requests", total_dhcp_request_);
        cm.addKeyValue("declines", total_dhcp_decline_);
        cm.addKeyValue("acks", total_dhcp_ack_);
        cm.addKeyValue("naks", total_dhcp_nak_);
        cm.addKeyValue("releases", total_dhcp_release_);
        cm.addKeyValue("informs", total_dhcp_inform_);

        return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
#if defined(PYTHON_BINDING)
boost::python::dict DHCPProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE DHCPProtocol::getCache() const {
#endif
        return addMapToHash(host_map_);
}

#if defined(PYTHON_BINDING)
void DHCPProtocol::showCache(std::basic_ostream<char> &out) const {

	showCacheMap(out, "", host_map_, "Host names", "Host");

}
#endif

#endif

} // namespace aiengine
