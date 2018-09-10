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
#include "SSHProtocol.h"
#include <iomanip>

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr SSHProtocol::logger(log4cxx::Logger::getLogger("aiengine.ssh"));
#endif

SSHProtocol::SSHProtocol():
	Protocol("SSHProtocol", "ssh", IPPROTO_TCP),
	header_(nullptr),
	total_encrypted_bytes_(0),
	total_encrypted_packets_(0),
	total_handshake_pdus_(0),
        total_algorithm_negotiation_messages_(0),
        total_key_exchange_messages_(0),
        total_others_(0),
	info_cache_(new Cache<SSHInfo>("SSH Info cache")),
	flow_mng_(),
	current_flow_(nullptr) {}

bool SSHProtocol::is_minimal_ssh_header(const uint8_t *hdr) {

        if ((hdr[0] == 'S')and(hdr[1] == 'S')and(hdr[2] == 'H')and 
                (hdr[3] == '-')and(hdr[4] == '2')) {
        	return true;
        }
        return false;
}

bool SSHProtocol::sshChecker(Packet &packet) {

        int length = packet.getLength();

        if (length >= 8) {
                setHeader(packet.getPayload());

                if (is_minimal_ssh_header(header_)) {
                        ++total_valid_packets_;
                        return true;
                }
        }
        ++total_invalid_packets_;
        return false;
}

void SSHProtocol::setDynamicAllocatedMemory(bool value) {

        info_cache_->setDynamicAllocatedMemory(value);
}

bool SSHProtocol::isDynamicAllocatedMemory() const {

        return info_cache_->isDynamicAllocatedMemory();
}

int64_t SSHProtocol::getCurrentUseMemory() const {

        int64_t mem = sizeof(SSHProtocol);

        mem += info_cache_->getCurrentUseMemory();

        return mem;
}

int64_t SSHProtocol::getAllocatedMemory() const {

        int64_t mem = sizeof(SSHProtocol);

        mem += info_cache_->getAllocatedMemory();

        return mem;
}

int64_t SSHProtocol::getTotalAllocatedMemory() const {

	return getAllocatedMemory();
}

int32_t SSHProtocol::getTotalCacheMisses() const {

        int32_t miss = 0;

        miss = info_cache_->getTotalFails();

        return miss;
}

void SSHProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

                int64_t total_bytes_released = 0;
                int64_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;

                for (auto &flow: ft) {
                        SharedPointer<SSHInfo> info = flow->getSSHInfo();
                        if (info) {
                                total_bytes_released_by_flows += sizeof(info);

                                ++release_flows;
                                flow->layer7info.reset();
                                info_cache_->release(info);
                        }
                } 

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_flows << " flows"; 
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}

void SSHProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getSSHInfo();
	if (info) {
		info_cache_->release(info);
	}
}

void SSHProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;
	++flow->total_packets_l7;

	current_flow_ = flow;

        SharedPointer<SSHInfo> info = flow->getSSHInfo();
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

#ifdef DEBUG
	std::cout << __FILE__ << ":" << __func__ << ":" << *flow << " pkts:" << flow->total_packets << std::endl;
#endif

	if (length >= header_size) {
		if (flow->total_packets_l7 > 2) { // Client and server hello done 
			if (info->isHandshake()) {
				const uint8_t *payload = flow->packet->getPayload();
				int32_t offset = 0;

				do {
					const ssh_header *hdr = reinterpret_cast<const ssh_header*>(&payload[offset]);

					uint32_t len = ntohl(hdr->length);
					int8_t msg_type = (int8_t)hdr->data[0];

					offset += len + sizeof(ssh_header) - 1;

					++total_handshake_pdus_;

					if ((msg_type >= 20)and(msg_type <= 29)) {
						++total_algorithm_negotiation_messages_;
					} else if ((msg_type >= 30)and(msg_type <= 49)) {
						++total_key_exchange_messages_;
					} else {
						++total_others_;
					}

					if (msg_type == 21) { // New keys
						if (flow->getFlowDirection() == FlowDirection::FORWARD) {
							info->setClientHandshake(false);
						} else { 
							info->setServerHandshake(false);
						}
					}

				} while ((offset < length)and(offset > 0));
			} else {
				// The flow is on encryption mode :)
				info->addEncryptedBytes(length);
				total_encrypted_bytes_ += length;
				++total_encrypted_packets_;
			}
		}
	}
}

void SSHProtocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
}

void SSHProtocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
}

void SSHProtocol::statistics(std::basic_ostream<char>& out, int level) { 

	if (level > 0) {
                int64_t alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";
		const char *dynamic_memory = (isDynamicAllocatedMemory() ? "yes":"no");

                unitConverter(alloc_memory, unit);

                out << getName() << "(" << this <<") statistics" << std::dec << std::endl;
		out << "\t" << "Dynamic memory alloc:   " << std::setw(10) << dynamic_memory << std::endl;
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ << std::endl;
		if (level > 1) {
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << std::endl;
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << std::endl;
			if (level > 3) {
                                out << "\t" << "Total encrypted bytes:  " << std::setw(10) << total_encrypted_bytes_ << std::endl;
                                out << "\t" << "Total encrypted packets:" << std::setw(10) << total_encrypted_packets_ << std::endl;
                                out << "\t" << "Total other packets:    " << std::setw(10) << total_others_ << std::endl;
                        }
			if (level > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
                        }
		}
	}
}

CounterMap SSHProtocol::getCounters() const {
       	CounterMap cm;
 
        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
        cm.addKeyValue("encrypted bytes", total_encrypted_bytes_);
        cm.addKeyValue("encrypted packets", total_encrypted_packets_);

        return cm;
}

} // namespace aiengine
