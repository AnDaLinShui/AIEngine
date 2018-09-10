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
#include "FrequencyProtocol.h"
#include <iomanip> // setw

namespace aiengine {

FrequencyProtocol::FrequencyProtocol(const std::string &name, const std::string &short_name):
	Protocol(name, short_name),
	freq_header_(nullptr),
	inspection_limit_(DefaultInspectionLimit),
	freqs_cache_(new Cache<Frequencies>("Frequencies cache")),
	packet_freqs_cache_(new Cache<PacketFrequencies>("Packet frequencies cache")),
	flow_mng_() {} 

bool FrequencyProtocol::freqChecker(Packet &packet) {

	setHeader(packet.getPayload());
	++total_valid_packets_;
	return true;
}

void FrequencyProtocol::createFrequencies(int number) {

	freqs_cache_->create(number);
	packet_freqs_cache_->create(number);
}

void FrequencyProtocol::destroyFrequencies(int number) {

	freqs_cache_->destroy(number);
	packet_freqs_cache_->destroy(number);
}


void FrequencyProtocol::setDynamicAllocatedMemory(bool value) {

	freqs_cache_->setDynamicAllocatedMemory(value);
	packet_freqs_cache_->setDynamicAllocatedMemory(value);
}

bool FrequencyProtocol::isDynamicAllocatedMemory() const {

	return freqs_cache_->isDynamicAllocatedMemory();	
}

int64_t FrequencyProtocol::getCurrentUseMemory() const {

	int64_t mem = sizeof(FrequencyProtocol);

	mem += freqs_cache_->getCurrentUseMemory();
	mem += packet_freqs_cache_->getCurrentUseMemory();
	
	return mem;
}

int64_t FrequencyProtocol::getAllocatedMemory() const {

        int64_t mem = sizeof(FrequencyProtocol);

        mem += freqs_cache_->getAllocatedMemory();
        mem += packet_freqs_cache_->getAllocatedMemory();

        return mem;
}

int64_t FrequencyProtocol::getTotalAllocatedMemory() const {

	return getAllocatedMemory();
}

void FrequencyProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

                int64_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;

                for (auto &flow: ft) {
                        SharedPointer<Frequencies> freq = flow->frequencies;
                	SharedPointer<PacketFrequencies> pkt_freq = flow->packet_frequencies;
			bool have_release = false;

                        if (freq) { // The flow have frequencies attached
                                flow->frequencies.reset();
                                total_bytes_released_by_flows += 255; // Sizeof Frequencies class 
                                freqs_cache_->release(freq);
				have_release = true;
                        }

                        if (pkt_freq) { // The flow have packet frequencies attached
                                flow->packet_frequencies.reset();
                                total_bytes_released_by_flows += MAX_PACKET_FREQUENCIES_VALUES; // Sizeof PacketFrequencies class aprox 
                                packet_freqs_cache_->release(pkt_freq);
				have_release = true;
                        }
			if (have_release) ++release_flows;
                }

                msg.str("");
                msg << "Release " << release_flows << " flows";
                msg << ", " << total_bytes_released_by_flows << " bytes";
                infoMessage(msg.str());
        }
}

void FrequencyProtocol::releaseFlowInfo(Flow *flow) {

	auto finfo = flow->frequencies;
	if (finfo) {
		freqs_cache_->release(finfo);
	}
	auto pinfo = flow->packet_frequencies;
	if (pinfo) {
		packet_freqs_cache_->release(pinfo);
	}
}

void FrequencyProtocol::processFlow(Flow *flow) {

	++total_packets_;
	total_bytes_ += flow->packet->getLength();
	++flow->total_packets_l7;

	if (flow->total_packets < inspection_limit_) {

		SharedPointer<Frequencies> freq = flow->frequencies;

		if (!freq) { // There is no Frequency object attached to the flow
			freq = freqs_cache_->acquire();
			if (freq)
				flow->frequencies = freq;
		} 

		if (freq) 
			freq->addPayload(flow->packet->getPayload(), flow->packet->getLength());		

                SharedPointer<PacketFrequencies> pkt_freq = flow->packet_frequencies;

                if (!pkt_freq) { // There is no Frequency object attached to the flow
                        pkt_freq = packet_freqs_cache_->acquire();
                        if (pkt_freq)
                                flow->packet_frequencies = pkt_freq;
                }
		if (freq) 
                        pkt_freq->addPayload(flow->packet->getPayload(), flow->packet->getLength());
	}
}

void FrequencyProtocol::statistics(std::basic_ostream<char>& out, int level) {

	if (level > 0) {
                int64_t alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory, unit);

                out << getName() << "(" << this <<") statistics" << std::dec << std::endl;
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ << std::endl;
		if (level > 1) {
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << std::endl;
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << std::endl;	
			if (level > 2) {
        			if (flow_forwarder_.lock())
                			flow_forwarder_.lock()->statistics(out);

                                if (level > 3) {
                                        freqs_cache_->statistics(out);
                                        packet_freqs_cache_->statistics(out);
				}
			}
		}
	}
}

} // namespace aiengine
