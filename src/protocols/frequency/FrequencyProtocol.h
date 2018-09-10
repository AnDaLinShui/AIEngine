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
#ifndef SRC_PROTOCOLS_FREQUENCY_FREQUENCYPROTOCOL_H_
#define SRC_PROTOCOLS_FREQUENCY_FREQUENCYPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include "Protocol.h"
#include "Frequencies.h"
#include "PacketFrequencies.h"
#include "Cache.h"
#include "flow/FlowManager.h"

namespace aiengine {

class FrequencyProtocol: public Protocol {
public:
    	explicit FrequencyProtocol(const std::string& name, const std::string& short_name);
	explicit FrequencyProtocol():FrequencyProtocol("FrequencyProtocol", "frequency") {}
    	virtual ~FrequencyProtocol() {}
	
	static const uint16_t id = 0;
	static const int header_size = 2;
	static const int DefaultInspectionLimit = 100; // Number of packets process for compute the frequencies

	int getHeaderSize() const { return header_size;}

	bool processPacket(Packet& packet) override { return true; }
	void processFlow(Flow *flow) override;

	void statistics(std::basic_ostream<char>& out, int level) override;

	void releaseCache() override; 

        void setHeader(const uint8_t *raw_packet) override {
        
                freq_header_ = raw_packet;
        }

	// All the flows are processed by the frequency proto
	bool freqChecker(Packet &packet); 

        void createFrequencies(int number); 
        void destroyFrequencies(int number); 

	void releaseFlowInfo(Flow *flow) override;
	
	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	int64_t getCurrentUseMemory() const override;
	int64_t getAllocatedMemory() const override; 
	int64_t getTotalAllocatedMemory() const override; 

        void setDynamicAllocatedMemory(bool value) override;
	bool isDynamicAllocatedMemory() const override;

	CounterMap getCounters() const override { CounterMap counters; return counters; }

private:
	const uint8_t *freq_header_;
	int inspection_limit_;
	Cache<Frequencies>::CachePtr freqs_cache_;
	Cache<PacketFrequencies>::CachePtr packet_freqs_cache_;
	FlowManagerPtrWeak flow_mng_;
};

typedef std::shared_ptr<FrequencyProtocol> FrequencyProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_FREQUENCY_FREQUENCYPROTOCOL_H_
