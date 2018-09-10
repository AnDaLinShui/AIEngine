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

// gets rid of annoying "deprecated conversion from string constant blah blah" warning
#pragma GCC diagnostic ignored "-Wwrite-strings"

#ifndef SRC_PROTOCOLS_TCPGENERIC_TCPGENERICPROTOCOL_H_
#define SRC_PROTOCOLS_TCPGENERIC_TCPGENERICPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "FlowRegexEvaluator.h"
#include "regex/RegexManager.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>

namespace aiengine {

class TCPGenericProtocol: public Protocol {
public:
    	explicit TCPGenericProtocol();
    	virtual ~TCPGenericProtocol(); 

	static constexpr char *default_name = "TCPGenericProtocol";	
	static const uint16_t id = 0;
	static const int header_size = 0;

	int getHeaderSize() const { return header_size;}

	bool processPacket(Packet &packet) override { return true; }
	void processFlow(Flow *flow) override;
	
	void statistics(std::basic_ostream<char> &out, int level) override;

        void releaseCache() override {} // No need to free cache

        void setHeader(const uint8_t *raw_packet) override {
        
                header_ = raw_packet;
        }

	// Condition for say that a payload is for generic tcp 
	// Accepts all!
	bool tcpGenericChecker(Packet &packet);

	void setRegexManager(const SharedPointer<RegexManager> &rm);
	const uint8_t *getPayload() const { return header_;}

	int64_t getCurrentUseMemory() const override { return sizeof(TCPGenericProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(TCPGenericProtocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(TCPGenericProtocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	int32_t getTotalEvents() const override { return eval_.getTotalMatches(); }

	CounterMap getCounters() const override; 

private:
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
	const uint8_t *header_;
	SharedPointer<RegexManager> rm_;
	FlowRegexEvaluator eval_;
};

typedef std::shared_ptr<TCPGenericProtocol> TCPGenericProtocolPtr;
typedef std::weak_ptr<TCPGenericProtocol> TCPGenericProtocolPtrWeak;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_TCPGENERIC_TCPGENERICPROTOCOL_H_
