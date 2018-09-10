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
#ifndef SRC_PROTOCOLS_ICMP_ICMPPROTOCOL_H_
#define SRC_PROTOCOLS_ICMP_ICMPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace aiengine {

class ICMPProtocol: public Protocol {
public:
    	explicit ICMPProtocol();
    	virtual ~ICMPProtocol() {}

	static const uint16_t id = IPPROTO_ICMP;
	static const int header_size = 8;

	int getHeaderSize() const { return header_size; }

	void processFlow(Flow *flow) override { /* No flow to manage */ } 
	bool processPacket(Packet &packet) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override {} // No need to free cache

        void setHeader(const uint8_t *raw_packet) override { 
       
#if defined(__FREEBSD__) || defined(__OPENBSD__) || defined(__DARWIN__)
                header_ = reinterpret_cast <const icmp*> (raw_packet);
#else
                header_ = reinterpret_cast <const icmphdr*> (raw_packet);
#endif
        }

	// Condition for say that a packet is icmp 
	bool icmpChecker(Packet &packet); 
	
#if defined(__FREEBSD__) || defined(__OPENBSD__) || defined(__DARWIN__)
        uint8_t getType() const { return header_->icmp_type; }
        uint8_t getCode() const { return header_->icmp_code; }
        uint16_t getId() const { return ntohs(header_->icmp_id); }
        uint16_t getSequence() const { return ntohs(header_->icmp_seq); }
#else
        uint8_t getType() const { return header_->type; }
        uint8_t getCode() const { return header_->code; }
        uint16_t getId() const { return ntohs(header_->un.echo.id); }
        uint16_t getSequence() const { return ntohs(header_->un.echo.sequence); }
#endif

	int64_t getCurrentUseMemory() const override { return sizeof(ICMPProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(ICMPProtocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(ICMPProtocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	CounterMap getCounters() const override; 

private:
#if defined(__FREEBSD__) || defined(__OPENBSD__) || defined(__DARWIN__)
	const icmp *header_;
#else
	const icmphdr *header_;
#endif 
        int32_t total_echo_request_;
        int32_t total_echo_replay_;
        int32_t total_destination_unreachable_;
        int32_t total_source_quench_; // Router with congestion
        int32_t total_redirect_;
        int32_t total_router_advertisment_;
        int32_t total_router_solicitation_;
	int32_t total_ttl_exceeded_;
        int32_t total_timestamp_request_;
        int32_t total_timestamp_replay_;
        int32_t total_others_;
};

typedef std::shared_ptr<ICMPProtocol> ICMPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_ICMP_ICMPPROTOCOL_H_
