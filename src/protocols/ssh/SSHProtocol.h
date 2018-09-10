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
#ifndef SRC_PROTOCOLS_SSH_SSHPROTOCOL_H_
#define SRC_PROTOCOLS_SSH_SSHPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <arpa/inet.h>
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "flow/FlowManager.h"
#include "Cache.h"

namespace aiengine {

struct ssh_header {
	uint32_t 	length;   	/* payload length */
    	uint8_t 	padding;        /* padding */
	uint8_t 	data[0];       
} __attribute__((packed));

// Some of the most common message types

class SSHProtocol: public Protocol {
public:
    	explicit SSHProtocol();
    	virtual ~SSHProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(ssh_header);

	int getHeaderSize() const { return header_size;}

        void processFlow(Flow *flow) override;
        bool processPacket(Packet& packet) override { return true; } 

	void statistics(std::basic_ostream<char>& out, int level) override;

	void releaseCache() override; 

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = raw_packet;
	}

	// Condition for say that a packet is ssh 
	bool sshChecker(Packet &packet); 
	
	// Protocol specific

	int64_t getCurrentUseMemory() const override; 
	int64_t getAllocatedMemory() const override;
	int64_t getTotalAllocatedMemory() const override;

        void setDynamicAllocatedMemory(bool value) override;
        bool isDynamicAllocatedMemory() const override;

        int32_t getTotalCacheMisses() const override;

        void increaseAllocatedMemory(int value) override;
        void decreaseAllocatedMemory(int value) override;

        void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	CounterMap getCounters() const override; 

	Flow *getCurrentFlow() const { return current_flow_; }

	void releaseFlowInfo(Flow *flow) override;

#if defined(STAND_ALONE_TEST) || defined(TESTING)
        int32_t getTotalHandshakePDUs() const { return total_handshake_pdus_; }
	int32_t getTotalAlgorithmNegotiationMessages() const { return total_algorithm_negotiation_messages_; }
	int32_t getTotalKeyExchangeMessages() const { return total_key_exchange_messages_; }
	int32_t getTotalOthers() const { return total_others_; }

	int64_t getTotalEncryptedBytes() const { return total_encrypted_bytes_; }
	int32_t getTotalEncryptedPackets() const { return total_encrypted_packets_; }
#endif

private:
	bool is_minimal_ssh_header(const uint8_t *hdr);

	const uint8_t *header_;

	// Some statistics 
	int64_t total_encrypted_bytes_;
	int32_t total_encrypted_packets_;
	int32_t total_handshake_pdus_;
	int32_t total_algorithm_negotiation_messages_; // messages from 20 to 29
	int32_t total_key_exchange_messages_; // messages from 30 to 49
	int32_t total_others_;

	Cache<SSHInfo>::CachePtr info_cache_;

	FlowManagerPtrWeak flow_mng_;
        Flow *current_flow_;
#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<SSHProtocol> SSHProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SSH_SSHPROTOCOL_H_
