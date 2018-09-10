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
#ifndef SRC_PROTOCOLS_BITCOIN_BITCOINPROTOCOL_H_
#define SRC_PROTOCOLS_BITCOIN_BITCOINPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>
#include "flow/FlowManager.h"
#include "BitcoinInfo.h"
#include "Cache.h"

namespace aiengine {

struct bitcoin_header {
        uint32_t       	magic;          /* Magic number */
        char       	command[12];    /* Command */
        uint32_t       	length;         /* Length */
        uint32_t       	cksum;          /* Checksum */
} __attribute__((packed));

enum bitcoin_command_code {
        BC_CMD_VERSION = 1,
        BC_CMD_VERACK,
        BC_CMD_ADDR,
        BC_CMD_INV,
        BC_CMD_GETDATA,
        BC_CMD_NOTFOUND,
        BC_CMD_GETBLOCKS,
        BC_CMD_GETHEADERS,
        BC_CMD_TX,
        BC_CMD_BLOCK,
        BC_CMD_HEADERS,
        BC_CMD_GETADDR,
        BC_CMD_MEMPOOL,
        BC_CMD_PING,
        BC_CMD_PONG,
        BC_CMD_REJECT,
        BC_CMD_ALERT
};

// Commands and their corresponding handlers
typedef std::tuple<short,const char*,int32_t,short,std::function <void (BitcoinInfo&)>> BitcoinCommandType;

class BitcoinProtocol: public Protocol {
public:
    	explicit BitcoinProtocol();
    	virtual ~BitcoinProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(bitcoin_header);

	int getHeaderSize() const { return header_size; }

        void processFlow(Flow *flow) override;
        bool processPacket(Packet &packet) override { return true; } 

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override;

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const bitcoin_header*> (raw_packet);
	}

	// Condition for say that a packet is bitcoin 
	bool bitcoinChecker(Packet &packet); 

	// Returns the length of the last block process on a packet
	int32_t getPayloadLength() const { return header_->length; }	
	int32_t getTotalBitcoinOperations() const { return total_bitcoin_operations_; }	

	int64_t getCurrentUseMemory() const override; 
	int64_t getAllocatedMemory() const override;
	int64_t getTotalAllocatedMemory() const override;

        void setDynamicAllocatedMemory(bool value) override;
	bool isDynamicAllocatedMemory() const override;

	int32_t getTotalCacheMisses() const override;

	void increaseAllocatedMemory(int value) override; 
	void decreaseAllocatedMemory(int value) override;

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }	

	void releaseFlowInfo(Flow *flow) override;

	CounterMap getCounters() const override; 

	Flow* getCurrentFlow() const { return current_flow_; }

private:

	static void default_handler(BitcoinProtocol &bt) { return; }

	const bitcoin_header *header_;
	int64_t total_bitcoin_operations_;

	static std::unordered_map<std::string, BitcoinCommandType> commands_;	        

	Cache<BitcoinInfo>::CachePtr info_cache_;

	FlowManagerPtrWeak flow_mng_;
	Flow *current_flow_;

#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<BitcoinProtocol> BitcoinProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_BITCOIN_BITCOINPROTOCOL_H_
