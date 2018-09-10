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
#include "BitcoinProtocol.h"
#include <iomanip>

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr BitcoinProtocol::logger(log4cxx::Logger::getLogger("aiengine.bitcoin"));
#endif

// List of support bitcoin commands
std::unordered_map<std::string, BitcoinCommandType> BitcoinProtocol::commands_ {
	{ "version", 	std::make_tuple(BC_CMD_VERSION,		"version",	0,	20, [](BitcoinInfo &a) {} ) }, // ok
	{ "verack", 	std::make_tuple(BC_CMD_VERACK,		"version ack",	0,	20, [](BitcoinInfo &a) {} ) }, // ok
	{ "addr", 	std::make_tuple(BC_CMD_ADDR,		"network addr",	0,	24, [](BitcoinInfo &a) {} ) }, // ok
	{ "inv", 	std::make_tuple(BC_CMD_INV,		"inv",		0,	20, [](BitcoinInfo &a) {} ) },
	{ "getdata", 	std::make_tuple(BC_CMD_GETDATA,		"getdata",	0,	20, [](BitcoinInfo &a) {} ) },
	{ "notfound", 	std::make_tuple(BC_CMD_NOTFOUND,	"not found",	0,	20, [](BitcoinInfo &a) {} ) },
	{ "getblocks", 	std::make_tuple(BC_CMD_GETBLOCKS,	"get blocks",	0,	24, [](BitcoinInfo &a) {} ) }, // ok
	{ "getheaders", std::make_tuple(BC_CMD_GETHEADERS,	"get headers",	0,	20, [](BitcoinInfo &a) {} ) },
	{ "tx", 	std::make_tuple(BC_CMD_TX,		"transaction",	0,	20, [](BitcoinInfo &a) { a.incTransactions(); } ) },
	{ "block", 	std::make_tuple(BC_CMD_BLOCK,		"block",	0,	24, [](BitcoinInfo &a) { a.incBlocks(); } ) }, // ok
	{ "headers", 	std::make_tuple(BC_CMD_HEADERS,		"headers",	0,	20, [](BitcoinInfo &a) {} ) },
	{ "getaddr", 	std::make_tuple(BC_CMD_GETADDR,		"getaddr",	0,	24, [](BitcoinInfo &a) {} ) }, // ok
	{ "mempool", 	std::make_tuple(BC_CMD_MEMPOOL,		"mempool",	0,	20, [](BitcoinInfo &a) {} ) },
	{ "ping",	std::make_tuple(BC_CMD_PING,		"ping",		0,	20, [](BitcoinInfo &a) {} ) },
	{ "pong",	std::make_tuple(BC_CMD_PONG,		"pong",		0,	20, [](BitcoinInfo &a) {} ) },
	{ "reject",	std::make_tuple(BC_CMD_REJECT,		"reject",	0,	20, [](BitcoinInfo &a) { a.incRejects(); } ) },
	{ "alert",	std::make_tuple(BC_CMD_ALERT,		"alert",	0,	20, [](BitcoinInfo &a) {} ) }
};

BitcoinProtocol::BitcoinProtocol():
	Protocol("BitcoinProtocol", "bitcoin", IPPROTO_TCP),
	header_(nullptr),
	total_bitcoin_operations_(0),
	info_cache_(new Cache<BitcoinInfo>("Bitcoin Info Cache")),
	flow_mng_(),
	current_flow_(nullptr) {}

bool BitcoinProtocol::bitcoinChecker(Packet &packet) {

	int length = packet.getLength();

	if (length >= header_size) {
		if ((packet.getSourcePort() == 8333)||(packet.getDestinationPort() == 8333)) {
			setHeader(packet.getPayload());
			if (header_->magic == 0xD9B4BEF9) { // Bitcoin magic value 0xf9beb4d9
				++total_valid_packets_;
				return true;
			}
		}
	}
	++total_invalid_packets_;
        return false;
}

void BitcoinProtocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);
}	

bool BitcoinProtocol::isDynamicAllocatedMemory() const {

	return info_cache_->isDynamicAllocatedMemory();	
}

int64_t BitcoinProtocol::getAllocatedMemory() const {

        int64_t mem = sizeof(BitcoinProtocol);

        mem += info_cache_->getAllocatedMemory();

        return mem;
}

int64_t BitcoinProtocol::getCurrentUseMemory() const { 
	
	int64_t mem = sizeof(BitcoinProtocol);

	mem += info_cache_->getCurrentUseMemory();

	return mem;
}	

int64_t BitcoinProtocol::getTotalAllocatedMemory() const {

        return getAllocatedMemory();
}

int32_t BitcoinProtocol::getTotalCacheMisses() const {

	return info_cache_->getTotalFails();
}

void BitcoinProtocol::releaseCache() {

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
                        SharedPointer<BitcoinInfo> info = flow->getBitcoinInfo();
                        if (info) {
                                total_bytes_released_by_flows += sizeof(info);

                                flow->layer7info.reset();
                                ++ release_flows;
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

void BitcoinProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getBitcoinInfo();
	if (info) {
		info_cache_->release(info);
	}
}

void BitcoinProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++flow->total_packets_l7;
	++total_packets_;
	
	current_flow_ = flow;

	SharedPointer<BitcoinInfo> info = flow->getBitcoinInfo();
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

	const uint8_t *payload = flow->packet->getPayload();
	int offset = 0;

	while (offset + header_size < length) {
	
		setHeader(&payload[offset]);	

		// If no magic no packet :)
		if (header_->magic == 0xD9B4BEF9) {
			const char *cmd = &header_->command[0];
			auto it = commands_.find(cmd);
                	if (it != commands_.end()) {
				int32_t *hits = &std::get<2>(it->second);
				short padding = std::get<3>(it->second);
				int32_t payload_len = getPayloadLength();
				auto callback = std::get<4>(it->second);

				callback(*info.get());
	
				++total_bitcoin_operations_;	
				++(*hits);

				offset = (offset + payload_len + padding) ;
			}
		} else {
			break;
		}
        }
}

void BitcoinProtocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
}

void BitcoinProtocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
}

void BitcoinProtocol::statistics(std::basic_ostream<char> &out, int level) { 

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
				for (auto &cmd: commands_) {
                                        const char *label = std::get<1>(cmd.second);
                                        int32_t hits = std::get<2>(cmd.second);
                                        out << "\t" << "Total " << label << ":" << std::right << std::setfill(' ') << std::setw(27 - strlen(label)) << hits << std::endl;
                                }
                        }
                        if (level > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
                                if (level > 3) {
                                        info_cache_->statistics(out);
                                }
			}
		}
	}
}

CounterMap BitcoinProtocol::getCounters() const { 
	CounterMap cm;

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);

        for (auto &cmd: commands_) {
        	const char *label = std::get<1>(cmd.second);
                int32_t hits = std::get<2>(cmd.second);
               
		cm.addKeyValue(label, hits);
	}                
	
        return cm;
}

} // namespace aiengine
