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
#include "GPRSProtocol.h"
#include <iomanip> // setw

namespace aiengine {

GPRSProtocol::GPRSProtocol():
	Protocol("GPRSProtocol", "gprs", IPPROTO_UDP),
	gprs_info_cache_(new Cache<GPRSInfo>("GPRS info cache")),
	header_(nullptr),
	total_create_pdp_ctx_requests_(0),
	total_create_pdp_ctx_responses_(0),
	total_update_pdp_ctx_requests_(0),
	total_update_pdp_ctx_responses_(0),
	total_delete_pdp_ctx_requests_(0),
	total_delete_pdp_ctx_responses_(0),
	total_tpdus_(0),
	total_echo_requests_(0),
	total_echo_responses_(0),
	ip_protocol_type_(ETHERTYPE_IP),
        flow_mng_() {}

bool GPRSProtocol::gprsChecker(Packet& packet) {

	int length = packet.getLength();

	if (length >= header_size) {
		setHeader(packet.getPayload());

		if (header_->flags & 0x30) {
			++total_valid_packets_;
			return true;
		}
	}
	++total_invalid_packets_;
	return false;
}

void GPRSProtocol::setDynamicAllocatedMemory(bool value) {

	gprs_info_cache_->setDynamicAllocatedMemory(value);
}


bool GPRSProtocol::isDynamicAllocatedMemory() const { 
	
	return gprs_info_cache_->isDynamicAllocatedMemory();
}

int64_t GPRSProtocol::getCurrentUseMemory() const {

	int64_t mem = sizeof(GPRSProtocol);

	mem += gprs_info_cache_->getCurrentUseMemory();

	return mem;
}

int64_t GPRSProtocol::getAllocatedMemory() const {

	int64_t mem = sizeof(GPRSProtocol);

        mem += gprs_info_cache_->getAllocatedMemory();

        return mem;
}

int64_t GPRSProtocol::getTotalAllocatedMemory() const {

        return getAllocatedMemory();
}

int32_t GPRSProtocol::getTotalCacheMisses() const {

	return gprs_info_cache_->getTotalFails();
}

void GPRSProtocol::increaseAllocatedMemory(int value) { 

	gprs_info_cache_->create(value); 
}
 
void GPRSProtocol::decreaseAllocatedMemory(int value) { 

	gprs_info_cache_->destroy(value); 
}

void GPRSProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

                int64_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;

                for (auto &flow: ft) {
                       	SharedPointer<GPRSInfo> info = flow->getGPRSInfo();
			if (info) {
                                flow->layer4info.reset();
                                total_bytes_released_by_flows += info->getIMSIString().size() + 16; // 16 bytes from the uint16_t
                                gprs_info_cache_->release(info);
                                ++release_flows;
                        }
                }

                msg.str("");
                msg << "Release " << release_flows << " flows";
                msg << ", " << total_bytes_released_by_flows << " bytes";
                infoMessage(msg.str());
        }
}

void GPRSProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getGPRSInfo();
	if (info) {
		gprs_info_cache_->release(info);
	}
}

void GPRSProtocol::process_create_pdp_context(Flow *flow) {

	SharedPointer<GPRSInfo> gprs_info = flow->getGPRSInfo();
	if (!gprs_info) {
		gprs_info = gprs_info_cache_->acquire();
                if (gprs_info) {
			flow->layer4info = gprs_info;
                }
	}

	if (gprs_info) {
		const gprs_create_pdp_header *cpd = reinterpret_cast<const gprs_create_pdp_header*>(header_->data);
		const uint8_t *extensions = &cpd->data[0];
		uint8_t token = extensions[0];

		if (cpd->presence == 0x02) {
			gprs_info->setIMSI(cpd->un.reg.imsi);
			extensions = &cpd->un.reg.hdr[0];
			token = extensions[0];
		}else {
			// And extension header
			if (cpd->presence == 0x01) {
				extensions = &cpd->data[0];
				token = extensions[0];
				gprs_info->setIMSI(cpd->un.ext.imsi);
			}
		}

		if (token == 0x03) { // Routing Area Identity Header
			const gprs_create_pdp_header_routing *rhdr = reinterpret_cast<const gprs_create_pdp_header_routing*>(extensions);
			extensions = &rhdr->data[0];
			token = extensions[0];
		}

		if (token == 0x0E) { // Recovery 
			extensions = &extensions[2];
			token = extensions[0];
		}
		if (token == 0x0F) { 
			const gprs_create_pdp_header_ext *hext = reinterpret_cast<const gprs_create_pdp_header_ext*>(&extensions[2]);
			extensions = &hext->data[0];
			token = extensions[0];

			if (token == 0x1A) { // Charging Characteristics
				token = extensions[3];
				extensions = &extensions[4];	
			} else {
				extensions = &extensions[1];	
			}
			if (token == 0x80) {
				uint16_t length = ntohs((extensions[1] << 8) + extensions[0]);
				if (length == 2) {
					uint8_t type_org __attribute__((unused)) = extensions[2];
					uint8_t type_num = extensions[3];
					// type_num eq 0x21 is IPv4
					// type_num eq 0x57 is IPv6
					
					gprs_info->setPdpTypeNumber(type_num);
				}
			}

		}
	}
}

void GPRSProtocol::processFlow(Flow *flow) {

	int bytes = flow->packet->getLength();
        total_bytes_ += bytes;
	++total_packets_;

        if (!mux_.expired()&&(bytes >= header_size)) {

		const uint8_t *payload = flow->packet->getPayload();      
		setHeader(payload);

		uint8_t type = header_->type; 
		int8_t version = header_->flags >> 5;
			
		if ((type == T_PDU)and(version == 1)) {
			MultiplexerPtr mux = mux_.lock();

			Packet gpacket(*(flow->packet));
		
			int offset = 0;

			// Not sure if seen this on user data
			if (haveExtensionHeader()) offset += 6; // sizeof extension headers 

			if (haveSequenceNumber()) 
				offset += 4;

			gpacket.setPayload(&payload[offset]);
			gpacket.setPrevHeaderSize(header_size + offset);
	
			mux->setNextProtocolIdentifier(ip_protocol_type_); 
			mux->forwardPacket(gpacket);

			if (gpacket.haveEvidence()) {
				flow->packet->setEvidence(gpacket.haveEvidence());	
			}

			++total_tpdus_;
		} else if (type == CREATE_PDP_CONTEXT_REQUEST) {
			process_create_pdp_context(flow);
			++total_create_pdp_ctx_requests_;
		} else if (type == CREATE_PDP_CONTEXT_RESPONSE) {
			++total_create_pdp_ctx_responses_;
		} else if (type == UPDATE_PDP_CONTEXT_REQUEST) {
			++total_update_pdp_ctx_requests_;
		} else if (type == UPDATE_PDP_CONTEXT_RESPONSE) {
			++total_update_pdp_ctx_responses_;
		} else if (type == DELETE_PDP_CONTEXT_REQUEST) {
			// TODO shutdown the flow
			++total_delete_pdp_ctx_requests_;
		} else if (type == DELETE_PDP_CONTEXT_RESPONSE) {
			// TODO shutdown the flow
			++total_delete_pdp_ctx_responses_;
		} else if (type == GPRS_ECHO_REQUEST) {
			++total_echo_requests_;
		} else if (type == GPRS_ECHO_RESPONSE) {
			++total_echo_responses_;
		}
         }
}

void GPRSProtocol::statistics(std::basic_ostream<char>& out, int level) {

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
                                out << "\t" << "Total echo reqs:        " << std::setw(10) << total_echo_requests_ << std::endl;
                                out << "\t" << "Total echo ress:        " << std::setw(10) << total_echo_responses_ << std::endl;
                                out << "\t" << "Total create pdp reqs:  " << std::setw(10) << total_create_pdp_ctx_requests_ << std::endl;
                                out << "\t" << "Total create pdp ress:  " << std::setw(10) << total_create_pdp_ctx_responses_ << std::endl;
                                out << "\t" << "Total update pdp reqs:  " << std::setw(10) << total_update_pdp_ctx_requests_ << std::endl;
                                out << "\t" << "Total update pdp ress:  " << std::setw(10) << total_update_pdp_ctx_responses_ << std::endl;
                                out << "\t" << "Total delete pdp reqs:  " << std::setw(10) << total_delete_pdp_ctx_requests_ << std::endl;
                                out << "\t" << "Total delete pdp ress:  " << std::setw(10) << total_delete_pdp_ctx_responses_ << std::endl;
                                out << "\t" << "Total tpdus:          " << std::setw(12) << total_tpdus_ << std::endl;
                        }
			if (level > 2) {
				if (mux_.lock())
					mux_.lock()->statistics(out);
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);

				if (level > 3) {
					if (gprs_info_cache_)
                                        	gprs_info_cache_->statistics(out);
				}
			}
		}
	}
}

CounterMap GPRSProtocol::getCounters() const {
   	CounterMap cm; 

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
        cm.addKeyValue("echo reqs", total_echo_requests_);
        cm.addKeyValue("echo ress", total_echo_requests_);
        cm.addKeyValue("create pdp reqs", total_create_pdp_ctx_requests_);
        cm.addKeyValue("create pdp ress", total_create_pdp_ctx_responses_);
        cm.addKeyValue("update pdp reqs", total_update_pdp_ctx_requests_);
        cm.addKeyValue("update pdp ress", total_update_pdp_ctx_responses_);
        cm.addKeyValue("delete pdp reqs", total_delete_pdp_ctx_requests_);
        cm.addKeyValue("delete pdp ress", total_delete_pdp_ctx_responses_);
        cm.addKeyValue("tpdus", total_tpdus_);

        return cm;
}

} // namespace aiengine 

