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
#include "OpenFlowProtocol.h"
#include <iomanip>

namespace aiengine {

OpenFlowProtocol::OpenFlowProtocol():
	Protocol("OpenFlowProtocol", "openflow", IPPROTO_TCP),
	header_(nullptr),
	total_ofp_hellos_(0),
	total_ofp_feature_requests_(0),
	total_ofp_feature_replys_(0),
	total_ofp_set_configs_(0),
	total_ofp_packets_in_(0),
	total_ofp_packets_out_(0) {} 

bool OpenFlowProtocol::openflowChecker(Packet &packet) {

	int length = packet.getLength();

	if (length >= header_size) {
		setHeader(packet.getPayload());

		if ((header_->version >= OF_VERSION_1)and(header_->version <= OF_VERSION_1_3)) {
			++total_valid_packets_;
			return true;
		}
	}
	++total_invalid_packets_;
	return false;
}


void OpenFlowProtocol::process_packet_in(MultiplexerPtr mux, Packet *packet) {

	const uint8_t *payload = packet->getPayload();
	int length = packet->getLength();
	int hdr_size = length;

	if (header_->version == OF_VERSION_1) {
		hdr_size = sizeof(openflow_v1_pktin_header);
	} else if (header_->version == OF_VERSION_1_3) {
		if (length > sizeof(openflow_v13_pktin_header) + 2) {
			const openflow_v13_pktin_header *inpkt = reinterpret_cast<const openflow_v13_pktin_header*>(payload);
			hdr_size = sizeof(openflow_v13_pktin_header) + ntohs(inpkt->match_length) + 2;
		}
	}

	// Just forward the packet if contains a valid openflow header
	if (hdr_size < packet->getLength()) {	
		Packet gpacket(&payload[hdr_size], packet->getLength() - hdr_size);

		gpacket.setPrevHeaderSize(0);
		mux->setHeaderSize(0);
		mux->setNextProtocolIdentifier(0);
		mux->forwardPacket(gpacket);
	}
}

void OpenFlowProtocol::process_packet_out(MultiplexerPtr mux, Packet *packet) {

	int bytes = packet->getLength();
	int offset = 0;
	const uint8_t *payload = packet->getPayload();
	int hdr_size = sizeof(openflow_v1_pktout_header);
	uint8_t version = header_->version;
	uint16_t length = ntohs(header_->length);

	do {
		int pkt_offset = offset;
		int olength = 0;
		if (version == OF_VERSION_1) {
			hdr_size = sizeof(openflow_v1_pktout_header);
			const openflow_v1_pktout_header *outpkt = reinterpret_cast<const openflow_v1_pktout_header*>(&payload[offset]);
			length = ntohs(outpkt->hdr.length);
			pkt_offset = offset + hdr_size;
			olength = length - hdr_size;
		} else if (version == OF_VERSION_1_3) {
			const openflow_v13_pktout_header *outpkt = reinterpret_cast<const openflow_v13_pktout_header*>(&payload[offset]);
			length = ntohs(outpkt->hdr.length);
			hdr_size = sizeof(openflow_v13_pktout_header) + ntohs(outpkt->actions_length);
			pkt_offset = offset + hdr_size;
			olength = length - hdr_size;
		} else {
			// TODO not supported openflow version
			break; /* LCOV_EXCL_LINE */
		}

		if (pkt_offset < bytes) { // offset on the boundaries
			int real_length = bytes - pkt_offset;
			if (olength <= real_length) { // The olength should be minor or equal to the real length	
				Packet gpacket(&payload[pkt_offset], olength);

				gpacket.setPrevHeaderSize(0);
				mux->setHeaderSize(0);
				mux->setNextProtocolIdentifier(0);
				mux->forwardPacket(gpacket);
			}
		}

		offset += length;
	} while (offset < bytes);
}

void OpenFlowProtocol::processFlow(Flow *flow) {

	int bytes = flow->packet->getLength();
	total_bytes_ += bytes;
	++total_packets_;

	if (mux_.lock()&&(bytes >= header_size)) {
		MultiplexerPtr mux = mux_.lock();

                Packet *packet = flow->packet;
		setHeader(packet->getPayload());

		uint8_t version = header_->version;
		uint8_t type = header_->type;

		if ((version >= OF_VERSION_1)and(version <= OF_VERSION_1_3)) {
			if (type == OFP_PACKET_IN) { // Message that contains a packet to forward
				process_packet_in(mux, packet);
				++total_ofp_packets_in_;
			} else if (type == OFP_PACKET_OUT) {
				process_packet_out(mux, packet);
				++total_ofp_packets_out_;
			} else if (type == OFP_HELLO ) {
				++total_ofp_hellos_;
			} else if (type == OFP_FEATURE_REQUEST) {
				++total_ofp_feature_requests_;
			} else if (type == OFP_FEATURE_REPLY) {
				++total_ofp_feature_replys_;
			} else if (type == OFP_SET_CONFIG) {
				++total_ofp_set_configs_;
			}
		}
         }
}

void OpenFlowProtocol::statistics(std::basic_ostream<char> &out, int level) { 

	if (level > 0) {
                int64_t alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory, unit);

                out << getName() << "(" << this <<") statistics" << std::dec << "\n";
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << "\n";
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << "\n";
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ << "\n";
		if (level > 1) {
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << "\n";
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << "\n";
                        if (level > 3) {
                                out << "\t" << "Total hellos:           " << std::setw(10) << total_ofp_hellos_ << "\n";
                                out << "\t" << "Total feature requests: " << std::setw(10) << total_ofp_feature_requests_ << "\n";
                                out << "\t" << "Total feature replys:   " << std::setw(10) << total_ofp_feature_replys_ << "\n";
                                out << "\t" << "Total set configs:      " << std::setw(10) << total_ofp_set_configs_ << "\n";
                                out << "\t" << "Total packets in:       " << std::setw(10) << total_ofp_packets_in_ << "\n";
                                out << "\t" << "Total packets out:      " << std::setw(10) << total_ofp_packets_out_ << std::endl;
                       	} 
			if (level > 2) {
				if (mux_.lock())
					mux_.lock()->statistics(out);
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
			}
		}
	}
}

CounterMap OpenFlowProtocol::getCounters() const {
  	CounterMap cm; 

        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);
        cm.addKeyValue("hellos", total_ofp_hellos_);
        cm.addKeyValue("feature requests", total_ofp_feature_requests_);
        cm.addKeyValue("feature replys", total_ofp_feature_replys_);
        cm.addKeyValue("set configs", total_ofp_set_configs_);
        cm.addKeyValue("packets in", total_ofp_packets_in_);
        cm.addKeyValue("packets out", total_ofp_packets_out_);

        return cm;
}

} // namespace aiengine
