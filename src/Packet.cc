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
#include "Packet.h"

namespace aiengine {

Packet::Packet(const uint8_t *packet, int length, int prev_header_size,
	PacketAnomalyType pa, time_t packet_time):
	curr_packet(packet, length),
	prev_packet(packet, length),
	link_packet(packet, length),
	net_packet(packet, length),
	trans_packet(packet, length),
	prev_header_size_(prev_header_size),
	source_port_(0),
	dest_port_(0),
	pa_(pa),
	packet_time_(packet_time),
	have_tag_(false),
	have_evidence_(false),
	force_adaptor_write_(false),
#if defined(BINDING)
        is_accept_(true),
#endif
	tag_(0xFFFFFFFF) 
#if defined(STAND_ALONE_TEST) || defined(TESTING)
	,pcap_(nullptr)
#endif 	
	{}
		
Packet::Packet(const Packet &p):
	curr_packet(p.curr_packet),
	prev_packet(p.prev_packet),
	link_packet(p.link_packet),
	net_packet(p.net_packet),
	trans_packet(p.trans_packet),
	prev_header_size_(p.prev_header_size_),
	source_port_(p.source_port_),
	dest_port_(p.dest_port_),
	pa_(p.pa_),
	packet_time_(p.packet_time_),
	have_tag_(p.have_tag_),
	have_evidence_(p.have_evidence_),
	force_adaptor_write_(p.force_adaptor_write_),
#if defined(BINDING)
        is_accept_(p.is_accept_),
#endif
	tag_(p.tag_)  
#if defined(STAND_ALONE_TEST) || defined(TESTING)
	,pcap_(nullptr)
#endif
	{}

#if defined(STAND_ALONE_TEST) || defined(TESTING)
Packet::Packet(const std::string &pcapfile, int offset):
	Packet(nullptr, 0) {

        char errorbuf[PCAP_ERRBUF_SIZE];

#if defined(TESTING)
	std::string filename(pcapfile);

	if (filename.compare(0, 12, "../protocols") == 0)
		filename = filename.substr(12);
	else if (filename.compare(0, 2, "..") == 0) 
		filename = filename.substr(3);
	
	std::string path ("protocols/" + filename);
#else
	std::string path (pcapfile);
#endif
        pcap_t * pcap = pcap_open_offline(path.c_str(), errorbuf);
        if (pcap != nullptr) {
		struct pcap_pkthdr *header;
        	const uint8_t *pkt;
		if (pcap_next_ex(pcap, &header, &pkt) >= 0) {
			setPayload(&pkt[offset]);
			setPayloadLength(header->len - offset);
			setPcap(pcap);
			return;
		}
	}
	throw "Invalid pcap file:" + pcapfile; /* LCOV_EXCL_LINE */
}

Packet::~Packet() {

	if (pcap_) {
		pcap_close(pcap_);
	}
}
#endif


void Packet::setTag(uint32_t tag) { 

	have_tag_ = true; 
	tag_ = tag; 
}

void Packet::setPayload(const uint8_t *packet) { 

	prev_packet.setPayload(curr_packet.getPayload()); 
	curr_packet.setPayload(packet); 
}

/* LCOV_EXCL_START */
std::ostream& operator<<(std::ostream &os, const Packet &p) {

	os << "Begin packet(" << &p << ") length:" << p.curr_packet.getLength() << " prev header size:" << p.prev_header_size_;
	os << " curr_packet.length:" << p.curr_packet.getLength();
	os << " prev_packet.length:" << p.prev_packet.getLength();
	os << " link_packet.length:" << p.link_packet.getLength();
	os << " net_packet.length:" << p.net_packet.getLength();
	os << " trans_packet.length:" << p.trans_packet.getLength();
	os << " anomaly:" << " " /* PacketAnomalies[static_cast<int8_t>(p.pa_)].name */ << " time:" << p.packet_time_;
	os << " sport:" << p.source_port_ << " dport:" << p.dest_port_ << " evi:" << p.have_evidence_ << std::endl;

	// showPayload(os,p.curr_packet.getPayload(),p.curr_packet.getLength());

	return os;
}	
/* LCOV_EXCL_STOP */

} // namespace aiengine

