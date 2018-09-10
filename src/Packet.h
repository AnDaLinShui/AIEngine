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
#ifndef SRC_PACKET_H_
#define SRC_PACKET_H_

#include <iostream>
#include <memory>
#include <pcap.h>
#include "RawPacket.h"
#include "AnomalyManager.h"

namespace aiengine {

auto print_payload_line = [](std::basic_ostream<char> &out, const uint8_t *payload, int from, int to) noexcept {

        out << "         ";
        for (int i = from ; i < to; ++i) {
                if (payload[i] >= 32 && payload[i] <= 128)
                        out << (unsigned char)payload[i];
                else
                        out << ".";
        }
        out << std::endl;
};

static auto showPayload = [](std::basic_ostream<char> &out, const uint8_t *payload, int length) {

	std::ios_base::fmtflags f(out.flags());

        for (int i = 0; i < length; ++i) {
                if ((i != 0)and(i % 16 == 0)) {
                        print_payload_line(out, payload, i - 16, i);
                }

                if (i % 16 == 0) out << "\t";
                out << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)payload[i] << " ";

                if (i == length -1) {
                        for (int j = 0; j < 15 - i % 16; ++j) out << "   ";

                        print_payload_line(out, payload, i - i % 16, i);
                }
        }
	// out << std::dec; // restore the decimal 
	out.flags(f);
};

class Packet {
public:
    	explicit Packet(const uint8_t *packet, int length, int prev_header_size,
		PacketAnomalyType pa, time_t packet_time);
	
	explicit Packet(const uint8_t *packet, int length, int prev_header_size,
		PacketAnomalyType pa): Packet(packet, length, prev_header_size, pa, 0) {}

	explicit Packet(const uint8_t *packet, int length, int prev_header_size):
		Packet(packet, length, prev_header_size, PacketAnomalyType::NONE, 0) {}

	explicit Packet(const uint8_t *packet, int length):
		Packet(packet, length, 0, PacketAnomalyType::NONE, 0) {}

    	explicit Packet():Packet(nullptr, 0, 0, PacketAnomalyType::NONE, 0) {}

#if defined(STAND_ALONE_TEST) || defined(TESTING)

	// For the unit tests we define a extra constructor that allows
        // to pass the path of a pcap file and load the first packet
        // into memory. This code is only compiled on testing mode
	explicit Packet(const std::string &pcapfile, int offset);
	explicit Packet(const std::string &pcapfile):
		Packet(pcapfile, 0) {}

    	virtual ~Packet(); 
	void setPcap(pcap_t *pcap) { pcap_ = pcap; }
#else
    	virtual ~Packet() {}
#endif
	Packet(const Packet &p);

	void setTag(uint32_t tag);
	bool haveTag() const { return have_tag_; }
	uint32_t getTag() const { return tag_; }

	void setForceAdaptorWrite(bool value) { force_adaptor_write_ = value; }
	bool forceAdaptorWrite() const { return force_adaptor_write_; }

        bool haveEvidence() const { return have_evidence_; }
        void setEvidence(bool value) { have_evidence_ = value; }

#if defined(BINDING)
        // The flow have been marked as accept or drop (for external Firewall integration) 
        bool isAccept() const { return is_accept_; }
        void setAccept(bool accept) { is_accept_ = accept; }
#endif
	void setPacketTime(time_t packet_time) { packet_time_ = packet_time; }
	time_t getPacketTime() const { return packet_time_; }

	void setPayload(const uint8_t *packet); 
	void setPayloadLength(int length) { curr_packet.setLength(length); }
	void setPrevHeaderSize(int size) { prev_header_size_ = size; }

	void setDestinationPort(uint16_t port) { dest_port_ = port; }
	void setSourcePort(uint16_t port) { source_port_ = port; }

	void setPacketAnomaly(const PacketAnomalyType &pa) { pa_ = pa; } 
	PacketAnomalyType getPacketAnomaly() const { return pa_; } 

	uint16_t getDestinationPort() { return dest_port_; }
	uint16_t getSourcePort() { return source_port_; }

	const uint8_t *getPayload() { return curr_packet.getPayload(); }
	const uint8_t *getPrevPayload() { return prev_packet.getPayload(); }
	int getLength()  { return curr_packet.getLength(); }
	int getPrevHeaderSize()  { return prev_header_size_; }

	friend std::ostream& operator<<(std::ostream &os, const Packet &p); 

	RawPacket curr_packet;
	RawPacket prev_packet;
	RawPacket link_packet;
	RawPacket net_packet;
	RawPacket trans_packet;
private:
	int prev_header_size_;
	uint16_t source_port_;
	uint16_t dest_port_;
	PacketAnomalyType pa_;
	time_t packet_time_;
	bool have_tag_;
	bool have_evidence_;
	bool force_adaptor_write_; // Force to call the databaseAdaptor update method
#if defined(BINDING)
        bool is_accept_;
#endif
	uint32_t tag_;
#if defined(STAND_ALONE_TEST) || defined(TESTING)
	pcap_t *pcap_;
#endif

};

typedef std::shared_ptr<Packet> PacketPtr;

} // namespace aiengine

#endif  // SRC_PACKET_H_
