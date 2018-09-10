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
#ifndef SRC_RAWPACKET_H_
#define SRC_RAWPACKET_H_

#include <iostream>

namespace aiengine {

class RawPacket {
public:
    	explicit RawPacket(const uint8_t *packet, int length):
		packet_(packet), length_(length) {}
    	explicit RawPacket():RawPacket(nullptr, 0) {}
	explicit RawPacket(const RawPacket& p):packet_(p.packet_), length_(p.length_) {}

    	virtual ~RawPacket() {}

	void setPayload(const uint8_t *packet) { packet_ = packet; }
	void setLength(int length) { length_ = length; }

	const uint8_t *getPayload() const { return packet_; }
	int getLength() const { return length_; }

	friend std::ostream& operator<<(std::ostream &os, const RawPacket &p) {
	
		for (int i = 0;i< p.length_;++i) {
			os << std::hex << (int)p.packet_[i] << " ";
		}
		os << std::endl; 
		return os;
	}	

#if defined(LUA_BINDING)
	short __getitem__(int i) const {
		if ((i >= 0)and(i < length_)) 
			return packet_[i];
		else
			return 0xFF;
	}
	void __setitem__(int i, short nothing) {}
#endif

private:
	const uint8_t *packet_;
	int length_;
};

typedef std::shared_ptr<RawPacket> RawPacketPtr;

} // namespace aiengine

#endif  // SRC_RAWPACKET_H_
