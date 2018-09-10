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
#ifndef SRC_PROTOCOLS_FREQUENCY_PACKETFREQUENCIES_H_
#define SRC_PROTOCOLS_FREQUENCY_PACKETFREQUENCIES_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sstream>
#include <iostream>
#include <array>
#include <unordered_map>
#include <cmath>

namespace aiengine {

static const int MAX_PACKET_FREQUENCIES_VALUES = 4096;

class PacketFrequencies 
{
public:
    	PacketFrequencies();
    	virtual ~PacketFrequencies() {};

	void reset();
	void addPayload(const uint8_t *data, int length); 
        void addPayload(const std::string &data); 

	std::string getPacketFrequenciesString() const; 

	friend std::ostream& operator<<(std::ostream &os, const PacketFrequencies &fq);

	uint8_t index(int index);
	uint8_t& operator[](const int index);

	PacketFrequencies operator+(const PacketFrequencies &fq);
        PacketFrequencies operator+(const int &value);
        PacketFrequencies operator/(const int &value);
        bool operator==(const PacketFrequencies &fq);
        bool operator!=(const PacketFrequencies &fq);

	int getDispersion();
	double getEntropy();
	int getLength() const;

private:
	std::array<uint8_t, MAX_PACKET_FREQUENCIES_VALUES> freqs_;
	int length_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_FREQUENCY_PACKETFREQUENCIES_H_
