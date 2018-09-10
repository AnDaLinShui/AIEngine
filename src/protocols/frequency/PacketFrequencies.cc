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
#include "PacketFrequencies.h"

namespace aiengine {

PacketFrequencies::PacketFrequencies():
	freqs_() 
	{ 
	reset(); 
}

void PacketFrequencies::reset() { 

	length_ = 0; 
	for (auto& value: freqs_) value = 0;
}

void PacketFrequencies::addPayload(const uint8_t *data, int length) {

	std::string buffer(reinterpret_cast<const char*>(data), length);

	addPayload(buffer);
}

void PacketFrequencies::addPayload(const std::string &data) {

	int limit = data.length();

	if (length_ >= MAX_PACKET_FREQUENCIES_VALUES) return;

	if (length_ + data.length() > MAX_PACKET_FREQUENCIES_VALUES) {
	
		limit = MAX_PACKET_FREQUENCIES_VALUES  - length_ ;
	}

	for (int i = 0; i < limit ;++i) freqs_[length_ + i] = data[i];
	length_ += limit;
}

std::string PacketFrequencies::getPacketFrequenciesString() const { 

	std::ostringstream os;

	os << "[";
	for (int i = 0; i < length_; ++i)
		os << freqs_[i] << ","; 

	std::string foo(os.str());
	foo.pop_back();
	os.str(foo);
	os.seekp (0, os.end);  

	os << "]";
	return os.str();
}

std::ostream& operator<<(std::ostream &os, const PacketFrequencies &fq) {

	std::ostringstream os_f;

	os << "Begin frequencies" << std::endl;
	os_f << "[";
	for (int i = 0; i < fq.length_; ++i)
		os << (int)fq.freqs_[i] << ","; 

	std::string foo(os_f.str());
	foo.pop_back();
	os_f.str(foo);
	os_f.seekp (0, os_f.end);

	os_f << "]";
	os << os_f.str() << std::endl;
	return os;
}	

uint8_t PacketFrequencies::index(int index) { 

	return freqs_[index];
}

uint8_t& PacketFrequencies::operator [](const int index) {

	return freqs_[index];
}

PacketFrequencies PacketFrequencies::operator +(const PacketFrequencies &fq) {

	PacketFrequencies freqs;

	for (int i = 0; i < MAX_PACKET_FREQUENCIES_VALUES; ++i) 
		freqs[i] = freqs_[i] + fq.freqs_[i];

	return freqs;
}	

PacketFrequencies PacketFrequencies::operator +(const int &value) {

	PacketFrequencies freqs;

	for (int i = 0; i < MAX_PACKET_FREQUENCIES_VALUES; ++i) 
		freqs[i] = freqs_[i] + value;

	return freqs;
}

PacketFrequencies PacketFrequencies::operator /(const int &value) {

	PacketFrequencies freqs;

	for (int i = 0; i < MAX_PACKET_FREQUENCIES_VALUES; ++i) 
		freqs[i] = freqs_[i] / value;

	return freqs;
}

bool PacketFrequencies::operator ==(const PacketFrequencies &fq) {

	for (int i = 0; i < MAX_PACKET_FREQUENCIES_VALUES; ++i)
		if (freqs_[i] != fq.freqs_[i])
			return false;	
	return true;
}

bool PacketFrequencies::operator !=(const PacketFrequencies &fq) {

	for(int i = 0; i < MAX_PACKET_FREQUENCIES_VALUES; ++i)
		if (freqs_[i] != fq.freqs_[i])
			return true;
	return false;
}

int PacketFrequencies::getDispersion() { 

	std::unordered_map<int, int> values;

        for (int i = 0; i < length_; ++i) {
                if (freqs_[i] > 0)
                        values[freqs_[i]] = 1;
        }

	return values.size();
}

double PacketFrequencies::getEntropy() {

	double h = 0;

        for (int i = 0; i < length_; ++i) {
		double x = (uint8_t)freqs_[i] / 255;
		if (x > 0) 
			h += - x * log2(x);
	}
	return h;
}

int PacketFrequencies::getLength() const { return length_;}

} // namespace aiengine
