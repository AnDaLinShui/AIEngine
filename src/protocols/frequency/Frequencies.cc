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
#include "Frequencies.h"

namespace aiengine {

void Frequencies::addPayload(const uint8_t *payload, int length) {

	for(int i = 0; i < length; ++i) 
		++freqs_[payload[i]];
}

void Frequencies::reset() { 

	for (auto& value: freqs_) 
		value = 0;
}

void Frequencies::addPayload(const std::string &data) {

	for (auto it = data.begin(); it!= data.end();++it) {
		uint8_t value = *it;
		++freqs_[(int)value];	
	}
}

std::string Frequencies::getFrequenciesString() const { 

	std::ostringstream os;

	os << "[";
	for (auto& value: freqs_) os << value << ","; 

	std::string foo(os.str());
	foo.pop_back();
	os.str(foo);
	os.seekp (0, os.end);  

	os << "]";
	return os.str();
}

std::ostream& operator<<(std::ostream &os, const Frequencies &fq) {

	std::ostringstream os_f;

	os << "Begin frequencies" << std::endl;
	os_f << "[";
	for (auto& value: fq.freqs_) os_f << value << ",";

	std::string foo(os_f.str());
	foo.pop_back();
	os_f.str(foo);
	os_f.seekp (0, os_f.end);

	os_f << "]";
	os << os_f.str() << std::endl;
	return os;
}	

int& Frequencies::operator[](const int index) {

	return freqs_[index];
}

Frequencies Frequencies::operator+(const Frequencies &fq) {

	Frequencies freqs;

	for(int i = 0; i < array_size; ++i) freqs[i] = freqs_[i] + fq.freqs_[i];
	return freqs;
}	

Frequencies Frequencies::operator+(const int &value) {

	Frequencies freqs;

	for(int i = 0; i < array_size ; ++i) freqs[i] = freqs_[i] + value;
	return freqs;
}

Frequencies Frequencies::operator /(const int &value) {

	Frequencies freqs;

	for (int i = 0; i < array_size; ++i) freqs[i] = freqs_[i] / value;
	return freqs;
}

bool Frequencies::operator==(const Frequencies &fq) {

	for (int i = 0; i < array_size; ++i)
		if (freqs_[i] != fq.freqs_[i])
			return false;	
	return true;
}

bool Frequencies::operator!=(const Frequencies &fq) {

	for (int i = 0; i < array_size; ++i)
		if (freqs_[i] != fq.freqs_[i])
			return true;
	return false;
}

int Frequencies::getDispersion() { 

	std::unordered_map<int,int> values;

	for (int i = 0; i < array_size; ++i ) {
		if (freqs_[i] > 0)
			values[i] = 1;
	}
	
	return values.size();
}

double Frequencies::getEntropy() {

	double h = 0;

	for (auto& value: freqs_) {
		double x = value / array_size - 1;
		if (x > 0) h += - x * std::log2(x);	
	}
	return h;
}

} // namespace aiengine

