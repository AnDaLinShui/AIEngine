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
#ifndef SRC_PROTOCOLS_FREQUENCY_FREQUENCIES_H_
#define SRC_PROTOCOLS_FREQUENCY_FREQUENCIES_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sstream>
#include <iostream>
#include <array>
#include <unordered_map>
#include <cmath>
#include "FlowInfo.h"

namespace aiengine {

// TODO: evaluate the use of valarray on the code
class Frequencies : public FlowInfo {
public:
    	explicit Frequencies():freqs_() { reset(); }
    	virtual ~Frequencies() {}

	static const int array_size = 256;	

	void reset(); 

	void serialize(JsonFlow &j) {}

	void addPayload(const uint8_t *payload, int length); 
	void addPayload(const std::string &data);

	std::string getFrequenciesString() const; 

	friend std::ostream& operator<<(std::ostream &os, const Frequencies &fq); 
	
	int& operator[](const int index);
	Frequencies operator+(const Frequencies &fq); 
	Frequencies operator+(const int &value); 
        Frequencies operator /(const int &value);
        bool operator==(const Frequencies &fq); 
        bool operator!=(const Frequencies &fq); 
        
	int getDispersion(); 
	double getEntropy(); 
	
private:
	std::array<int, array_size> freqs_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_FREQUENCY_FREQUENCIES_H_
