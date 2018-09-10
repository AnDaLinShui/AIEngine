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
#ifndef SRC_LEARNER_LEARNERENGINE_H_
#define SRC_LEARNER_LEARNERENGINE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <memory>
#include <iomanip> // setw
#include <unordered_map>
#include <boost/format.hpp>

#ifdef PYTHON_BINDING
#include <boost/python.hpp>
#endif

#include "protocols/frequency/PacketFrequencies.h"
#include "protocols/frequency/FrequencyGroup.h"
#include "flow/FlowManager.h"

namespace aiengine {

class LearnerEngine {
public:
    	explicit LearnerEngine();
    	virtual ~LearnerEngine() {};

	static const int byteQuality = 80; // This is a percent
	static const int maxBufferSize = 64; 

	void reset(); 

	void statistics(std::basic_ostream<char> &out) const;
	void statistics() { statistics(std::cout);};	

	void agregatePacketFlow(const SharedPointer<PacketFrequencies> &pkt_freq); 
	
	void compute();
	void setMaxBufferSize(int size) { max_raw_expression_ = size; }
	void setRegexByteQuality(int value) { byte_quality_ = value; }

	std::string getRegularExpression() { return regex_expression_;}
	std::string getRawExpression() { return raw_expression_;}
	std::string getAsciiExpression();

	void setMaxLenghtForRegularExpression(int value) { max_raw_expression_ = value;}

	void setFrequencyGroup(const FrequencyGroup<std::string>::Ptr &fg) { freq_group_ = fg;}

	int getCurrentFlowsProcess() const { return flows_;}
	int getTotalFlowsProcess() const { return total_flows_;}

#if defined(PYTHON_BINDING) 
	void agregateFlows(boost::python::list flows);
#elif defined(RUBY_BINDING)
	void agregateFlows(VALUE flows);
#else
	void agregateFlows(const std::vector<WeakPointer<Flow>> &flows);
#endif

	friend std::ostream& operator<< (std::ostream &out, const LearnerEngine &le);

#if defined(STAND_ALONE_TEST) || defined(TESTING)
	int getQualityByte(int offset) const { return get_quality_byte(offset); }
#endif

private:
	int get_quality_byte(int offset) const;

	int length_;
	int flows_;
	int max_raw_expression_;
	int byte_quality_;
	int32_t total_computes_;
	int32_t total_flows_;
	std::string raw_expression_;	
	std::string regex_expression_;	
	FrequencyGroup<std::string>::PtrWeak freq_group_;
	std::array<std::unordered_map<unsigned short, int>, MAX_PACKET_FREQUENCIES_VALUES> q_array_;
};

typedef std::shared_ptr<LearnerEngine> LearnerEnginePtr;

} // namespace aiengine

#endif  // SRC_LEARNER_LEARNERENGINE_H_
