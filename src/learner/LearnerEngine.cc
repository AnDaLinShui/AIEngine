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
#include "LearnerEngine.h"

namespace aiengine {

LearnerEngine::LearnerEngine():
	length_(0),
	flows_(0),
	max_raw_expression_(maxBufferSize),
	byte_quality_(byteQuality),
	total_computes_(0),
	total_flows_(0),
	raw_expression_(""),
	regex_expression_(""),
	freq_group_(),
	q_array_() 
	{}

void LearnerEngine::reset() {

	flows_ = 0;
	length_ = 0;
	raw_expression_.clear();
	regex_expression_.clear();
	for (int i = 0; i < MAX_PACKET_FREQUENCIES_VALUES; ++i) q_array_[i].clear();
}


void LearnerEngine::statistics(std::basic_ostream<char> &out) const {

	out << "Learner statistics" << std::endl;
        out << "\t" << "Total computes:         " << std::setw(10) << total_computes_ << std::endl;
        out << "\t" << "Total computed flows:   " << std::setw(10) << total_flows_ << std::endl;
        out << "\t" << "Current flows:          " << std::setw(10) << flows_ << std::endl;
        out << "\t" << "Regex expression:" << regex_expression_ << std::endl;

	/* Just for debbuging regex
	for (int i = 0; i < 300; ++i) {
		for (auto it = q_array_[i].begin(); it!=q_array_[i].end(); ++it) {
			out << "(" << i <<")[" << std::hex << it->first << "," << std::dec << it->second << "]" << std::endl;
		}	
	}
	*/
}

void LearnerEngine::agregatePacketFlow(const SharedPointer<PacketFrequencies> &pkt_freq) {

	++flows_;
	++total_flows_;

	for (int i = 0; i < pkt_freq->getLength(); ++i) {
		uint8_t value = pkt_freq->index(i);

		auto it = q_array_[i].find(value);	
		if (it == q_array_[i].end()) { 
			q_array_[i].insert(std::make_pair(value, 1));
		} else {
			int *j = &it->second;
			++(*j);
		}		
	}
	if (length_< pkt_freq->getLength()) length_ = pkt_freq->getLength();
}

int LearnerEngine::get_quality_byte(int offset) const {

	int quality = 0;

	if (offset >= 0 && offset < MAX_PACKET_FREQUENCIES_VALUES) {
		int items = q_array_[offset].size();

		if ( flows_ > 0) {
			quality = 100 - (((items -1 ) * 100) / flows_);
		}	
	}
	return quality;
}

void LearnerEngine::compute() {

	std::ostringstream raw_expr;
	std::ostringstream expr;
	std::ostringstream token;
	std::ostringstream raw_token;	
	int length = 0;

	if (length_ > max_raw_expression_)
		length = max_raw_expression_;
	else
		length = length_;

	expr << "^";

	++total_computes_;
	
        for (int i = 0; i < length; ++i) {
        
		token.clear(); 
		token.str("");
		raw_token.clear(); 
		raw_token.str("");

		int quality = get_quality_byte(i);

		if ((quality >= byte_quality_) && (q_array_[i].size() > 0)) {
			unsigned short token_candidate = (q_array_[i].begin()->first);
			int quality_token = 0;
	
			for (auto it = q_array_[i].begin(); it != q_array_[i].end(); ++it) {
				if (it->second > quality_token) {
					quality_token = it->second;
					token_candidate = it->first;
				}
			}
			token << boost::format("\\x%02x") % token_candidate;
			raw_token << boost::format("%02x") % token_candidate;
		} else {
			token << ".?";
		}
		expr << token.str();
		raw_expr << raw_token.str();
        }

	std::ostringstream re_opt;

	// Remove .? and substitute for operators {n} or .*

	std::string candidate(expr.str());
	const char *r_data = candidate.c_str();
	int rlen = candidate.length();

	for (int i = 0; i < rlen ; ++i) {
		if (std::memcmp(".?", &r_data[i], 2) == 0 ) {

			int total_tokens = 0;
			for (int j = i; j < rlen; ++j) {
				if (std::memcmp(".?", &r_data[j], 2) == 0 ) {
					++total_tokens;
					++j;
				} else {
					break;
				}
			}	
		
			if (total_tokens > 1 ) {
				i += (total_tokens * 2) - 2;
		
				re_opt << ".{" << total_tokens << "}";
			} else {
				re_opt << r_data[i] << r_data[i + 1];
			}	
			++i;
		} else {
			re_opt << r_data[i];
		}
	}

	regex_expression_ = re_opt.str();
	raw_expression_ = raw_expr.str();
}


#if defined(PYTHON_BINDING)
void LearnerEngine::agregateFlows(boost::python::list flows) {

	boost::python::ssize_t len = boost::python::len(flows);
    	for (int i = 0; i < len; ++i) {
	
		SharedPointer<Flow> flow = boost::python::extract<SharedPointer<Flow>>(flows[i]);
#elif defined(RUBY_BINDING)
void LearnerEngine::agregateFlows(VALUE flows) {

	size_t len = RARRAY_LEN(flows);
	for (int i = 0; i < len; ++i) {
		VALUE obj = rb_ary_entry(flows,i);
		Flow *flow = nullptr;
	
		Data_Get_Struct(obj, Flow, flow);
#else
void LearnerEngine::agregateFlows(const std::vector<WeakPointer<Flow>> &flows) {

	for (auto it = flows.begin(); it != flows.end(); ++it) {
	
		SharedPointer<Flow> flow = (*it).lock();
#endif
		if (flow) {
                	if (flow->packet_frequencies) {
                        	agregatePacketFlow(flow->packet_frequencies);
                        }
                }
	}
}

std::string LearnerEngine::getAsciiExpression() {
	std::ostringstream out;

	for (std::size_t i = 0; i < raw_expression_.length(); i = i + 2) {
		int a = (raw_expression_[i] - 48) * 16;
		int b = raw_expression_[i + 1];
		if ((b >= 97) && (b <= 102))
			b -= 32;
		if (b < 65)
			out << char(a + b - 48);
		else
			out << char(a + b - 55);
	} 
	return out.str();
}

std::ostream& operator<< (std::ostream &out, const LearnerEngine &le) {

        le.statistics(out);

        return out;
}

} // namespace aiengine 
