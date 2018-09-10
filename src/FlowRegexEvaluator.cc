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
#include "FlowRegexEvaluator.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr FlowRegexEvaluator::logger(log4cxx::Logger::getLogger("aiengine.evaluator"));
#endif

void FlowRegexEvaluator::processFlowPayloadLayer7(Flow *flow, const boost::string_ref &data) {

	auto regex = flow->regex.lock();
	bool result = false;

        if ((regex)and(!regex->getContinue())) { // The flow have been matched with some regex
        	if (regex->isTerminal() == false) {
                	regex = regex->getNextRegex();
                        if (regex)
                        	result = regex->evaluate(data);
		}
	} else {
		if (flow->regex_mng) {
			flow->regex_mng->evaluate(data, &result);
			if (result) 
				regex = flow->regex_mng->getMatchedRegex();
		}
	}

	if ((result)and(regex)) {
		++total_matched_regexs_;
		if (regex->getShowMatch()) {
			/* LCOV_EXCL_START */
			std::cout << std::dec << "Flow:[" << *flow << "] pkts:" << flow->total_packets << " matchs with (";
			std::cout << std::addressof(*regex.get()) << ")Regex [" << regex->getName() << "]" << std::endl;
			if (regex->getShowPacket())
				showPayload(std::cout, flow->packet->getPayload(), flow->packet->getLength());
			/* LCOV_EXCL_STOP */
		}
#ifdef HAVE_LIBLOG4CXX
		LOG4CXX_INFO(logger, "Flow:" << *flow << " matchs with " << regex->getName());
#endif
		flow->regex = regex;
		auto next_rm = regex->getNextRegexManager();
		if (next_rm) {
			flow->regex_mng = next_rm;
			flow->regex.reset();
		}
#if defined(BINDING)

		if (flow->regex_mng->call.haveCallback()) {
			flow->regex_mng->call.executeCallback(flow);
		} else {
			if (regex->call.haveCallback()) {
				regex->call.executeCallback(flow);
			}
		}

		if (regex->getWritePacket()) flow->setWriteMatchedPacket(true);
#endif
		if (regex->getRejectConnection()) flow->setReject(true);
		if (regex->haveEvidence()) flow->setEvidence(true);

                // Force to write on the databaseAdaptor update method
                flow->packet->setForceAdaptorWrite(true);
	}
}

} // namespace aiengine

