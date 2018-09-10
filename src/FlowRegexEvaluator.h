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
#ifndef SRC_FLOWREGEXEVALUATOR_H_
#define SRC_FLOWREGEXEVALUATOR_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ostream>
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Flow.h"
#include "regex/RegexManager.h"

namespace aiengine {

class FlowRegexEvaluator {
public:
	FlowRegexEvaluator():total_matched_regexs_(0) {}
    	virtual ~FlowRegexEvaluator() {}

	void processFlowPayloadLayer7(Flow *flow, const boost::string_ref &data);

	int32_t getTotalMatches() const { return total_matched_regexs_; }
private:
	int32_t total_matched_regexs_;
#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
};

} // namespace aiengine 

#endif  // SRC_FLOWREGEXEVALUATOR_H_
