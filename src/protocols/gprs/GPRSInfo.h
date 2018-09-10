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
#ifndef SRC_PROTOCOLS_GPRS_GPRSINFO_H_ 
#define SRC_PROTOCOLS_GPRS_GPRSINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <sstream>
#include "FlowInfo.h"

namespace aiengine {

#define PDP_END_USER_TYPE_IPV4 0x21
#define PDP_END_USER_TYPE_IPV6 0x57

class GPRSInfo : public FlowInfo {
public:
    	explicit GPRSInfo() { reset(); }
    	virtual ~GPRSInfo() {}

        void reset(); 
	void serialize(JsonFlow &j); 

	void setPdpTypeNumber(uint8_t type) { pdp_type_number_ = type; }
	uint8_t getPdpTypeNumber() const { return pdp_type_number_; }
	void setIMSI(uint64_t imsi) { imsi_ = imsi; }
	uint64_t getIMSI() const { return imsi_; }

	std::string& getIMSIString() const ; 

        friend std::ostream& operator<< (std::ostream &out, const GPRSInfo &info);
        
private:
	uint64_t imsi_;
	uint64_t imei_;
	uint8_t pdp_type_number_;
};

} // namespace aiengine
 

#endif  // SRC_PROTOCOLS_GPRS_GPRSINFO_H_
