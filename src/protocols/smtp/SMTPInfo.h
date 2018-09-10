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
#ifndef SRC_PROTOCOLS_SMTP_SMTPINFO_H_
#define SRC_PROTOCOLS_SMTP_SMTPINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <vector> 
#include "Pointer.h"
#include "StringCache.h"
#include "FlowInfo.h"
#include "names/DomainName.h"

namespace aiengine {

class SMTPInfo : public FlowInfo {
public:
    	explicit SMTPInfo() { reset(); }
    	virtual ~SMTPInfo() {}

	void reset();
	void serialize(JsonFlow &j); 
	
	void setCommand(int8_t command) { command_ = command; }
	int8_t getCommand() const { return command_; }

	void resetStrings();

        void setIsBanned(bool value) { is_banned_ = value; }
        bool isBanned() const { return is_banned_; }

	void setIsData(bool value) { is_data_ = value; }
	bool isData() const { return is_data_; }

        void setStartTLS(bool value) { is_starttls_ = value; }
        bool isStartTLS() const { return is_starttls_; }
	
	void incTotalDataBytes(int32_t value) { total_data_bytes_ += value; }
	int32_t getTotalDataBytes() const { return total_data_bytes_; }

	void incTotalDataBlocks() { ++total_data_blocks_; }
	int32_t getTotalDataBlocks() { return total_data_blocks_; }

        SharedPointer<StringCache> from;
        SharedPointer<StringCache> to;
        SharedPointer<DomainName> matched_domain_name;

	friend std::ostream& operator<< (std::ostream &out, const SMTPInfo &info);

#if defined(BINDING)
	const char *getFrom() const { return (from ? from->getName() : ""); }	
	const char *getTo() const { return (to ? to->getName() : ""); }	
#endif

#if defined(PYTHON_BINDING)
        SharedPointer<DomainName> getMatchedDomainName() const { return matched_domain_name;}
#elif defined(RUBY_BINDING)
        DomainName& getMatchedDomainName() const { return *matched_domain_name.get(); }
#elif defined(JAVA_BINDING)
        DomainName& getMatchedDomainName() const { return *matched_domain_name.get(); }
#elif defined(LUA_BINDING)
        DomainName& getMatchedDomainName() const { return *matched_domain_name.get(); }
#endif

private:
	int8_t command_;	
	bool is_banned_:1;
	bool is_data_:1;
	bool is_starttls_:1;
	int32_t total_data_bytes_;
	int32_t total_data_blocks_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SMTP_SMTPINFO_H_
