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
#ifndef SRC_PROTOCOLS_HTTP_HTTPINFO_H_
#define SRC_PROTOCOLS_HTTP_HTTPINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "StringCache.h"
#include "names/DomainName.h"
#include "FlowDirection.h"
#include "FlowInfo.h"
#include <iostream>
#include <vector> 

namespace aiengine {

class HTTPInfo : public FlowInfo {
public:
    	explicit HTTPInfo() { reset(); }
    	virtual ~HTTPInfo() {}

	void reset(); 
	void serialize(JsonFlow &j); 
	void resetStrings();

	int64_t getContentLength() const { return content_length_; }
	void setContentLength(int64_t content_length) { content_length_ = content_length; }

	int32_t getDataChunkLength() const { return data_chunk_length_; }
	void setDataChunkLength(int32_t length) { data_chunk_length_ = length; }
	
	void setIsBanned(bool value) { is_banned_ = value; }
	bool isBanned() const { return is_banned_; }

	void setHaveData(bool value) { have_data_ = value; }
	bool getHaveData() const { return have_data_; }

	// Write the URI on a DatabaseAdaptor if have been match with something
	void setWriteUri(bool value) { write_uri_ = value; }
	bool getWriteUri() const { return write_uri_; }

	void incTotalRequests() { ++total_requests_; }
	void incTotalResponses() { ++total_responses_; }

	int16_t getTotalRequests() const { return total_requests_; }
	int16_t getTotalResponses() const { return total_responses_; }

	void setResponseCode(int16_t code) { response_code_ = code; }
	int16_t getResponseCode() const { return response_code_; }

	void setHTTPDataDirection(FlowDirection dir) { direction_ = dir; }
	FlowDirection getHTTPDataDirection() const { return direction_; }

        SharedPointer<StringCache> uri;
        SharedPointer<StringCache> host_name;
        SharedPointer<StringCache> ua;
        SharedPointer<StringCache> ct;
        SharedPointer<StringCache> filename;
	SharedPointer<DomainName> matched_domain_name;

	friend std::ostream& operator<< (std::ostream &out, const HTTPInfo &info);

#if defined(BINDING)
	void setBanAndRelease(bool value) { needs_release_ = value; is_banned_ = value; }
	void setIsRelease(bool value) { needs_release_ = value; }
	bool getIsRelease() const { return needs_release_; }

	const char *getUri() const { return  (uri ? uri->getName() : ""); }	
	const char *getHostName() const { return (host_name ? host_name->getName() : ""); }	
	const char *getUserAgent() const { return (ua ? ua->getName() : ""); }	
	const char *getContentType() const { return (ct ? ct->getName() : ""); }	
	const char *getFilename() const { return (filename ? filename->getName() : ""); }	
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
	bool have_data_:1;
	bool is_banned_:1;
	bool write_uri_:1;
#if defined(BINDING)
	bool needs_release_:1;
#endif
	int64_t content_length_;	
	int32_t data_chunk_length_;
	int16_t total_requests_;
	int16_t total_responses_;	
	int16_t response_code_;
        FlowDirection direction_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_HTTP_HTTPINFO_H_
