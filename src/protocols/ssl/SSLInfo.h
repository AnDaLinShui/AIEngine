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
#ifndef SRC_PROTOCOLS_SSL_SSLINFO_H_
#define SRC_PROTOCOLS_SSL_SSLINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include "StringCache.h"
#include "names/DomainName.h"
#include "FlowInfo.h"

namespace aiengine {

class SSLInfo : public FlowInfo {
public:
        explicit SSLInfo() { reset(); }
        virtual ~SSLInfo() {}

        void reset(); 
	void serialize(JsonFlow &j); 

        SharedPointer<StringCache> host_name;
        SharedPointer<StringCache> issuer;
        SharedPointer<DomainName> matched_domain_name;

        void setIsBanned(bool value) { is_banned_ = value; }
        bool isBanned() const { return is_banned_; }

        void setAlert(bool value) { alert_ = value; }
        bool isAlert() const { return alert_; }

        void setAlertCode(int8_t value) { alert_code_ = value; }
        int8_t getAlertCode() const { return alert_code_; }

	void incDataPdus() { ++data_pdus_; }
	int32_t getTotalDataPdus() const { return data_pdus_; }

	void setVersion(uint16_t version) { version_ = version; }
	uint16_t getVersion() const { return version_; }

	void setHeartbeat(bool value) { heartbeat_ = value; }
	bool getHeartbeat() const { return heartbeat_; }

	void setCipher(uint16_t cipher) { cipher_ = cipher; }
	uint16_t getCipher() const { return cipher_; }

        friend std::ostream& operator<< (std::ostream &out, const SSLInfo &info);

#if defined(BINDING)
        const char *getServerName() const { return (host_name ? host_name->getName() : ""); }
        const char *getIssuerName() const { return (issuer ? issuer->getName() : ""); }
#endif

#if defined(PYTHON_BINDING)
        SharedPointer<DomainName> getMatchedDomainName() const { return matched_domain_name;}
#elif defined(RUBY_BINDING)
        DomainName& getMatchedDomainName() const { return *matched_domain_name.get();}
#elif defined(JAVA_BINDING) || defined(LUA_BINDING) || defined(GO_BINDING)
        DomainName& getMatchedDomainName() const { return *matched_domain_name.get();}
#endif

private:
	bool is_banned_:1;
	bool heartbeat_:1;
	bool alert_:1;
	uint16_t alert_code_;
	uint16_t version_;
	uint16_t cipher_;
	int32_t data_pdus_;
};

} // namespace aiengine  

#endif  // SRC_PROTOCOLS_SSL_SSLINFO_H_
