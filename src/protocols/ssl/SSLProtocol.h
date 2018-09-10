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
#ifndef SRC_PROTOCOLS_SSL_SSLPROTOCOL_H_
#define SRC_PROTOCOLS_SSL_SSLPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "SSLInfo.h"
#include "Cache.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <boost/utility/string_ref.hpp> 
#include "flow/FlowManager.h"

namespace aiengine {

// Minium SSL header
struct ssl_record {
	uint8_t 	type; 		/* SSL record type */
	uint16_t 	version; 	/* SSL version (major/minor) */
	uint16_t 	length; 	/* Length of data in the record (excluding the header itself), The maximum SSL supports is 16384 (16K). */
	uint8_t 	data[0];	
} __attribute__((packed));

struct handshake_record {
	uint8_t		type;
	uint8_t		padd;
	uint16_t	length;
	uint8_t		data[0];
} __attribute__((packed));

// The only supported versions
#define SSL3_VERSION 0x0300
#define TLS1_VERSION 0x0301
#define TLS1_1_VERSION 0x0302
#define TLS1_2_VERSION 0x0303
#define TLS1_3_VERSION 0x0304 // Beta mode

// Record_type
#define SSL3_CT_HANDSHAKE		22
#define SSL3_CT_ALERT 			21
#define SSL3_CT_CHANGE_CIPHER_SPEC 	20
#define SSL3_CT_APPLICATION_DATA 	23

// Record types of the ssl_handshake_record
#define SSL3_MT_HELLO_REQUEST            0   //(x'00')
#define SSL3_MT_CLIENT_HELLO             1   //(x'01')
#define SSL3_MT_SERVER_HELLO             2   //(x'02')
#define SSL3_MT_CERTIFICATE             11   //(x'0B')
#define SSL3_MT_SERVER_KEY_EXCHANGE     12   // (x'0C')
#define SSL3_MT_CERTIFICATE_REQUEST     13   // (x'0D')
#define SSL3_MT_SERVER_DONE             14   // (x'0E')
#define SSL3_MT_CERTIFICATE_VERIFY      15   // (x'0F')
#define SSL3_MT_CLIENT_KEY_EXCHANGE     16   // (x'10')
#define SSL3_MT_FINISHED                20   // (x'14')

struct ssl_hello {
	uint8_t 	handshake_type[2];
	uint16_t 	length;
	uint16_t 	version;
	uint8_t 	random[32];
	uint8_t 	session_id_length;
	uint8_t 	data[0];
} __attribute__((packed)); 

struct ssl_extension {
	uint16_t 	type;
	short 		length;
	uint8_t 	data[0];
} __attribute__((packed)); 

struct ssl_server_name {
	uint16_t 	list_length;
	uint8_t 	type;
	uint16_t 	length;
	uint8_t 	data[0];
} __attribute__((packed)); 

struct ssl_cert {
	uint16_t 	type;
	uint16_t 	length;
	uint8_t 	pad1;
	uint16_t 	cert_length;
	uint8_t 	data[0];
} __attribute__((packed)); 

class SSLProtocol: public Protocol {
public:
    	explicit SSLProtocol();
    	virtual ~SSLProtocol(); 

	static const uint16_t id = 0;
	static const int header_size = sizeof(ssl_record);

	int getHeaderSize() const { return header_size; }

	bool processPacket(Packet &packet) override { return true; }
	void processFlow(Flow *flow) override;

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override;

        void setHeader(const uint8_t *raw_packet) override {
        
                header_ = reinterpret_cast<const ssl_record*>(raw_packet);
        }

	// Condition for say that a payload is ssl 
	bool sslChecker(Packet &packet); 

        void increaseAllocatedMemory(int value) override;
        void decreaseAllocatedMemory(int value) override;

	void setDomainNameManager(const SharedPointer<DomainNameManager> &dm) override; 
	void setDomainNameBanManager(const SharedPointer<DomainNameManager> &dm) override { ban_domain_mng_ = dm; }

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	int64_t getCurrentUseMemory() const override;
	int64_t getAllocatedMemory() const override;
	int64_t getTotalAllocatedMemory() const override;

        void setDynamicAllocatedMemory(bool value) override;
        bool isDynamicAllocatedMemory() const override;

	int32_t getTotalCacheMisses() const override;
	int32_t getTotalEvents() const override { return total_events_; }

	CounterMap getCounters() const override;

#if defined(PYTHON_BINDING)
	boost::python::dict getCache() const override;
	void showCache(std::basic_ostream<char> &out) const override; 
#elif defined(RUBY_BINDING)
        VALUE getCache() const;
#endif

#if defined(STAND_ALONE_TEST) || defined(TESTING)
	// Just for testing purposes on the unit test
	Cache<StringCache>::CachePtr getHostCache() const { return host_cache_; }
	GenericMapType *getHostMap() { return &host_map_; }
	GenericMapType *getIssuerMap() { return &issuer_map_; }
        int32_t getTotalHandshakes() const { return total_handshakes_; }
        int32_t getTotalAlerts() const { return total_alerts_; }
        int32_t getTotalChangeCipherSpecs() const { return total_change_cipher_specs_; }
        int32_t getTotalDatas() const { return total_data_; }

        int32_t getTotalClientHellos() const { return total_client_hellos_; }
        int32_t getTotalServerHellos() const { return total_server_hellos_; }
        int32_t getTotalCertificates() const { return total_certificates_; }
        int32_t getTotalCertificateRequests() const { return total_certificate_requests_; }
        int32_t getTotalCertificateVerifies() const { return total_certificate_verifies_; }
        int32_t getTotalServerDones() const { return total_server_dones_; } 
	int32_t getTotalServerKeyExchanges() const {  return total_server_key_exchanges_; }
	int32_t getTotalClientKeyExchanges() const {  return total_client_key_exchanges_; }
	int32_t getTotalHandshakeFinishes() const { return total_handshake_finishes_; }
        int32_t getTotalRecords() const { return total_records_; }
        int32_t getTotalBanHosts() const { return total_ban_hosts_; }
        int32_t getTotalAllowHosts() const { return total_allow_hosts_; }
#endif

	void setAnomalyManager(SharedPointer<AnomalyManager> amng) override { anomaly_ = amng; }

	Flow* getCurrentFlow() const { return current_flow_; }

	void releaseFlowInfo(Flow *flow) override;

private:
        int32_t release_ssl_info(SSLInfo *info);
	int64_t compute_memory_used_by_maps() const;

	void handle_handshake(SSLInfo *info, const ssl_record *record, int length);
	void handle_client_hello(SSLInfo *info, const uint8_t *data, int length);
	void handle_server_hello(SSLInfo *info, const uint8_t *data, int length);
	void handle_certificate(SSLInfo *info, const uint8_t *data, int length);
	void handle_issuer_certificate(SSLInfo *info, const uint8_t *data, int length);

	void attach_host(SSLInfo *info, const boost::string_ref &servername); 
	void attach_common_name(SSLInfo *info, const boost::string_ref &name); 

	short get_asn1_length(short byte);

	const ssl_record *header_;
        int32_t total_events_;
	// content types
	int32_t total_handshakes_;
	int32_t total_alerts_;
	int32_t total_change_cipher_specs_;
	int32_t total_data_;
	// handshake types
	int32_t total_client_hellos_;
	int32_t total_server_hellos_;
	int32_t total_certificates_;
	int32_t total_server_key_exchanges_;
	int32_t total_certificate_requests_;
	int32_t total_server_dones_;
	int32_t total_certificate_verifies_;
	int32_t total_client_key_exchanges_;
	int32_t total_handshake_finishes_;
	int32_t total_records_;
	int32_t total_ban_hosts_;
	int32_t total_allow_hosts_;

	Cache<SSLInfo>::CachePtr info_cache_;
	Cache<StringCache>::CachePtr host_cache_;
	Cache<StringCache>::CachePtr issuer_cache_;

        GenericMapType host_map_;
        GenericMapType issuer_map_;

        SharedPointer<DomainNameManager> domain_mng_;
        SharedPointer<DomainNameManager> ban_domain_mng_;
	FlowManagerPtrWeak flow_mng_;

#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
	Flow *current_flow_; // For accessing for logging
	SharedPointer<AnomalyManager> anomaly_;
};

typedef std::shared_ptr<SSLProtocol> SSLProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SSL_SSLPROTOCOL_H_
