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
#include "SSLProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr SSLProtocol::logger(log4cxx::Logger::getLogger("aiengine.ssl"));
#endif

SSLProtocol::SSLProtocol():
	Protocol("SSLProtocol", "ssl", IPPROTO_TCP),
	header_(nullptr),
	total_events_(0),
        total_handshakes_(0),
        total_alerts_(0),
        total_change_cipher_specs_(0),
        total_data_(0),
	total_client_hellos_(0),
	total_server_hellos_(0),
	total_certificates_(0),
        total_server_key_exchanges_(0),
        total_certificate_requests_(0),
	total_server_dones_(0),
	total_certificate_verifies_(0),
	total_client_key_exchanges_(0),
	total_handshake_finishes_(0),
	total_records_(0),
	total_ban_hosts_(0),
	total_allow_hosts_(0),
	info_cache_(new Cache<SSLInfo>("SSL Info cache")),
	host_cache_(new Cache<StringCache>("Host cache")),
	issuer_cache_(new Cache<StringCache>("Issuer cache")),
	host_map_(),
	issuer_map_(),
	domain_mng_(),
	ban_domain_mng_(),
	flow_mng_(),
	current_flow_(nullptr),
	anomaly_() {}

SSLProtocol::~SSLProtocol() { 

	anomaly_.reset(); 
}

bool SSLProtocol::sslChecker(Packet &packet) {

        int length = packet.getLength();

        if (length >= header_size) {
		const uint8_t *payload = packet.getPayload();
		if ((payload[0] == 0x16)and(payload[1] == 0x03)) {
			setHeader(payload);
			++total_valid_packets_;
			return true;
		}
	}
	++total_invalid_packets_;
	return false;
}

void SSLProtocol::setDynamicAllocatedMemory(bool value) {

	info_cache_->setDynamicAllocatedMemory(value);
	host_cache_->setDynamicAllocatedMemory(value);
	issuer_cache_->setDynamicAllocatedMemory(value);
}

bool SSLProtocol::isDynamicAllocatedMemory() const {

	return info_cache_->isDynamicAllocatedMemory();	
}

int64_t SSLProtocol::getCurrentUseMemory() const {

	int64_t mem = sizeof(SSLProtocol);

	mem += info_cache_->getCurrentUseMemory();
	mem += host_cache_->getCurrentUseMemory();
	mem += issuer_cache_->getCurrentUseMemory();

	return mem;
}

int64_t SSLProtocol::getAllocatedMemory() const {

        int64_t mem = sizeof(SSLProtocol); 

        mem += info_cache_->getAllocatedMemory();
        mem += host_cache_->getAllocatedMemory();
        mem += issuer_cache_->getAllocatedMemory();

        return mem;
}

int64_t SSLProtocol::getTotalAllocatedMemory() const {

	int64_t mem = getAllocatedMemory();

	mem += compute_memory_used_by_maps();

	return mem;
}

int32_t SSLProtocol::release_ssl_info(SSLInfo *info) {

        int32_t bytes_released = 0;

	bytes_released = releaseStringToCache(host_cache_, info->host_name);
	bytes_released += releaseStringToCache(issuer_cache_, info->issuer);

        return bytes_released;
}

int64_t SSLProtocol::compute_memory_used_by_maps() const {

	int64_t bytes = (host_map_.size() + issuer_map_.size()) * sizeof(StringCacheHits);
	
        // Compute the size of the strings used as keys on the map
        std::for_each (host_map_.begin(), host_map_.end(), [&bytes] (PairStringCacheHits const &ht) {
        	bytes += ht.first.size();
	});
        std::for_each (issuer_map_.begin(), issuer_map_.end(), [&bytes] (PairStringCacheHits const &ht) {
        	bytes += ht.first.size();
	});
	
	return bytes;
}

int32_t SSLProtocol::getTotalCacheMisses() const {
	
	int32_t miss = 0;

	miss = info_cache_->getTotalFails();
	miss += host_cache_->getTotalFails();
	miss += issuer_cache_->getTotalFails();

	return miss;
}

void SSLProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

		int64_t total_bytes_released = compute_memory_used_by_maps();
		int64_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;
                int32_t release_hosts = host_map_.size();
                int32_t release_issuers = issuer_map_.size();

                for (auto &flow: ft) {
		       	auto info = flow->getSSLInfo();
               		if (info) { 
                                total_bytes_released_by_flows += release_ssl_info(info.get());
                                total_bytes_released_by_flows += sizeof(info);

                                flow->layer7info.reset();
                                info_cache_->release(info);
				++release_flows;
                        }
                } 
	        host_map_.clear();
		issuer_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);
                }
        
        	msg.str("");
                msg << "Release " << release_hosts << " hosts, " << release_issuers << " issuers, " << release_flows << " flows";
		msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}


void SSLProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getSSLInfo();
	if (info) {
		info_cache_->release(info);
	}
}

void SSLProtocol::attach_common_name(SSLInfo *info, const boost::string_ref &name) {

        if (!info->issuer) {
                auto it = issuer_map_.find(name);
                if (it == issuer_map_.end()) {
                        auto name_ptr = issuer_cache_->acquire();
                        if (name_ptr) {
                                name_ptr->setName(name.data(), name.length());
                                info->issuer = name_ptr;
                                issuer_map_.insert(std::make_pair(name_ptr->getName(), name_ptr));
                        }
                } else {
                        ++ (it->second).hits;
                        info->issuer = (it->second).sc;
                }
        }
}

void SSLProtocol::attach_host(SSLInfo *info, const boost::string_ref &host) {

	if (!info->host_name) {
                auto it = host_map_.find(host);
                if (it == host_map_.end()) {
                        auto host_ptr = host_cache_->acquire();
                        if (host_ptr) {
                                host_ptr->setName(host.data(), host.length());
                                info->host_name = host_ptr;
                                host_map_.insert(std::make_pair(host_ptr->getName(), host_ptr));
                        }
                } else {
                        ++ (it->second).hits;
                        info->host_name = (it->second).sc;
                }
        }
}

void SSLProtocol::handle_client_hello(SSLInfo *info, const uint8_t *data, int length) {

#ifdef DEBUG
	std::cout << __FILE__ << ":" << __func__ << ":length:" << std::dec << length << std::endl;
#endif
	const ssl_hello *hello = reinterpret_cast<const ssl_hello*>(data); 
	uint16_t version = ntohs(hello->version);
	int block_offset = sizeof(ssl_hello);

	++ total_client_hellos_;

	if ((version >= SSL3_VERSION)and(version <= TLS1_2_VERSION)) {
		int len = ntohs(hello->length);

		if (ntohs(hello->session_id_length) > 0) {
			// Session id management
			// the alignment of the struct should be fix
			block_offset += 32;
		}

		uint16_t cipher_length = ntohs((data[block_offset + 1] << 8) + data[block_offset]);
		if (cipher_length < len) {

			block_offset += cipher_length  + 2;
			const uint8_t *compression_pointer = &data[block_offset];
			short compression_length = compression_pointer[0];
		
			if (compression_length > 0) {
				block_offset += (compression_length + 1);
			}
			if (block_offset < len) {
				const uint8_t *extensions = &data[block_offset];
				uint16_t extensions_length __attribute__((unused)) = ((extensions[0] << 8) + extensions[1]);

				block_offset += 2;
				while (block_offset < len) {
					const ssl_extension *extension = reinterpret_cast<const ssl_extension*>(&data[block_offset]);
					if (extension->type == 0x0000) { // Server name
						const ssl_server_name *server = reinterpret_cast<const ssl_server_name*>(&extension->data[0]);
						int server_length = ntohs(server->length);
						
						if ((block_offset + server_length < len)and(server_length > 0)) {
							boost::string_ref servername((char*)server->data, server_length);
				
							if (ban_domain_mng_) {		
								auto host_candidate = ban_domain_mng_->getDomainName(servername);
								if (host_candidate) {
#ifdef HAVE_LIBLOG4CXX
									LOG4CXX_INFO (logger, "Flow:" << *current_flow_ << " matchs with banned host " << host_candidate->getName());
#endif
									++total_ban_hosts_;
									info->setIsBanned(true);
									return;
								}
							}
							++total_allow_hosts_;

							attach_host(info, servername);
						}	
					} else {
						if (extension->type == 0x01FF) { // Renegotiation
							// TODO std::cout << "RENEOGOTIATIONT" << std::endl;
						} else {
							if (extension->type == 0x0F00) { // Heartbeat
								info->setHeartbeat(true);
							} else {
								if (extension->type == 0x000D) {
									// TODO std::cout << "signature algorithm" << std::endl;
								}
							}
						}
					}	
					block_offset += ntohs(extension->length) + sizeof(ssl_extension);
				}
			}	
		}
	} // end version 
	return;
}

void SSLProtocol::handle_server_hello(SSLInfo *info, const uint8_t *data, int length) {

#ifdef DEBUG
	std::cout << __FILE__ << ":" << __func__ << ":length:" << std::dec << length << std::endl;
#endif
	const ssl_hello *hello __attribute__((unused)) = reinterpret_cast<const ssl_hello*>(data); 
        uint16_t version = ntohs(hello->version);
        int block_offset = sizeof(ssl_hello);

	++ total_server_hellos_;

        if ((version >= SSL3_VERSION)and(version <= TLS1_2_VERSION)) {
                int len = ntohs(hello->length);

                if (ntohs(hello->session_id_length) > 0) {
                        // Session id management
                        // the alignment of the struct should be fix
                        block_offset += 32;
                }
		uint16_t cipher_id = ntohs((data[block_offset + 1] << 8) + data[block_offset]);
		info->setCipher(cipher_id);
	} else if (hello->version == 0x0E7F) { // This is TLS1.3 draft
		info->setVersion(TLS1_3_VERSION);
	}
}

short SSLProtocol::get_asn1_length(short byte) {

	short value = byte;

	value &= ~(1 << 7);
	if (byte & (1 << 7)) { // The bit 8 is set
		value &= ~(1 << 6);
	}

	return value;
}

void SSLProtocol::handle_issuer_certificate(SSLInfo *info, const uint8_t *data, int length) {

	// Handle the ASN1 issuer component
	const uint8_t *ptr = &data[4];
	int off = 0;

#ifdef DEBUG
	std::cout << __FILE__ << ":" <<  __func__ << ":len:" << std::dec << length << std::endl;
        showPayload(std::cout, data, length - 8);
#endif
	while (off < length - (8 + 9)) { // one of the items 
		if (ptr[0] == 0x06) { // Object identifier
			if ((ptr[2] == 0x55)and(ptr[3] == 0x04)and(ptr[4] == 0x03)) { // id-at-commonName 
				short atype = ptr[5];
				if ((atype == 0x13)or(atype == 0x14)or(atype == 0x0C)) {
					// PrintableString(0x13), teletextString(0x14), DirectorySTring(0x0C)
					short alen = get_asn1_length(ptr[6]);
					boost::string_ref name((char*)&ptr[7], alen);
#ifdef DEBUG
					std::cout << __FILE__ << ":" <<  __func__ << ":commonName:" << name << std::endl;
#endif
					attach_common_name(info, name);
					return;
				}
			}
		} 
		++ptr; 
		++off;
	}
}

void SSLProtocol::handle_certificate(SSLInfo *info, const uint8_t *data, int length) {

#ifdef DEBUG
	std::cout << __FILE__ << ":" << __func__ << ":len:" << std::dec << length << std::endl;
#endif
	const ssl_cert *record = reinterpret_cast<const ssl_cert*>(data); 
        uint16_t type = record->type;
	int16_t len = ntohs(record->cert_length);

	/* The cert is encode with ASN1 DER format from &data[sizeof(ssl_cert)] */
	++ total_certificates_;
	const uint8_t *ptr = &data[sizeof(ssl_cert)];

#ifdef DEBUG
	std::cout << "CERT Payload, rlen:" << len << " len:" << length << " atype:" << std::hex << (short)ptr[0] << "\n";
	// showPayload(std::cout, data, length);
#endif
	short alen = get_asn1_length(ptr[12]);
	short atype = ptr[11];
	
	if (atype == 0xA0) { // Enumerated of the items
		ptr = &ptr[11 + alen + 2];

		atype = ptr[0];
		alen = get_asn1_length(ptr[1]);
		if (atype == 0x02) { // serialNumber integer
			ptr = &ptr[alen + 2];

			atype = ptr[0];
			if (atype == 0x30) { // signature 
				handle_issuer_certificate(info, ptr, length - (ptr - data - sizeof(ssl_cert)));
			}	
		}
	}
}

void SSLProtocol::handle_handshake(SSLInfo *info, const ssl_record *record, int length) {

	uint16_t version = ntohs(record->version);
	uint8_t type = record->data[0];
	int record_length = ntohs(record->length);

#ifdef DEBUG
	std::cout << __FILE__ << ":" << __func__ << ":Container:len:" << length;
	std::cout << " rlen:" << record_length << " type:" << int(type) << std::endl;
#endif

	if ((version >= SSL3_VERSION)and(version <= TLS1_2_VERSION)) {

		info->setVersion(version);

		// This is a valid SSL header that we could extract some usefulll information.
		// SSL Records are group by blocks

		int max_records = 0;
		int offset = 0;
		const uint8_t *ssl_data = record->data;

		if (length < sizeof(handshake_record)) {
                       	++total_events_;
                        if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                               	current_flow_->setPacketAnomaly(PacketAnomalyType::SSL_BOGUS_HEADER);
                        }
                        anomaly_->incAnomaly(current_flow_, PacketAnomalyType::SSL_BOGUS_HEADER); 
			return;
		}

		do {	
			const handshake_record *hsk_record = reinterpret_cast<const handshake_record*>(&ssl_data[offset]);
			record_length = ntohs(hsk_record->length);
			type = hsk_record->type;
#ifdef DEBUG
			std::cout << __FILE__ << ":" << __func__ << ":record:len:" << length << " rlen:" << record_length;
			std::cout << " type:" << int(type) << std::endl;
#endif
			++max_records;

			if ((record_length > length)and(type != SSL3_MT_CERTIFICATE)and(type < SSL3_MT_FINISHED)) {
                        	++total_events_;
                                if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                                	current_flow_->setPacketAnomaly(PacketAnomalyType::SSL_BOGUS_HEADER);
                                }
                                anomaly_->incAnomaly(current_flow_, PacketAnomalyType::SSL_BOGUS_HEADER);
				return;	
			}


			if (type == SSL3_MT_CLIENT_HELLO) {
				handle_client_hello(info, ssl_data, length);
			} else if (type == SSL3_MT_SERVER_HELLO)  {
				handle_server_hello(info, ssl_data, length);
			} else if (type == SSL3_MT_CERTIFICATE) {
				handle_certificate(info, &ssl_data[offset], length - offset);
			} else if (type == SSL3_MT_SERVER_KEY_EXCHANGE) {
				++total_server_key_exchanges_;				
			} else if (type == SSL3_MT_CERTIFICATE_REQUEST) {
				++total_certificate_requests_;
			} else if (type == SSL3_MT_SERVER_DONE) {
				++total_server_dones_;
			} else if (type == SSL3_MT_CERTIFICATE_VERIFY) {
				++total_certificate_verifies_;
			} else if (type == SSL3_MT_CLIENT_KEY_EXCHANGE) {
				++total_client_key_exchanges_;
			} else if (type >= SSL3_MT_FINISHED) {
				++total_handshake_finishes_;
			}

			offset += record_length + sizeof(handshake_record);
		
		} while ((offset + sizeof(handshake_record) <= length) and (max_records < 3));
	}					
}

void SSLProtocol::processFlow(Flow *flow) {

	++total_packets_;
	int length = flow->packet->getLength();
	total_bytes_ += length;
	++flow->total_packets_l7;

        auto info = flow->getSSLInfo();
        if (!info) {
                info = info_cache_->acquire();
                if (!info) {
#ifdef HAVE_LIBLOG4CXX
			LOG4CXX_WARN (logger, "No memory on '" << info_cache_->getName() << "' for flow:" << *flow);
#endif
			return;
                }
                flow->layer7info = info;
        }

        if (info->isBanned() == true) {
                // No need to process the SSL pdu.
                return;
        }

	current_flow_ = flow;

	if (length > header_size) {
		setHeader(flow->packet->getPayload());
		const uint8_t *payload = flow->packet->getPayload();

		if (flow->total_packets_l7 < 4) { 
			int record_length = ntohs(header_->length);

			if (record_length > 0) {
				const ssl_record *record = header_;
				int offset = 0;         // Total offset byte
				int maxattemps = 0;     // For prevent invalid decodings

				do {
					record = reinterpret_cast<const ssl_record*>(&payload[offset]);
					uint16_t version = ntohs(record->version);
					short type = record->type;
					record_length = ntohs(record->length);
					++maxattemps;
#ifdef DEBUG
					std::cout << __FILE__ << ":" << __func__ << ":len:" << length << " rlen:" << record_length;
					std::cout << " type: " << int(type) << " offset:" << offset << std::endl;
#endif
					if (type == SSL3_CT_HANDSHAKE) {
						// There is a ssl record with the minimal length
						++total_handshakes_;

						// Check if the record length is valid, if not truncate
						if (offset + record_length + sizeof(handshake_record) > length ) {
							record_length = length - (offset + sizeof(handshake_record));
						}

						handle_handshake(info.get(), record, record_length); 
					} else if (type == SSL3_CT_CHANGE_CIPHER_SPEC) {
						++total_change_cipher_specs_;
					} else if (type == SSL3_CT_APPLICATION_DATA) { // On Tls1.3 encrypted data can be sent
						++total_data_;
						info->incDataPdus();
					}

					++total_records_;

					offset += record_length + sizeof(ssl_record);

					if (maxattemps == 5) break; // Maximum Pdus per packet allowed
				} while (offset + sizeof(ssl_record) < length);
			}

			if (flow->total_packets_l7 == 1) {
				if ((domain_mng_)and(info->host_name)) { 
					auto host_candidate = domain_mng_->getDomainName(info->host_name->getName());
					if (host_candidate) {
						++total_events_;
						info->matched_domain_name = host_candidate;
#if defined(BINDING)
#ifdef HAVE_LIBLOG4CXX
						LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with " << host_candidate->getName());
#endif  
						if (host_candidate->call.haveCallback()) {
							host_candidate->call.executeCallback(flow);
						}
#endif
					}
				}
			}
		} else {
			// Check if the PDU is encrypted data
			if (header_->type == SSL3_CT_APPLICATION_DATA) { 
				++total_data_;
				info->incDataPdus();
			} else if (header_->type == SSL3_CT_ALERT) {
				// Is an Alert messsage
				info->setAlert(true);
				++total_alerts_;
				int length = ntohs(header_->length);
				if (length >= 2) { // Regular length of alerts
					int8_t value = header_->data[1];
					info->setAlertCode(value);
				}
			}
		}
	}
}

void SSLProtocol::setDomainNameManager(const SharedPointer<DomainNameManager> &dm) {

	if (domain_mng_) {
		domain_mng_->setPluggedToName("");
	}
	if (dm) {
		domain_mng_ = dm;
        	domain_mng_->setPluggedToName(getName());
	} else {
		domain_mng_.reset();
	}
}

void SSLProtocol::statistics(std::basic_ostream<char> &out, int level) {

	if (level > 0) {
                int64_t alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";
		const char *dynamic_memory = (isDynamicAllocatedMemory() ? "yes":"no");

                unitConverter(alloc_memory, unit);

                out << getName() << "(" << this <<") statistics" << std::dec << "\n";

                if (ban_domain_mng_) out << "\t" << "Plugged banned domains from:" << ban_domain_mng_->getName() << "\n";
                if (domain_mng_) out << "\t" << "Plugged domains from:" << domain_mng_->getName() << "\n";

		out << "\t" << "Dynamic memory alloc:   " << std::setw(10) << dynamic_memory << "\n";
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << "\n";
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << "\n";
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ << std::endl;
		if (level > 1) { 
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << std::endl;
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << std::endl;
			if (level > 3) {
				out << "\t" << "Total allow hosts:      " << std::setw(10) << total_allow_hosts_ << "\n";
				out << "\t" << "Total banned hosts:     " << std::setw(10) << total_ban_hosts_ << "\n";
				out << "\t" << "Total handshakes:       " << std::setw(10) << total_handshakes_ << "\n";
				out << "\t" << "Total alerts:           " << std::setw(10) << total_alerts_ << "\n";
				out << "\t" << "Total change cipher specs:" << std::setw(8) << total_change_cipher_specs_ << "\n";
				out << "\t" << "Total data:             " << std::setw(10) << total_data_ << "\n";
		
				out << "\t" << "Total client hellos:    " << std::setw(10) << total_client_hellos_ << "\n";
				out << "\t" << "Total server hellos:    " << std::setw(10) << total_server_hellos_ << "\n";
				out << "\t" << "Total certificates:     " << std::setw(10) << total_certificates_ << "\n";
				out << "\t" << "Total server key exs:   " << std::setw(10) << total_server_key_exchanges_ << "\n";
				out << "\t" << "Total certificate reqs: " << std::setw(10) << total_certificate_requests_ << "\n";
				out << "\t" << "Total server dones:     " << std::setw(10) << total_server_dones_ << "\n";
				out << "\t" << "Total certificates vers:" << std::setw(10) << total_certificate_verifies_ << "\n";
				out << "\t" << "Total client key exs:   " << std::setw(10) << total_client_key_exchanges_ << "\n";
				out << "\t" << "Total handshakes finish:" << std::setw(10) << total_handshake_finishes_ << "\n";
				out << "\t" << "Total records:          " << std::setw(10) << total_records_ << std::endl;
			}
			if (level > 2) {
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
			}
			if (level > 3) {
				info_cache_->statistics(out);
				host_cache_->statistics(out);
				issuer_cache_->statistics(out);
				if (level > 4) {
					showCacheMap(out, "\t", host_map_, "SSL Hosts", "Host");
					showCacheMap(out, "\t", issuer_map_, "SSL Issuers", "Issuer");
				}
			}
		}
	}
}


void SSLProtocol::increaseAllocatedMemory(int value) { 

	info_cache_->create(value);
	host_cache_->create(value);
	issuer_cache_->create(value);
}

void SSLProtocol::decreaseAllocatedMemory(int value) { 

	info_cache_->destroy(value);
	host_cache_->destroy(value);
	issuer_cache_->destroy(value);
}

CounterMap SSLProtocol::getCounters() const { 
	CounterMap cm;

	cm.addKeyValue("packets", total_packets_);
	cm.addKeyValue("bytes", total_bytes_);
	cm.addKeyValue("allow hosts", total_allow_hosts_);
	cm.addKeyValue("banned hosts", total_ban_hosts_);

	cm.addKeyValue("handshakes", total_handshakes_);
	cm.addKeyValue("alerts", total_alerts_);
	cm.addKeyValue("change cipher specs", total_change_cipher_specs_);
	cm.addKeyValue("datas", total_data_);

	cm.addKeyValue("client hellos", total_client_hellos_);
	cm.addKeyValue("server hellos", total_server_hellos_);
	cm.addKeyValue("certificates", total_certificates_);
	cm.addKeyValue("server key exchanges", total_server_key_exchanges_);
	cm.addKeyValue("certificate requests", total_certificate_requests_);
	cm.addKeyValue("server dones", total_server_dones_);
	cm.addKeyValue("certificate verifies", total_certificate_verifies_);
	cm.addKeyValue("client key exchanges", total_client_key_exchanges_);
	cm.addKeyValue("handshake dones", total_handshake_finishes_);
	cm.addKeyValue("records", total_records_);

        return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
#if defined(PYTHON_BINDING)
boost::python::dict SSLProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE SSLProtocol::getCache() const {
#endif
        return addMapToHash(host_map_);
}

#if defined(PYTHON_BINDING)
void SSLProtocol::showCache(std::basic_ostream<char> &out) const {

	showCacheMap(out, "", host_map_, "SSL Hosts", "Host");
}
#endif

#endif

} // namespace aiengine
