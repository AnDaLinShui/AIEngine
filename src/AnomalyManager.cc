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
#include "AnomalyManager.h"

namespace aiengine {

AnomalyManager::AnomalyManager(): anomalies_{{
	{ static_cast<std::int8_t>(PacketAnomalyType::NONE),                            0,      "" },
	{ static_cast<std::int8_t>(PacketAnomalyType::IPV4_FRAGMENTATION),              0,      "" },
	{ static_cast<std::int8_t>(PacketAnomalyType::IPV6_FRAGMENTATION),              0,      "" },
	{ static_cast<std::int8_t>(PacketAnomalyType::IPV6_LOOP_EXTENSION_HEADERS),     0,      "" }, 
	{ static_cast<std::int8_t>(PacketAnomalyType::TCP_BAD_FLAGS),                   0,      "tcp" },
	{ static_cast<std::int8_t>(PacketAnomalyType::TCP_BOGUS_HEADER),                0,      "tcp" },
	{ static_cast<std::int8_t>(PacketAnomalyType::UDP_BOGUS_HEADER),                0,      "udp" },
	{ static_cast<std::int8_t>(PacketAnomalyType::DNS_BOGUS_HEADER),                0,      "dns" },
	{ static_cast<std::int8_t>(PacketAnomalyType::DNS_LONG_NAME),                   0,      "dns" },
	{ static_cast<std::int8_t>(PacketAnomalyType::SMTP_BOGUS_HEADER),               0,      "smtp" },
	{ static_cast<std::int8_t>(PacketAnomalyType::SMTP_LONG_EMAIL),                 0,      "smtp" },
	{ static_cast<std::int8_t>(PacketAnomalyType::IMAP_BOGUS_HEADER),               0,      "imap" },
	{ static_cast<std::int8_t>(PacketAnomalyType::POP_BOGUS_HEADER),                0,      "pop" },
	{ static_cast<std::int8_t>(PacketAnomalyType::SNMP_BOGUS_HEADER),               0,      "" }, 
	{ static_cast<std::int8_t>(PacketAnomalyType::SSL_BOGUS_HEADER),                0,      "ssl" },
	{ static_cast<std::int8_t>(PacketAnomalyType::HTTP_BOGUS_URI_HEADER),           0,      "http" },
	{ static_cast<std::int8_t>(PacketAnomalyType::HTTP_BOGUS_NO_HEADERS),           0,      "http" },
	{ static_cast<std::int8_t>(PacketAnomalyType::COAP_BOGUS_HEADER),               0,      "" },
	{ static_cast<std::int8_t>(PacketAnomalyType::RTP_BOGUS_HEADER),                0,      "" },
	{ static_cast<std::int8_t>(PacketAnomalyType::MQTT_BOGUS_HEADER),               0,      "" },
	{ static_cast<std::int8_t>(PacketAnomalyType::NETBIOS_BOGUS_HEADER),            0,      "" },
	{ static_cast<std::int8_t>(PacketAnomalyType::DHCP_BOGUS_HEADER),               0,      "" },
	{ static_cast<std::int8_t>(PacketAnomalyType::SMB_BOGUS_HEADER),                0,      "" }
	}}
	{}

void AnomalyManager::statistics(std::basic_ostream<char>& out) {

	out << "Packet Anomalies " << std::endl;
	for (int i = 1; i < static_cast<std::int8_t>(PacketAnomalyType::MAX_PACKET_ANOMALIES) ; ++i ) { 
		AnomalyInfo &ai = anomalies_[static_cast<std::int8_t>(i)];
		const char *name = PacketAnomalyTypeString[i].name;
                int32_t hits = anomalies_[i].hits;

                out << "\t" << "Total " << name << ":" << std::right << std::setfill(' ') << std::setw(27 - strlen(name)) ;
		out << hits; 
#if defined(BINDING)
		if (ai.call.haveCallback()) {
			out << " Callback:" << ai.call.getCallbackName();
		}
#endif
		out << "\n";
        }
	out.flush();
}

void AnomalyManager::incAnomaly(Flow *flow, PacketAnomalyType t) { 

	AnomalyInfo &ai = anomalies_[static_cast<std::int8_t>(t)];
	ai.hits += 1; 
#if defined(BINDING)
	if (ai.call.haveCallback()) {
		ai.call.executeCallback(flow);
	}
#endif
}

void AnomalyManager::incAnomaly(PacketAnomalyType t) { 

	anomalies_[static_cast<std::int8_t>(t)].hits += 1; 
}

const char *AnomalyManager::getName(PacketAnomalyType t) {

	return PacketAnomalyTypeString[static_cast<std::int8_t>(t)].name;
}

#if defined(BINDING)
#if defined(PYTHON_BINDING)
void AnomalyManager::setCallback(PyObject *callback,const std::string &protocol_name) {
#elif defined(RUBY_BINDING)
void AnomalyManager::setCallback(VALUE callback,const std::string &protocol_name) {
#elif defined(JAVA_BINDING)
void AnomalyManager::setCallback(JaiCallback *callback,const std::string &protocol_name) {
#elif defined(LUA_BINDING)
void AnomalyManager::setCallback(lua_State *L, const std::string& callback,const std::string &protocol_name) {
#elif defined(GO_BINDING)
void AnomalyManager::setCallback(GoaiCallback *callback,const std::string &protocol_name) {
#endif
	std::for_each(anomalies_.begin(), anomalies_.end(), [&] (AnomalyInfo &ai) {
		// protocol_name could be "HTTP", "http" or "HTTPProtocol"
		int len = strlen(ai.protocol_name);
		if (len > 0) { // The protocol accept callback
			if (protocol_name.length() >= len) {
				std::string proto(protocol_name, 0, len);

				if (boost::iequals(proto, ai.protocol_name)) {
#if defined(LUA_BINDING)
					ai.call.setCallback(L, callback.c_str());
#else
					ai.call.setCallback(callback);	
#endif
				}
			}
		}			 
	});

}
#endif // BINDING

} // namespace aiengine 

