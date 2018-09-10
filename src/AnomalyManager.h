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
#ifndef SRC_ANOMALYMANAGER_H_
#define SRC_ANOMALYMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Callback.h"
#include <iostream>
#include <iomanip> // setw
#include <array>
#include <vector>
#include <cstring>
#include <algorithm>
#include <boost/algorithm/string.hpp>

namespace aiengine {

class Flow;

enum class PacketAnomalyType : std::int8_t {
	NONE = 0,
	IPV4_FRAGMENTATION = 1,
	IPV6_FRAGMENTATION = 2,
	IPV6_LOOP_EXTENSION_HEADERS = 3,
	TCP_BAD_FLAGS = 4,
	TCP_BOGUS_HEADER = 5,
	UDP_BOGUS_HEADER = 6,
	DNS_BOGUS_HEADER = 7,
	DNS_LONG_NAME = 8,
	SMTP_BOGUS_HEADER = 9,
	SMTP_LONG_EMAIL = 10,
	IMAP_BOGUS_HEADER = 11,
	POP_BOGUS_HEADER = 12,
	SNMP_BOGUS_HEADER = 13,
	SSL_BOGUS_HEADER = 14,
	HTTP_BOGUS_URI_HEADER = 15,
	HTTP_BOGUS_NO_HEADERS = 16,
	COAP_BOGUS_HEADER = 17,
	RTP_BOGUS_HEADER = 18,
	MQTT_BOGUS_HEADER = 19,
	NETBIOS_BOGUS_HEADER = 20,
	DHCP_BOGUS_HEADER = 21,
	SMB_BOGUS_HEADER = 22,
	MAX_PACKET_ANOMALIES = 23
};

typedef struct {
	std::int8_t index;
	const char* name;
} AnomalyDescription;

static std::array <AnomalyDescription, static_cast<std::int8_t>(PacketAnomalyType::MAX_PACKET_ANOMALIES)> PacketAnomalyTypeString __attribute__((unused)) {{
        { static_cast<std::int8_t>(PacketAnomalyType::NONE),				"None"                          },
        { static_cast<std::int8_t>(PacketAnomalyType::IPV4_FRAGMENTATION),              "IPv4 Fragmentation"            },
        { static_cast<std::int8_t>(PacketAnomalyType::IPV6_FRAGMENTATION),              "IPv6 Fragmentation"            },
        { static_cast<std::int8_t>(PacketAnomalyType::IPV6_LOOP_EXTENSION_HEADERS),     "IPv6 Loop ext headers"         },
        { static_cast<std::int8_t>(PacketAnomalyType::TCP_BAD_FLAGS),                   "TCP bad flags"                 },
        { static_cast<std::int8_t>(PacketAnomalyType::TCP_BOGUS_HEADER),                "TCP bogus header"              },
        { static_cast<std::int8_t>(PacketAnomalyType::UDP_BOGUS_HEADER),                "UDP bogus header"              },
        { static_cast<std::int8_t>(PacketAnomalyType::DNS_BOGUS_HEADER),                "DNS bogus header"              },
        { static_cast<std::int8_t>(PacketAnomalyType::DNS_LONG_NAME),                   "DNS long domain name"          },
        { static_cast<std::int8_t>(PacketAnomalyType::SMTP_BOGUS_HEADER),               "SMTP bogus header"             },
        { static_cast<std::int8_t>(PacketAnomalyType::SMTP_LONG_EMAIL),                 "SMTP long email"               },
        { static_cast<std::int8_t>(PacketAnomalyType::IMAP_BOGUS_HEADER),               "IMAP bogus header"             },
        { static_cast<std::int8_t>(PacketAnomalyType::POP_BOGUS_HEADER),                "POP bogus header"              },
        { static_cast<std::int8_t>(PacketAnomalyType::SNMP_BOGUS_HEADER),               "SNMP bogus header"             },
        { static_cast<std::int8_t>(PacketAnomalyType::SSL_BOGUS_HEADER),                "SSL bogus header"              },
        { static_cast<std::int8_t>(PacketAnomalyType::HTTP_BOGUS_URI_HEADER),           "HTTP malformed URI"            },
        { static_cast<std::int8_t>(PacketAnomalyType::HTTP_BOGUS_NO_HEADERS),           "HTTP no headers"		},
        { static_cast<std::int8_t>(PacketAnomalyType::COAP_BOGUS_HEADER),		"CoAP bogus headers"          	},
        { static_cast<std::int8_t>(PacketAnomalyType::RTP_BOGUS_HEADER),		"RTP bogus headers"          	},
        { static_cast<std::int8_t>(PacketAnomalyType::MQTT_BOGUS_HEADER),		"MQTT bogus headers"          	},
        { static_cast<std::int8_t>(PacketAnomalyType::NETBIOS_BOGUS_HEADER),		"Netbios bogus headers"        	},
        { static_cast<std::int8_t>(PacketAnomalyType::DHCP_BOGUS_HEADER),		"DHCP bogus headers"        	},
        { static_cast<std::int8_t>(PacketAnomalyType::SMB_BOGUS_HEADER),		"SMB bogus headers"        	}
}};

typedef struct {
	std::int8_t index;
	int32_t hits;
	const char* protocol_name;
#if defined(BINDING)
	Callback call;
#endif
} AnomalyInfo;

class AnomalyManager {
public:
        explicit AnomalyManager();

	void statistics(std::basic_ostream<char> &out);
        void statistics() { statistics(std::cout); }
	void incAnomaly(Flow *flow, PacketAnomalyType t);
	void incAnomaly(PacketAnomalyType t);
	const char *getName(PacketAnomalyType t);

#if defined(PYTHON_BINDING)
        void setCallback(PyObject *callback, const std::string &protocol_name);
#elif defined(RUBY_BINDING)
        void setCallback(VALUE callback, const std::string &protocol_name);
#elif defined(JAVA_BINDING)
        void setCallback(JaiCallback *callback, const std::string &protocol_name);
#elif defined(LUA_BINDING)
        void setCallback(lua_State *L, const std::string &callback, const std::string &protocol_name);
#elif defined(GO_BINDING)
        void setCallback(GoaiCallback *callback, const std::string &protocol_name);
#endif

private:
	std::array <AnomalyInfo, static_cast<std::int8_t>(PacketAnomalyType::MAX_PACKET_ANOMALIES)> anomalies_;
};

} // namespace aiengine

#endif  // SRC_ANOMALYMANAGER_H_
