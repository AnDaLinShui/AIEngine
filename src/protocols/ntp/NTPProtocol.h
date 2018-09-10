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
#ifndef SRC_PROTOCOLS_NTP_NTPPROTOCOL_H_
#define SRC_PROTOCOLS_NTP_NTPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

#define	NTP_VERSIONMASK	0x38
#define	NTP_MODEMASK	0x07

struct l_fixedpt {
	uint32_t 	int_part;
	uint32_t 	fraction;
};

struct s_fixedpt {
	uint16_t 	int_part;
	uint16_t 	fraction;
};

struct ntp_header {
	uint8_t 	flags;		/* version, mode, status of local clock and leap info */
	uint8_t 	stratum;	/* Stratum level */
	uint8_t 	ppoll;		/* poll value */
	int 		precision:8;
	struct s_fixedpt root_delay;
	struct s_fixedpt root_dispersion;
	uint32_t 	refid;
	struct l_fixedpt ref_timestamp;
	struct l_fixedpt org_timestamp;
	struct l_fixedpt rec_timestamp;
	struct l_fixedpt xmt_timestamp;
	uint8_t 	data[0]; // key id and message digest
} __attribute__((packed));

enum ntp_mode_types {
	NTP_MODE_UNSPEC = 0,
	NTP_MODE_SYM_ACT,
	NTP_MODE_SYM_PAS,
	NTP_MODE_CLIENT,
	NTP_MODE_SERVER,
	NTP_MODE_BROADCAST,
	NTP_MODE_RES1,
	NTP_MODE_RES2
};

class NTPProtocol: public Protocol {
public:
    	explicit NTPProtocol();
    	virtual ~NTPProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(struct ntp_header);

	int getHeaderSize() const { return header_size; }

        void processFlow(Flow *flow) override;
        bool processPacket(Packet &packet) override { return true; } 

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override {} // No need to free cache

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const ntp_header*> (raw_packet);
	}

	// Condition for say that a packet is ntp 
	bool ntpChecker(Packet &packet); 
	
	uint8_t getVersion() const { return ((header_->flags & NTP_VERSIONMASK) >> 3); }
	uint8_t getMode() const { return (header_->flags & NTP_MODEMASK); }

	int64_t getCurrentUseMemory() const override { return sizeof(NTPProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(NTPProtocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(NTPProtocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }

	CounterMap getCounters() const override; 

private:
	const ntp_header *header_;
        
	// Some statistics
	int32_t total_ntp_unspecified_;
        int32_t total_ntp_sym_active_;
        int32_t total_ntp_sym_passive_;
        int32_t total_ntp_client_;
        int32_t total_ntp_server_;
        int32_t total_ntp_broadcast_;
        int32_t total_ntp_reserved_; 
};

typedef std::shared_ptr<NTPProtocol> NTPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_NTP_NTPPROTOCOL_H_
