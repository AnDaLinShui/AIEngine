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
#ifndef _TEST_PPPOE_H_
#define _TEST_PPPOE_H_

#include <string>
#include <cstring>
#include "Protocol.h"
#include "StackTest.h"
#include "protocols/ip/IPProtocol.h"
#include "protocols/ip6/IPv6Protocol.h"
#include "PPPoEProtocol.h"

using namespace aiengine;

struct StackTestPPPoE : public StackTest
{
        PPPoEProtocolPtr pppoe;
        MultiplexerPtr mux_pppoe;
        IPProtocolPtr ip;
        IPv6ProtocolPtr ip6;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_ip6;

        StackTestPPPoE()
        {
        	pppoe = PPPoEProtocolPtr(new PPPoEProtocol());
        	mux_pppoe = MultiplexerPtr(new Multiplexer());
       	
		ip = IPProtocolPtr(new IPProtocol());
		ip6 = IPv6ProtocolPtr(new IPv6Protocol());

        	mux_ip = MultiplexerPtr(new Multiplexer());
        	mux_ip6 = MultiplexerPtr(new Multiplexer());

        	// configure the pppoe handler
        	pppoe->setMultiplexer(mux_pppoe);
		mux_pppoe->setProtocol(static_cast<ProtocolPtr>(pppoe));
		mux_pppoe->setProtocolIdentifier(ETHERTYPE_PPPOE);
        	mux_pppoe->setHeaderSize(pppoe->getHeaderSize());
        	mux_pppoe->addChecker(std::bind(&PPPoEProtocol::pppoeChecker, pppoe, std::placeholders::_1));
		mux_pppoe->addPacketFunction(std::bind(&PPPoEProtocol::processPacket, pppoe, std::placeholders::_1));

		// configure the ip handler
		ip->setMultiplexer(mux_ip);
		mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
		mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
		mux_ip->setHeaderSize(ip->getHeaderSize());
		mux_ip->addChecker(std::bind(&IPProtocol::ipChecker, ip, std::placeholders::_1));
		mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket, ip, std::placeholders::_1));

		// configure the ipv6 handler
		ip6->setMultiplexer(mux_ip6);
		mux_ip6->setProtocol(static_cast<ProtocolPtr>(ip6));
		mux_ip6->setProtocolIdentifier(ETHERTYPE_IPV6);
		mux_ip6->setHeaderSize(ip6->getHeaderSize());
		mux_ip6->addChecker(std::bind(&IPv6Protocol::ip6Checker, ip6, std::placeholders::_1));
		mux_ip6->addPacketFunction(std::bind(&IPv6Protocol::processPacket, ip6, std::placeholders::_1));

		// configure the multiplexers
		mux_eth->addUpMultiplexer(mux_pppoe, ETHERTYPE_PPPOE);
		mux_pppoe->addDownMultiplexer(mux_eth);

                // configure the multiplexers of the first part
                mux_pppoe->addUpMultiplexer(mux_ip, ETHERTYPE_IP);
                mux_ip->addDownMultiplexer(mux_pppoe);

                mux_pppoe->addUpMultiplexer(mux_ip6, ETHERTYPE_IPV6);
                mux_ip6->addDownMultiplexer(mux_pppoe);
	}

        ~StackTestPPPoE() {}
};

#endif
