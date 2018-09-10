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
#ifndef _TEST_UDP_H_
#define _TEST_UDP_H_

#include <string>
#include "Protocol.h"
#include "StackTest.h"
#include "../vlan/VLanProtocol.h"
#include "../ip/IPProtocol.h"
#include "../ip6/IPv6Protocol.h"
#include "UDPProtocol.h"

using namespace aiengine;

struct StackUDPTest : public StackTest 
{
	IPProtocolPtr ip;	
	UDPProtocolPtr udp;
	MultiplexerPtr mux_ip;
	MultiplexerPtr mux_udp;
	
	StackUDPTest()
	{
        	udp = UDPProtocolPtr(new UDPProtocol());
        	ip = IPProtocolPtr(new IPProtocol());
        	mux_ip = MultiplexerPtr(new Multiplexer());
        	mux_udp = MultiplexerPtr(new Multiplexer());	

        	// configure the ip
        	ip->setMultiplexer(mux_ip);
		mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
		mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
        	mux_ip->setHeaderSize(ip->getHeaderSize());
        	mux_ip->addChecker(std::bind(&IPProtocol::ipChecker, ip, std::placeholders::_1));
        	mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket, ip, std::placeholders::_1));

		//configure the udp
		udp->setMultiplexer(mux_udp);
		mux_udp->setProtocol(static_cast<ProtocolPtr>(udp));
		mux_udp->setProtocolIdentifier(IPPROTO_UDP);
		mux_udp->setHeaderSize(udp->getHeaderSize());
		mux_udp->addChecker(std::bind(&UDPProtocol::udpChecker, udp, std::placeholders::_1));
        	mux_udp->addPacketFunction(std::bind(&UDPProtocol::processPacket, udp, std::placeholders::_1));

		// configure the multiplexers
		mux_eth->addUpMultiplexer(mux_ip, ETHERTYPE_IP);
		mux_ip->addDownMultiplexer(mux_eth);
		mux_ip->addUpMultiplexer(mux_udp, IPPROTO_UDP);
		mux_udp->addDownMultiplexer(mux_ip);

		udp->setAnomalyManager(anomaly);
	}

	~StackUDPTest() {}
};

struct StackIPv6UDPTest : public StackTest
{
        IPv6ProtocolPtr ip6;
        UDPProtocolPtr udp;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_udp;

        StackIPv6UDPTest()
        {
                udp = UDPProtocolPtr(new UDPProtocol());
                ip6 = IPv6ProtocolPtr(new IPv6Protocol());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_udp = MultiplexerPtr(new Multiplexer());

                // configure the ip6
                ip6->setMultiplexer(mux_ip);
                mux_ip->setProtocol(static_cast<ProtocolPtr>(ip6));
                mux_ip->setProtocolIdentifier(ETHERTYPE_IPV6);
                mux_ip->setHeaderSize(ip6->getHeaderSize());
                mux_ip->addChecker(std::bind(&IPv6Protocol::ip6Checker, ip6, std::placeholders::_1));
                mux_ip->addPacketFunction(std::bind(&IPv6Protocol::processPacket, ip6, std::placeholders::_1));

                //configure the udp
                udp->setMultiplexer(mux_udp);
                mux_udp->setProtocol(static_cast<ProtocolPtr>(udp));
                mux_udp->setProtocolIdentifier(IPPROTO_UDP);
                mux_udp->setHeaderSize(udp->getHeaderSize());
                mux_udp->addChecker(std::bind(&UDPProtocol::udpChecker, udp, std::placeholders::_1));
                mux_udp->addPacketFunction(std::bind(&UDPProtocol::processPacket, udp, std::placeholders::_1));

                // configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip, ETHERTYPE_IPV6);
                mux_ip->addDownMultiplexer(mux_eth);
                mux_ip->addUpMultiplexer(mux_udp, IPPROTO_UDP);
                mux_udp->addDownMultiplexer(mux_ip);
		
		udp->setAnomalyManager(anomaly);
        }

        ~StackIPv6UDPTest() {}
};

#endif
