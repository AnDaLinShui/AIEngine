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
#ifndef _TEST_IP_H_
#define _TEST_IP_H_

#include <string>
#include "Protocol.h"
#include "StackTest.h"
#include "../vlan/VLanProtocol.h"
#include "IPProtocol.h"

using namespace aiengine;

struct StackEthernetIP : public StackTest
{
        IPProtocolPtr ip;
        MultiplexerPtr mux_ip;

        StackEthernetIP()
        {
                ip = IPProtocolPtr(new IPProtocol());
                mux_ip = MultiplexerPtr(new Multiplexer());

                // configure the ip handler
                ip->setMultiplexer(mux_ip);
                mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
		mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
                mux_ip->setHeaderSize(ip->getHeaderSize());
                mux_ip->addChecker(std::bind(&IPProtocol::ipChecker, ip, std::placeholders::_1));
		mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket, ip, std::placeholders::_1));

                // configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip, ETHERTYPE_IP);
                mux_ip->addDownMultiplexer(mux_eth);

		ip->setAnomalyManager(anomaly);
	}

	~StackEthernetIP() {}
};

struct StackEthernetVLanIP : public StackTest
{
        VLanProtocolPtr vlan;
        IPProtocolPtr ip;
        MultiplexerPtr mux_vlan;
        MultiplexerPtr mux_ip;

        StackEthernetVLanIP()
        {
                vlan = VLanProtocolPtr(new VLanProtocol());
                ip = IPProtocolPtr(new IPProtocol());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_vlan = MultiplexerPtr(new Multiplexer());

                // configure the vlan handler
                vlan->setMultiplexer(mux_vlan);
                mux_vlan->setProtocol(static_cast<ProtocolPtr>(vlan));
		mux_vlan->setProtocolIdentifier(ETHERTYPE_VLAN);
                mux_vlan->setHeaderSize(vlan->getHeaderSize());
                mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker, vlan, std::placeholders::_1));
                mux_vlan->addPacketFunction(std::bind(&VLanProtocol::processPacket, vlan, std::placeholders::_1));

                // configure the ip handler
                ip->setMultiplexer(mux_ip);
		mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
                mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
                mux_ip->setHeaderSize(ip->getHeaderSize());
                mux_ip->addChecker(std::bind(&IPProtocol::ipChecker, ip, std::placeholders::_1));
		mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket, ip, std::placeholders::_1));

        	// configure the multiplexers
        	mux_eth->addUpMultiplexer(mux_vlan, ETHERTYPE_VLAN);
		mux_vlan->addDownMultiplexer(mux_eth);
		mux_vlan->addUpMultiplexer(mux_ip, ETHERTYPE_IP);
		mux_ip->addDownMultiplexer(mux_vlan);
        }

        ~StackEthernetVLanIP() {}
};

#endif
