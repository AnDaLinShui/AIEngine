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
#ifndef _TEST_VLAN_H_
#define _TEST_VLAN_H_

#include <string>
#include <cstring>
#include "Protocol.h"
#include "StackTest.h"
#include "VLanProtocol.h"

using namespace aiengine;

struct StackTestVlan : public StackTest
{
        VLanProtocolPtr vlan;
        MultiplexerPtr mux_vlan;

        StackTestVlan()
        {
        	vlan = VLanProtocolPtr(new VLanProtocol());
        	mux_vlan = MultiplexerPtr(new Multiplexer());

        	// configure the vlan handler
        	vlan->setMultiplexer(mux_vlan);
		mux_vlan->setProtocol(static_cast<ProtocolPtr>(vlan));
		mux_vlan->setProtocolIdentifier(ETHERTYPE_VLAN);
        	mux_vlan->setHeaderSize(vlan->getHeaderSize());
        	mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker, vlan, std::placeholders::_1));
		mux_vlan->addPacketFunction(std::bind(&VLanProtocol::processPacket, vlan, std::placeholders::_1));

		// configure the multiplexers
		mux_eth->addUpMultiplexer(mux_vlan, ETHERTYPE_VLAN);
		mux_vlan->addDownMultiplexer(mux_eth);

	}

        ~StackTestVlan() {}
};

#endif
