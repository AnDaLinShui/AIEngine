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
#ifndef SRC_STACKTEST_H_
#define SRC_STACKTEST_H_

#include <string>
#include "Multiplexer.h"
#include "FlowForwarder.h"
#include "protocols/ethernet/EthernetProtocol.h"
#include "AnomalyManager.h"

using namespace aiengine;

struct RedirectOutput {
        std::streambuf *old_cout;
        std::ostringstream cout;

        RedirectOutput():
                old_cout(std::cout.rdbuf()),
                cout() {

                std::cout.rdbuf(cout.rdbuf());
        }

        ~RedirectOutput() { std::cout.rdbuf(old_cout); }
};

struct StackTest {
        EthernetProtocolPtr eth;
        MultiplexerPtr mux_eth;
	SharedPointer<AnomalyManager> anomaly;

        StackTest() {
                eth = EthernetProtocolPtr(new EthernetProtocol());
                mux_eth = MultiplexerPtr(new Multiplexer());

                // Configure the eth
                eth->setMultiplexer(mux_eth);
                mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
		mux_eth->setProtocolIdentifier(0);
                mux_eth->setHeaderSize(eth->getHeaderSize());
                mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker, eth, std::placeholders::_1));

		anomaly = SharedPointer<AnomalyManager>(new AnomalyManager());
        }

        void inject(Packet &pkt) {
                mux_eth->setPacket(&pkt);
                eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
                mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
                mux_eth->forwardPacket(pkt);
        }

        ~StackTest() {}
};

#endif  // SRC_STACKTEST_H_
