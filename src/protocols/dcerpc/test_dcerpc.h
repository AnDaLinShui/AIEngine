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
#ifndef _TEST_DCERPC_H_
#define _TEST_DCERPC_H_

#include <string>
#include <cstring>
#include "Protocol.h"
#include "StackTest.h"
#include "../ip/IPProtocol.h"
#include "../ip6/IPv6Protocol.h"
#include "../tcp/TCPProtocol.h"
#include "DCERPCProtocol.h"

using namespace aiengine;

struct StackDCERPCtest : public StackTest
{
        //Protocols
        IPProtocolPtr ip;
        TCPProtocolPtr tcp;
        DCERPCProtocolPtr dcerpc;

        // Multiplexers
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_tcp;

        // FlowManager and FlowCache
        FlowManagerPtr flow_mng;
        FlowCachePtr flow_cache;

        // FlowForwarders
        SharedPointer<FlowForwarder> ff_tcp, ff_dcerpc;

        StackDCERPCtest()
        {
                // Allocate all the Protocol objects
                tcp = TCPProtocolPtr(new TCPProtocol());
                ip = IPProtocolPtr(new IPProtocol());
                dcerpc = DCERPCProtocolPtr(new DCERPCProtocol());

                // Allocate the Multiplexers
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_tcp = MultiplexerPtr(new Multiplexer());

                // Allocate the flow caches and tables
                flow_mng = FlowManagerPtr(new FlowManager());
                flow_cache = FlowCachePtr(new FlowCache());

                ff_tcp = SharedPointer<FlowForwarder>(new FlowForwarder());
                ff_dcerpc = SharedPointer<FlowForwarder>(new FlowForwarder());

                // configure the ip
                ip->setMultiplexer(mux_ip);
                mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
                mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
                mux_ip->setHeaderSize(ip->getHeaderSize());
                mux_ip->addChecker(std::bind(&IPProtocol::ipChecker, ip, std::placeholders::_1));
                mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket, ip, std::placeholders::_1));

                //configure the tcp 
                tcp->setMultiplexer(mux_tcp);
                mux_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
                ff_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
                mux_tcp->setProtocolIdentifier(IPPROTO_TCP);
                mux_tcp->setHeaderSize(tcp->getHeaderSize());
                mux_tcp->addChecker(std::bind(&TCPProtocol::tcpChecker, tcp, std::placeholders::_1));
                mux_tcp->addPacketFunction(std::bind(&TCPProtocol::processPacket, tcp, std::placeholders::_1));

                // configure the dcerpc 
                dcerpc->setFlowForwarder(ff_dcerpc);
                ff_dcerpc->setProtocol(static_cast<ProtocolPtr>(dcerpc));
                ff_dcerpc->addChecker(std::bind(&DCERPCProtocol::dcerpcChecker, dcerpc, std::placeholders::_1));
                ff_dcerpc->addFlowFunction(std::bind(&DCERPCProtocol::processFlow, dcerpc,
			std::placeholders::_1));

                // configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip, ETHERTYPE_IP);
                mux_ip->addDownMultiplexer(mux_eth);
                mux_ip->addUpMultiplexer(mux_tcp, IPPROTO_TCP);
                mux_tcp->addDownMultiplexer(mux_ip);

                // Connect the FlowManager and FlowCache
                flow_cache->createFlows(1);

                tcp->setFlowCache(flow_cache);
                tcp->setFlowManager(flow_mng);
                dcerpc->setFlowManager(flow_mng);

		dcerpc->increaseAllocatedMemory(1);
		tcp->createTCPInfos(2);
                // Configure the FlowForwarders
                tcp->setFlowForwarder(ff_tcp);
		ff_tcp->addUpFlowForwarder(ff_dcerpc);
        }

	void show() {

		tcp->statistics(std::cout, 5);
		dcerpc->statistics(std::cout, 5);
	}

	void showFlows() {

		flow_mng->showFlows();
	}

        ~StackDCERPCtest() {}
};

struct StackIPv6DCERPCtest : public StackTest
{
        //Protocols
        IPv6ProtocolPtr ip6;
        TCPProtocolPtr tcp;
        DCERPCProtocolPtr dcerpc;

        // Multiplexers
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_tcp;

        // FlowManager and FlowCache
        FlowManagerPtr flow_mng;
        FlowCachePtr flow_cache;

        // FlowForwarders
        SharedPointer<FlowForwarder> ff_tcp, ff_dcerpc;

        StackIPv6DCERPCtest()
        {
                // Allocate all the Protocol objects
                tcp = TCPProtocolPtr(new TCPProtocol());
                ip6 = IPv6ProtocolPtr(new IPv6Protocol());
                dcerpc = DCERPCProtocolPtr(new DCERPCProtocol());

                // Allocate the Multiplexers
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_tcp = MultiplexerPtr(new Multiplexer());

                // Allocate the flow caches and tables
                flow_mng = FlowManagerPtr(new FlowManager());
                flow_cache = FlowCachePtr(new FlowCache());

                ff_tcp = SharedPointer<FlowForwarder>(new FlowForwarder());
                ff_dcerpc = SharedPointer<FlowForwarder>(new FlowForwarder());

                // configure the ip
                ip6->setMultiplexer(mux_ip);
                mux_ip->setProtocol(static_cast<ProtocolPtr>(ip6));
                mux_ip->setProtocolIdentifier(ETHERTYPE_IPV6);
                mux_ip->setHeaderSize(ip6->getHeaderSize());
                mux_ip->addChecker(std::bind(&IPv6Protocol::ip6Checker, ip6, std::placeholders::_1));
                mux_ip->addPacketFunction(std::bind(&IPv6Protocol::processPacket, ip6, std::placeholders::_1));

                //configure the tcp
                tcp->setMultiplexer(mux_tcp);
                mux_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
                ff_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
                mux_tcp->setProtocolIdentifier(IPPROTO_TCP);
                mux_tcp->setHeaderSize(tcp->getHeaderSize());
                mux_tcp->addChecker(std::bind(&TCPProtocol::tcpChecker, tcp, std::placeholders::_1));
                mux_tcp->addPacketFunction(std::bind(&TCPProtocol::processPacket, tcp, std::placeholders::_1));

                // configure the dcerpc
                dcerpc->setFlowForwarder(ff_dcerpc);
                ff_dcerpc->setProtocol(static_cast<ProtocolPtr>(dcerpc));
                ff_dcerpc->addChecker(std::bind(&DCERPCProtocol::dcerpcChecker, dcerpc, std::placeholders::_1));
                ff_dcerpc->addFlowFunction(std::bind(&DCERPCProtocol::processFlow, dcerpc,
			std::placeholders::_1));

                // configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip, ETHERTYPE_IPV6);
                mux_ip->addDownMultiplexer(mux_eth);
                mux_ip->addUpMultiplexer(mux_tcp, IPPROTO_TCP);
                mux_tcp->addDownMultiplexer(mux_ip);

                // Connect the FlowManager and FlowCache
                flow_cache->createFlows(1);

                tcp->setFlowCache(flow_cache);
                tcp->setFlowManager(flow_mng);

                // Configure the FlowForwarders
                tcp->setFlowForwarder(ff_tcp);
		ff_tcp->addUpFlowForwarder(ff_dcerpc);
        }

	void show() {

		ip6->statistics(std::cout, 5);
		tcp->statistics(std::cout, 5);
		dcerpc->statistics(std::cout, 5);
	}

	void showFlows() {

		flow_mng->showFlows();
	}

        ~StackIPv6DCERPCtest() {}
};

#endif
