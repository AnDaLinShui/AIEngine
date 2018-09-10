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
#ifndef _TEST_SSH_H_
#define _TEST_SSH_H_

#include <string>
#include "Protocol.h"
#include "StackTest.h"
#include "../ip/IPProtocol.h"
#include "../ip6/IPv6Protocol.h"
#include "../tcp/TCPProtocol.h"
#include "SSHProtocol.h"
#include <cstring>

using namespace aiengine;

struct StackSSHtest : public StackTest
{
        //Protocols
        IPProtocolPtr ip;
        TCPProtocolPtr tcp;
        SSHProtocolPtr ssh;

        // Multiplexers
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_tcp;

        // FlowManager and FlowCache
        FlowManagerPtr flow_mng;
        FlowCachePtr flow_cache;

        // FlowForwarders
        SharedPointer<FlowForwarder> ff_tcp, ff_ssh;

        StackSSHtest()
        {
                // Allocate all the Protocol objects
                tcp = TCPProtocolPtr(new TCPProtocol());
                ip = IPProtocolPtr(new IPProtocol());
                ssh = SSHProtocolPtr(new SSHProtocol());

                // Allocate the Multiplexers
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_tcp = MultiplexerPtr(new Multiplexer());

                // Allocate the flow caches and tables
                flow_mng = FlowManagerPtr(new FlowManager());
                flow_cache = FlowCachePtr(new FlowCache());

                ff_tcp = SharedPointer<FlowForwarder>(new FlowForwarder());
                ff_ssh = SharedPointer<FlowForwarder>(new FlowForwarder());

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

                // configure the ssh
                ssh->setFlowForwarder(ff_ssh);
                ff_ssh->setProtocol(static_cast<ProtocolPtr>(ssh));
                ff_ssh->addChecker(std::bind(&SSHProtocol::sshChecker, ssh,std::placeholders::_1));
                ff_ssh->addFlowFunction(std::bind(&SSHProtocol::processFlow, ssh,
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
                ssh->setFlowManager(flow_mng);

                // Configure the FlowForwarders
                tcp->setFlowForwarder(ff_tcp);
		ff_tcp->addUpFlowForwarder(ff_ssh);

		tcp->createTCPInfos(2);
		ssh->setAnomalyManager(anomaly);

		ssh->increaseAllocatedMemory(2);
        }

	void show() {

		tcp->statistics(std::cout, 5);
		ssh->statistics(std::cout, 5);
	}

	void showFlows() {

		flow_mng->showFlows();
	}

        ~StackSSHtest() {}
};

struct StackIPv6SSHtest : public StackTest
{
        //Protocols
        IPv6ProtocolPtr ip6;
        TCPProtocolPtr tcp;
        SSHProtocolPtr ssh;

        // Multiplexers
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_tcp;

        // FlowManager and FlowCache
        FlowManagerPtr flow_mng;
        FlowCachePtr flow_cache;

        // FlowForwarders
        SharedPointer<FlowForwarder> ff_tcp, ff_ssh;

        StackIPv6SSHtest()
        {
                // Allocate all the Protocol objects
                tcp = TCPProtocolPtr(new TCPProtocol());
                ip6 = IPv6ProtocolPtr(new IPv6Protocol());
                ssh = SSHProtocolPtr(new SSHProtocol());


                // Allocate the Multiplexers
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_tcp = MultiplexerPtr(new Multiplexer());

                // Allocate the flow caches and tables
                flow_mng = FlowManagerPtr(new FlowManager());
                flow_cache = FlowCachePtr(new FlowCache());

                ff_tcp = SharedPointer<FlowForwarder>(new FlowForwarder());
                ff_ssh = SharedPointer<FlowForwarder>(new FlowForwarder());

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

                // configure the ssh
                ssh->setFlowForwarder(ff_ssh);
                ff_ssh->setProtocol(static_cast<ProtocolPtr>(ssh));
                ff_ssh->addChecker(std::bind(&SSHProtocol::sshChecker, ssh, std::placeholders::_1));
                ff_ssh->addFlowFunction(std::bind(&SSHProtocol::processFlow, ssh,
			std::placeholders::_1));

                // configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip, ETHERTYPE_IPV6);
                mux_ip->addDownMultiplexer(mux_eth);
                mux_ip->addUpMultiplexer(mux_tcp, IPPROTO_TCP);
                mux_tcp->addDownMultiplexer(mux_ip);

                // Connect the FlowManager and FlowCache
                flow_cache->createFlows(1);

		tcp->createTCPInfos(2);
                tcp->setFlowCache(flow_cache);
                tcp->setFlowManager(flow_mng);
                ssh->setFlowManager(flow_mng);

                // Configure the FlowForwarders
                tcp->setFlowForwarder(ff_tcp);
		ff_tcp->addUpFlowForwarder(ff_ssh);
		
		ssh->increaseAllocatedMemory(2);
        }

	void show() {
		ip6->statistics(std::cout, 5);
		tcp->statistics(std::cout, 5);
		ssh->statistics(std::cout, 5);
	}

	void showFlows() {

		flow_mng->showFlows();
	}

        ~StackIPv6SSHtest() {}
};

#endif
