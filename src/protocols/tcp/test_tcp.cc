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
#include "test_tcp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE tcptest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(tcp_test_suite1, StackTCPTest)

BOOST_AUTO_TEST_CASE (test01)
{
	BOOST_CHECK(tcp->getTotalBytes() == 0);
	BOOST_CHECK(tcp->getTotalPackets() == 0);
	BOOST_CHECK(tcp->getTotalValidPackets() == 0);
	BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(tcp->getTotalEvents() == 0);

	tcp->processFlow(nullptr); // nothing to do
	CounterMap c = tcp->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../http/packets/packet01.pcap");

	inject(packet);	

        // Check the TCP integrity
        BOOST_CHECK(tcp->getSourcePort() == 53637);
        BOOST_CHECK(tcp->getDestinationPort() == 80);
	BOOST_CHECK(tcp->getTotalBytes() == 809);
	BOOST_CHECK(tcp->getTotalPackets() == 1);
	BOOST_CHECK(tcp->getTotalValidPackets() == 1);
	BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(tcp->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
        Packet packet("../ssl/packets/packet01.pcap");
                
	inject(packet);	
                
        // Check the TCP integrity
        BOOST_CHECK(tcp->getSourcePort() == 44265);
        BOOST_CHECK(tcp->getDestinationPort() == 443);
        BOOST_CHECK(tcp->getTotalBytes() == 225);
}

// Test case for verify tcp flags
BOOST_AUTO_TEST_CASE (test04)
{
        Packet packet("../ssl/packets/packet01.pcap");

	inject(packet);	

	Flow *flow = tcp->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
	SharedPointer<TCPInfo> info = flow->getTCPInfo();
        BOOST_CHECK(info != nullptr);
	BOOST_CHECK(flow->regex_mng == nullptr);
	
	// Process the packet but no syn or syn ack so the info have been released
	BOOST_CHECK(info->syn == 0);
	BOOST_CHECK(info->fin == 0);
	BOOST_CHECK(info->syn_ack == 0);
	BOOST_CHECK(info->ack == 1);
	BOOST_CHECK(info->push == 1);
	BOOST_CHECK(tcp->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_CASE (test05)
{
        Packet packet("../tcp/packets/packet01.pcap");

	inject(packet);	

	BOOST_CHECK(tcp->getTotalBytes() == 40);
	BOOST_CHECK(tcp->getTotalPackets() == 1);
	BOOST_CHECK(tcp->getTotalValidPackets() == 1);
	BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(tcp->getTotalEvents() == 0);

        Flow *flow = tcp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer4info != nullptr);
        SharedPointer<TCPInfo> info = flow->getTCPInfo();

        BOOST_CHECK(info->syn == 1);
        BOOST_CHECK(info->fin == 0);
        BOOST_CHECK(info->syn_ack == 0);
        BOOST_CHECK(info->ack == 0);
        BOOST_CHECK(info->push == 0);
}

BOOST_AUTO_TEST_CASE (test06)
{
        Packet packet("../tcp/packets/packet02.pcap");

	inject(packet);

        Flow *flow = tcp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<TCPInfo> info = flow->getTCPInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(info->syn == 0);
	BOOST_CHECK(info->syn_ack == 1);
	// no syn packet so nothing to process
	BOOST_CHECK(tcp->isSyn() == true);
	BOOST_CHECK(tcp->isFin() == false);
	BOOST_CHECK(tcp->isAck() == true);
	BOOST_CHECK(tcp->isRst() == false);
	BOOST_CHECK(tcp->isPushSet() == false);
}

BOOST_AUTO_TEST_CASE (test07)
{
        Packet packet1("../tcp/packets/packet01.pcap");
        Packet packet2("../tcp/packets/packet02.pcap");

	inject(packet1);
	
	BOOST_CHECK(tcp->getTotalBytes() == 40);
	BOOST_CHECK(tcp->getTotalPackets() == 1);
	BOOST_CHECK(tcp->getTotalValidPackets() == 1);
	BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(tcp->getTotalEvents() == 0);

	inject(packet2);

	BOOST_CHECK(tcp->getTotalBytes() == 80);
	BOOST_CHECK(tcp->getTotalPackets() == 2);
	BOOST_CHECK(tcp->getTotalValidPackets() == 2);
	BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(tcp->getTotalEvents() == 0);

        Flow *flow = tcp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer4info != nullptr);
        SharedPointer<TCPInfo> info = flow->getTCPInfo();

        BOOST_CHECK(info->syn == 1);
        BOOST_CHECK(info->fin == 0);
        BOOST_CHECK(info->syn_ack == 1);
        BOOST_CHECK(info->ack == 0);
        BOOST_CHECK(info->push == 0);
}

// Test case for verify tcp bad flags
BOOST_AUTO_TEST_CASE (test08)
{
        Packet packet("../tcp/packets/packet04.pcap");

	inject(packet);

        Flow *flow = tcp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<TCPInfo> info = flow->getTCPInfo();
        BOOST_CHECK(info  != nullptr);

	BOOST_CHECK(info->syn == 0);
	BOOST_CHECK(info->syn_ack == 1);
	BOOST_CHECK(info->fin == 1);
	BOOST_CHECK(info->ack == 0);

	BOOST_CHECK(tcp->isSyn() == true);
	BOOST_CHECK(tcp->isFin() == true);
	BOOST_CHECK(tcp->isAck() == true);
	BOOST_CHECK(tcp->isRst() == false);
	BOOST_CHECK(tcp->isPushSet() == false);
}

BOOST_AUTO_TEST_CASE (test09)
{
        Packet packet("../tcp/packets/packet02.pcap");

        inject(packet);

        Flow *flow = tcp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<TCPInfo> info = flow->getTCPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK( info->syn == 0);
        BOOST_CHECK( info->syn_ack == 1);
        // no syn packet so nothing to process
        BOOST_CHECK(tcp->isSyn() == true);
        BOOST_CHECK(tcp->isFin() == false);
        BOOST_CHECK(tcp->isAck() == true);
        BOOST_CHECK(tcp->isRst() == false);
        BOOST_CHECK(tcp->isPushSet() == false);
}

BOOST_AUTO_TEST_CASE (test10) // malformed tcp header
{
	Packet packet("../tcp/packets/packet03.pcap");
	
	packet.setPayloadLength(14 + 20 + 10);

	inject(packet);

	BOOST_CHECK(tcp->getTotalBytes() == 0);
	BOOST_CHECK(tcp->getTotalPackets() == 0);
	BOOST_CHECK(tcp->getTotalValidPackets() == 0);
	BOOST_CHECK(tcp->getTotalInvalidPackets() == 1);
	BOOST_CHECK(tcp->getTotalEvents() == 0);
}

#if defined(HAVE_TCP_QOS_METRICS)

// Verify the Connection setup time, time between syn and first ack
// Verify also the application response time
BOOST_AUTO_TEST_CASE (test11)
{
	std::vector<Packet> pktlist;
	Packet packet1("../tcp/packets/packet08.pcap"); // Syn packet
	packet1.setPacketTime(1);
	pktlist.push_back(packet1);
	
	Packet packet2("../tcp/packets/packet09.pcap"); // Syn Ack packet
	packet2.setPacketTime(5);
	pktlist.push_back(packet2);

	Packet packet3("../tcp/packets/packet10.pcap"); // Ack packet
	packet3.setPacketTime(10);
	pktlist.push_back(packet3);

	Packet packet4("../tcp/packets/packet11.pcap"); // Ack with data packet
	packet4.setPacketTime(11);
	pktlist.push_back(packet4);
        
	Packet packet5("../tcp/packets/packet12.pcap"); // Ack with no data packet
	packet5.setPacketTime(11);
	pktlist.push_back(packet5);
	
	Packet packet6("../tcp/packets/packet13.pcap"); // Ack with data packet
	packet6.setPacketTime(17);
	pktlist.push_back(packet6);

	// Inject the 6 packets 
	for (auto &pkt: pktlist) { 
		inject(pkt);
	}
	
        Flow *flow = tcp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<TCPInfo> info = flow->getTCPInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(info->state_curr == static_cast<int>(TcpState::ESTABLISHED));
	BOOST_CHECK(info->state_prev == static_cast<int>(TcpState::ESTABLISHED));
	BOOST_CHECK(info->connection_setup_time == 4);
	BOOST_CHECK(info->application_response_time == 1);
}

// Similar test case but with different value results
BOOST_AUTO_TEST_CASE (test12)
{
        std::vector<Packet> pktlist;
	Packet packet1("../tcp/packets/packet08.pcap"); // Syn packet
        packet1.setPacketTime(1);
        pktlist.push_back(packet1);

	Packet packet2("../tcp/packets/packet09.pcap"); // Syn Ack packet
        packet2.setPacketTime(1);
        pktlist.push_back(packet2);

	Packet packet3("../tcp/packets/packet10.pcap"); // Ack packet
        packet3.setPacketTime(1);
        pktlist.push_back(packet3);

	Packet packet4("../tcp/packets/packet11.pcap"); // Ack with data packet
        packet4.setPacketTime(2);
        pktlist.push_back(packet4);

	Packet packet5("../tcp/packets/packet12.pcap"); // Ack with no data packet
        packet5.setPacketTime(2);
        pktlist.push_back(packet5);

	Packet packet6("../tcp/packets/packet13.pcap"); // Ack with data packet
        packet6.setPacketTime(2);
        pktlist.push_back(packet6);

        // Inject the 6 packets
        for (auto &pkt: pktlist) {
		inject(pkt);
        }

        Flow *flow = tcp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<TCPInfo> info = flow->getTCPInfo();
        BOOST_CHECK( info != nullptr);

        BOOST_CHECK(info->state_curr == static_cast<int>(TcpState::ESTABLISHED));
        BOOST_CHECK(info->state_prev == static_cast<int>(TcpState::ESTABLISHED));
        BOOST_CHECK(info->connection_setup_time == 0);
        BOOST_CHECK(info->application_response_time == 1);
}

#endif

BOOST_AUTO_TEST_CASE (test13) // malformed tcp header but accepted
{
	Packet packet("../tcp/packets/packet03.pcap");

	packet.setPayloadLength(14 + 20 + 30);	

	tcp->increaseAllocatedMemory(2);

        inject(packet);

        BOOST_CHECK(tcp->getTotalBytes() == 30);
        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp->getTotalEvents() == 1);
	
	Flow *flow = tcp->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
	SharedPointer<TCPInfo> info = flow->getTCPInfo();
	BOOST_CHECK(info != nullptr);

	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::TCP_BOGUS_HEADER);	
}

BOOST_AUTO_TEST_CASE (test14) // fin, push, urg packet
{
	Packet packet("../tcp/packets/packet05.pcap");

        tcp->increaseAllocatedMemory(2);

        inject(packet);

        BOOST_CHECK(tcp->getTotalBytes() == 40);
        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp->getTotalEvents() == 0);

        Flow *flow = tcp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr); 
        SharedPointer<TCPInfo> info = flow->getTCPInfo();
        BOOST_CHECK(info  != nullptr);

        BOOST_CHECK(info->syn == 0);
        BOOST_CHECK(info->syn_ack == 0);
        BOOST_CHECK(info->fin == 1);
        BOOST_CHECK(info->ack == 0);

        BOOST_CHECK(tcp->isSyn() == false);
        BOOST_CHECK(tcp->isFin() == true);
        BOOST_CHECK(tcp->isAck() == false);
        BOOST_CHECK(tcp->isRst() == false);
        BOOST_CHECK(tcp->isPushSet() == true);
}

BOOST_AUTO_TEST_CASE (test15) // syn rst packet malformed
{
	Packet packet("../tcp/packets/packet06.pcap");

        tcp->increaseAllocatedMemory(1);

        inject(packet);

        BOOST_CHECK(tcp->getTotalBytes() == 20);
        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp->getTotalEvents() == 1);

        Flow *flow = tcp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<TCPInfo> info = flow->getTCPInfo();
        BOOST_CHECK(info  != nullptr);

        BOOST_CHECK(info->syn == 1);
        BOOST_CHECK(info->syn_ack == 0);
        BOOST_CHECK(info->fin == 0);
        BOOST_CHECK(info->ack == 0);

        BOOST_CHECK(tcp->isSyn() == true);
        BOOST_CHECK(tcp->isFin() == false);
        BOOST_CHECK(tcp->isAck() == false);
        BOOST_CHECK(tcp->isRst() == true);
        BOOST_CHECK(tcp->isPushSet() == false);
        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::TCP_BAD_FLAGS);
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_FIXTURE_TEST_SUITE(tcp_test_suite2, StackIPv6TCPTest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet("../http/packets/packet11.pcap");

	inject(packet);

        // Check the TCP integrity
        BOOST_CHECK(tcp->getSourcePort() == 1287);
        BOOST_CHECK(tcp->getDestinationPort() == 80);
        BOOST_CHECK(tcp->getTotalBytes() == 797+20);
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../ip6/packets/packet02.pcap");

	inject(packet);

        // Check the TCP integrity
        BOOST_CHECK(tcp->getSourcePort() == 36951);
        BOOST_CHECK(tcp->getDestinationPort() == 80);
        BOOST_CHECK(tcp->getTotalBytes() == 15+20);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../ip6/packets/packet04.pcap");

	inject(packet);

        // Check the TCP integrity
        BOOST_CHECK(tcp->getSourcePort() == 17257);
        BOOST_CHECK(tcp->getDestinationPort() == 80);
	BOOST_CHECK(tcp->isSyn() == true);
	BOOST_CHECK(tcp->isFin() == false);
	BOOST_CHECK(tcp->isRst() == false);
	BOOST_CHECK(tcp->isAck() == false);
	BOOST_CHECK(tcp->isPushSet() == false);
        BOOST_CHECK(tcp->getTotalBytes() == 20);
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../ip6/packets/packet03.pcap");

	inject(packet);

        // Check the TCP integrity
        BOOST_CHECK(tcp->getSourcePort() == 55617);
        BOOST_CHECK(tcp->getDestinationPort() == 80);
        BOOST_CHECK(tcp->isSyn() == true);
        BOOST_CHECK(tcp->isFin() == false);
        BOOST_CHECK(tcp->isRst() == false);
        BOOST_CHECK(tcp->isAck() == false);
        BOOST_CHECK(tcp->isPushSet() == false);
        BOOST_CHECK(tcp->getTotalBytes() == 40);
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE(tcp_test_suite3)
// Unit tests for the tcp state machine

BOOST_AUTO_TEST_CASE (test01)
{
	int flags = static_cast<int>(TcpFlags::INVALID);
	FlowDirection dir = FlowDirection::FORWARD;
	int state = static_cast<int>(TcpState::CLOSED);

	int newstate = ((tcp_states[state]).state)->dir[static_cast<int>(dir)].flags[flags];	

	BOOST_CHECK(newstate == 0);

	// receive a syn packet for the three way handshake
	flags = static_cast<int>(TcpFlags::SYN);
	dir = FlowDirection::FORWARD;

	state = newstate;	
	newstate = ((tcp_states[static_cast<int>(state)]).state)->dir[static_cast<int>(dir)].flags[flags];	

	BOOST_CHECK(newstate == static_cast<int>(TcpState::SYN_SENT));

	flags = static_cast<int>(TcpFlags::SYNACK);
	dir = FlowDirection::BACKWARD;
	state = newstate;	
	newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];	

	BOOST_CHECK(newstate == static_cast<int>(TcpState::SYN_RECEIVED));

	flags = static_cast<int>(TcpFlags::ACK);
	dir = FlowDirection::FORWARD;
	state = newstate;	
	newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];	
	BOOST_CHECK(newstate == static_cast<int>(TcpState::ESTABLISHED));
}

BOOST_AUTO_TEST_CASE (test02)
{
	// The flow have been established previously
     
        int flags = static_cast<int>(TcpFlags::ACK);
        FlowDirection dir = FlowDirection::BACKWARD;
        int state = static_cast<int>(TcpState::ESTABLISHED);
	int newstate = state;
        newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];
        if (newstate == -1) { // Keep on the same state
                newstate = state;
        }
        BOOST_CHECK(newstate == static_cast<int>(TcpState::ESTABLISHED));

        dir = FlowDirection::FORWARD;
	state = newstate;
        newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];
        if (newstate == -1) { // Keep on the same state
                newstate = state;
        }
        BOOST_CHECK(newstate == static_cast<int>(TcpState::ESTABLISHED));

	flags = static_cast<int>(TcpFlags::ACK);
        dir = FlowDirection::BACKWARD;
        state = newstate;
        newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];
        if (newstate == -1) { // Keep on the same state
                newstate = state;
        }
        BOOST_CHECK(newstate == static_cast<int>(TcpState::ESTABLISHED));
}

BOOST_AUTO_TEST_CASE (test03)
{
        // The flow have been established previously and a wrong flag appears

        int flags = static_cast<int>(TcpFlags::ACK);
        FlowDirection dir = FlowDirection::BACKWARD;
        int state = static_cast<int>(TcpState::ESTABLISHED);
        int newstate = state;
        newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];
        if (newstate == -1) { // Keep on the same state
                newstate = state;
        }
        BOOST_CHECK(newstate == static_cast<int>(TcpState::ESTABLISHED));

	
        flags = static_cast<int>(TcpFlags::SYNACK);
        dir = FlowDirection::FORWARD;
        state = newstate;
        newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];

        BOOST_CHECK(newstate == static_cast<int>(TcpState::CLOSED));
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_FIXTURE_TEST_SUITE(tcp_test_suite_timeouts, StackTCPTest)
// Unit tests for test the timeouts on the tcp part

BOOST_AUTO_TEST_CASE (test01) // Two flows, the first expires
{
	Packet packet1("../tcp/packets/packet01.pcap");
	Packet packet2("../tcp/packets/packet07.pcap");

	packet2.setPacketTime(100); // 100 seconds after	

	flow_mng->setTimeout(80);

	inject(packet1);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

	inject(packet2);

	BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
	BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 1);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);
}

BOOST_AUTO_TEST_CASE (test02) // Two flows, none of them expires due to the timeout value
{
	Packet packet1("../tcp/packets/packet01.pcap");
	Packet packet2("../tcp/packets/packet07.pcap");

	packet2.setPacketTime(100); // 100 seconds after

        flow_mng->setTimeout(120);

	inject(packet1);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

	inject(packet2);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 0);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);
}

BOOST_AUTO_TEST_CASE (test03) // Two flows, the first expires
{
	Packet packet1("../tcp/packets/packet01.pcap");
	Packet packet2("../tcp/packets/packet07.pcap");

	packet2.setPacketTime(100); // 100 seconds after

	flow_mng->setReleaseFlows(false); // The flows will be on memory

        flow_mng->setTimeout(80);

        inject(packet1);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

        inject(packet2);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFlows() == 0);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);
}

BOOST_AUTO_TEST_SUITE_END( )
