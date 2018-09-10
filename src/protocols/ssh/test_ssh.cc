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
#include "test_ssh.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE sshtest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(ssh_test_suite, StackSSHtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

	BOOST_CHECK(ssh->getTotalBytes() == 0);
	BOOST_CHECK(ssh->getTotalPackets() == 0);
	BOOST_CHECK(ssh->getTotalValidPackets() == 0);
	BOOST_CHECK(ssh->getTotalInvalidPackets() == 0);
	BOOST_CHECK(ssh->processPacket(packet) == true);
	
	CounterMap c = ssh->getCounters();

	BOOST_CHECK(ssh->isDynamicAllocatedMemory() == false);

	auto v1 = ssh->getCurrentUseMemory();
	auto v2 = ssh->getAllocatedMemory();
	auto v3 = ssh->getTotalAllocatedMemory();

	BOOST_CHECK(ssh->getTotalCacheMisses() == 0);

	ssh->decreaseAllocatedMemory(10);
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet1("../ssh/packets/packet01.pcap");
	Packet packet2("../ssh/packets/packet02.pcap");

	inject(packet1);

        Flow *flow = ssh->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SSHInfo> info = flow->getSSHInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(info->isHandshake() == true);
	BOOST_CHECK(info->getTotalEncryptedBytes() == 0);

	BOOST_CHECK(ssh->getTotalBytes() == 25);
	BOOST_CHECK(ssh->getTotalPackets() == 1);
	BOOST_CHECK(ssh->getTotalValidPackets() == 1);
	BOOST_CHECK(ssh->getTotalInvalidPackets() == 0);

	inject(packet2);

        flow = ssh->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	info = flow->getSSHInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(info->isHandshake() == true);
	BOOST_CHECK(info->getTotalEncryptedBytes() == 0);

	BOOST_CHECK(ssh->getTotalBytes() == 25 + 21);
	BOOST_CHECK(ssh->getTotalPackets() == 2);
	BOOST_CHECK(ssh->getTotalValidPackets() == 1);
	BOOST_CHECK(ssh->getTotalInvalidPackets() == 0);
	BOOST_CHECK(ssh->getTotalHandshakePDUs() == 0);

        BOOST_CHECK(ssh->getTotalAlgorithmNegotiationMessages() == 0);
        BOOST_CHECK(ssh->getTotalKeyExchangeMessages() == 0);
        BOOST_CHECK(ssh->getTotalOthers() == 0);
        BOOST_CHECK(ssh->getTotalEncryptedBytes() == 0);

	// Force a release
	ssh->releaseFlowInfo(flow);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../ssh/packets/packet03.pcap", 66);
        auto flow = SharedPointer<Flow>(new Flow());

	flow->total_packets_l7 = 3;
        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);

        ssh->processFlow(flow.get());

	BOOST_CHECK(ssh->getTotalBytes() == 600);
	BOOST_CHECK(ssh->getTotalPackets() == 1);
	BOOST_CHECK(ssh->getTotalHandshakePDUs() == 1);
        
        BOOST_CHECK(ssh->getTotalAlgorithmNegotiationMessages() == 1);
        BOOST_CHECK(ssh->getTotalKeyExchangeMessages() == 0);
        BOOST_CHECK(ssh->getTotalOthers() == 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../ssh/packets/packet04.pcap", 66);
        auto flow = SharedPointer<Flow>(new Flow());

	flow->total_packets_l7 = 4;
        flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet);

        ssh->processFlow(flow.get());

	BOOST_CHECK(ssh->getTotalBytes() == 784);
	BOOST_CHECK(ssh->getTotalPackets() == 1);
	BOOST_CHECK(ssh->getTotalHandshakePDUs() == 1);
	
        BOOST_CHECK(ssh->getTotalAlgorithmNegotiationMessages() == 1);
        BOOST_CHECK(ssh->getTotalKeyExchangeMessages() == 0);
        BOOST_CHECK(ssh->getTotalOthers() == 0);
        BOOST_CHECK(ssh->getTotalEncryptedBytes() == 0);
}

BOOST_AUTO_TEST_CASE (test05)
{
	Packet packet("../ssh/packets/packet05.pcap", 66);
        auto flow = SharedPointer<Flow>(new Flow());

	flow->total_packets_l7 = 4;
        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);

        ssh->processFlow(flow.get());

	BOOST_CHECK(ssh->getTotalBytes() == 144);
	BOOST_CHECK(ssh->getTotalPackets() == 1);
	BOOST_CHECK(ssh->getTotalHandshakePDUs() == 1);
	
        BOOST_CHECK(ssh->getTotalAlgorithmNegotiationMessages() == 0);
        BOOST_CHECK(ssh->getTotalKeyExchangeMessages() == 1);
        BOOST_CHECK(ssh->getTotalOthers() == 0);
        BOOST_CHECK(ssh->getTotalEncryptedBytes() == 0);
}

BOOST_AUTO_TEST_CASE (test06)
{
        auto flow = SharedPointer<Flow>(new Flow());
	Packet packet("../ssh/packets/packet06.pcap", 66);

	flow->total_packets_l7 = 4;
        flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet);

        ssh->processFlow(flow.get());

	BOOST_CHECK(ssh->getTotalBytes() == 720);
	BOOST_CHECK(ssh->getTotalPackets() == 1);
	BOOST_CHECK(ssh->getTotalHandshakePDUs() == 2);
	
        BOOST_CHECK(ssh->getTotalAlgorithmNegotiationMessages() == 1);
        BOOST_CHECK(ssh->getTotalKeyExchangeMessages() == 1);
        BOOST_CHECK(ssh->getTotalOthers() == 0);
        BOOST_CHECK(ssh->getTotalEncryptedBytes() == 0);

	SharedPointer<SSHInfo> info = flow->getSSHInfo();
        BOOST_CHECK(info != nullptr);

	// The next packet from the server will be encrypted
	BOOST_CHECK(info->isServerHandshake() == false);
}

BOOST_AUTO_TEST_CASE (test07)
{
        auto flow = SharedPointer<Flow>(new Flow());
	Packet packet("../ssh/packets/packet07.pcap", 66);

	flow->total_packets_l7 = 4;
        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);

        ssh->processFlow(flow.get());

	BOOST_CHECK(ssh->getTotalBytes() == 16);
	BOOST_CHECK(ssh->getTotalPackets() == 1);
	BOOST_CHECK(ssh->getTotalHandshakePDUs() == 1);
	
        BOOST_CHECK(ssh->getTotalAlgorithmNegotiationMessages() == 1);
        BOOST_CHECK(ssh->getTotalKeyExchangeMessages() == 0);
        BOOST_CHECK(ssh->getTotalOthers() == 0);
        BOOST_CHECK(ssh->getTotalEncryptedBytes() == 0);
	
	SharedPointer<SSHInfo> info = flow->getSSHInfo();
        BOOST_CHECK(info != nullptr);

	// The client will send the next packet encrypted
	BOOST_CHECK(info->isClientHandshake() == false);
	BOOST_CHECK(info->getTotalEncryptedBytes() == 0);
	
	BOOST_CHECK(ssh->getTotalEncryptedBytes() == 0);
	BOOST_CHECK(ssh->getTotalEncryptedPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test08) 
{
	Packet packet1("../ssh/packets/packet06.pcap", 66);
	Packet packet2("../ssh/packets/packet07.pcap", 66);
	Packet packet3("../ssh/packets/packet08.pcap", 66);

        auto flow = SharedPointer<Flow>(new Flow());

	ssh->setDynamicAllocatedMemory(true);

	flow->total_packets_l7 = 4;
        flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet1);

	// Inject the server packet
        ssh->processFlow(flow.get());

	SharedPointer<SSHInfo> info = flow->getSSHInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(info->isClientHandshake() == true);
	BOOST_CHECK(info->isServerHandshake() == false);
	BOOST_CHECK(info->isHandshake() == true);
	BOOST_CHECK(info->getTotalEncryptedBytes() == 0);
        
	flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet2);
       
	// Inject the client packet 
	ssh->processFlow(flow.get());

	BOOST_CHECK(info->isClientHandshake() == false);
	BOOST_CHECK(info->isServerHandshake() == false);
	BOOST_CHECK(info->isHandshake() == false);
	BOOST_CHECK(info->getTotalEncryptedBytes() == 0);

	flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet3);

	// Inject the client encrypted packet        
	ssh->processFlow(flow.get());

	// The number of encrypted bytes should be non zero

	BOOST_CHECK(info->isClientHandshake() == false);
	BOOST_CHECK(info->isServerHandshake() == false);
	BOOST_CHECK(info->isHandshake() == false);
	BOOST_CHECK(info->getTotalEncryptedBytes() == 48);
	
	BOOST_CHECK(ssh->getTotalEncryptedBytes() == 48);
	BOOST_CHECK(ssh->getTotalEncryptedPackets() == 1);

        JsonFlow j;
        info->serialize(j);

	{
		RedirectOutput r;

        	flow->serialize(r.cout);
        	flow->showFlowInfo(r.cout);
        	r.cout << *(info.get());
		ssh->statistics(r.cout, 5);
     	} 
}

BOOST_AUTO_TEST_CASE (test09) // Two pdus and the latest is encrypted
{
        auto flow = SharedPointer<Flow>(new Flow());
        Packet packet("../ssh/packets/packet12.pcap", 54);

        flow->total_packets_l7 = 4;
        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);

        ssh->processFlow(flow.get());

        BOOST_CHECK(ssh->getTotalBytes() == 64);
        BOOST_CHECK(ssh->getTotalPackets() == 1);
        BOOST_CHECK(ssh->getTotalHandshakePDUs() == 2);

        SharedPointer<SSHInfo> info = flow->getSSHInfo();
        BOOST_CHECK(info != nullptr);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ipv6_ssh_test_suite, StackIPv6SSHtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet("../ssh/packets/packet11.pcap");

        inject(packet);

        Flow *flow = ssh->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SSHInfo> info = flow->getSSHInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->isHandshake() == true);
        BOOST_CHECK(info->getTotalEncryptedBytes() == 0);

        BOOST_CHECK(ssh->getTotalBytes() == 19);
        BOOST_CHECK(ssh->getTotalPackets() == 1);
        BOOST_CHECK(ssh->getTotalValidPackets() == 1);
        BOOST_CHECK(ssh->getTotalInvalidPackets() == 0);

        JsonFlow j;
        info->serialize(j);

	{
		RedirectOutput r;

        	flow->serialize(r.cout);
        	flow->showFlowInfo(r.cout);
        	r.cout << *(info.get());
        	ssh->statistics(r.cout, 5);
	}

	ssh->releaseCache();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../ssh/packets/packet09.pcap", 74);
        auto flow = SharedPointer<Flow>(new Flow());

	flow->total_packets_l7 = 4;
        flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet);

        ssh->processFlow(flow.get());

	BOOST_CHECK(ssh->getTotalBytes() == 16);
	BOOST_CHECK(ssh->getTotalPackets() == 1);
	BOOST_CHECK(ssh->getTotalHandshakePDUs() == 1);
	
        BOOST_CHECK(ssh->getTotalAlgorithmNegotiationMessages() == 1);
        BOOST_CHECK(ssh->getTotalKeyExchangeMessages() == 0);
        BOOST_CHECK(ssh->getTotalOthers() == 0);
        BOOST_CHECK(ssh->getTotalEncryptedBytes() == 0);
	
	SharedPointer<SSHInfo> info = flow->getSSHInfo();
        BOOST_CHECK(info != nullptr);
	
	BOOST_CHECK(info->isClientHandshake() == true);
	BOOST_CHECK(info->isServerHandshake() == false);
	BOOST_CHECK(info->isHandshake() == true);
	BOOST_CHECK(info->getTotalEncryptedBytes() == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
        auto flow = SharedPointer<Flow>(new Flow());
	Packet packet("../ssh/packets/packet10.pcap", 74);

	flow->total_packets_l7 = 4;
        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);

        ssh->processFlow(flow.get());

	BOOST_CHECK(ssh->getTotalBytes() == 16);
	BOOST_CHECK(ssh->getTotalPackets() == 1);
	BOOST_CHECK(ssh->getTotalHandshakePDUs() == 1);
	
        BOOST_CHECK(ssh->getTotalAlgorithmNegotiationMessages() == 1);
        BOOST_CHECK(ssh->getTotalKeyExchangeMessages() == 0);
        BOOST_CHECK(ssh->getTotalOthers() == 0);
        BOOST_CHECK(ssh->getTotalEncryptedBytes() == 0);
	
	SharedPointer<SSHInfo> info = flow->getSSHInfo();
        BOOST_CHECK(info != nullptr);
	
	BOOST_CHECK(info->isClientHandshake() == false);
	BOOST_CHECK(info->isServerHandshake() == true);
	BOOST_CHECK(info->isHandshake() == true);
	BOOST_CHECK(info->getTotalEncryptedBytes() == 0);
}

BOOST_AUTO_TEST_CASE (test04) // Memory failure test
{
	Packet packet("../ssh/packets/packet11.pcap");

	ssh->decreaseAllocatedMemory(10);

        inject(packet);

        Flow *flow = ssh->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SSHInfo> info = flow->getSSHInfo();
        BOOST_CHECK(info == nullptr);
}

BOOST_AUTO_TEST_CASE (test05) // Bogus length on the packet
{
        auto flow = SharedPointer<Flow>(new Flow());
	Packet packet("../ssh/packets/packet10.pcap", 74);
	uint8_t buffer[128];

	std::memcpy(buffer, packet.getPayload(), 128);
	buffer[1] = '\xff';
	buffer[2] = '\xff';
	buffer[3] = '\xff';
        Packet packet_mod(buffer, packet.getLength() - 74);

	flow->total_packets_l7 = 4;
        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet_mod);

        ssh->processFlow(flow.get());

        SharedPointer<SSHInfo> info = flow->getSSHInfo();
        BOOST_CHECK(info != nullptr);
	
	BOOST_CHECK(ssh->getTotalPackets() == 1);
	BOOST_CHECK(ssh->getTotalHandshakePDUs() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
