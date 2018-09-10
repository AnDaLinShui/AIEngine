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
#include "test_smb.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE smbtest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(smb_test_suite, StackSMBtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

	BOOST_CHECK(smb->getTotalBytes() == 0);
	BOOST_CHECK(smb->getTotalPackets() == 0);
	BOOST_CHECK(smb->getTotalValidPackets() == 0);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);
	BOOST_CHECK(smb->processPacket(packet) == true);
	
	CounterMap c = smb->getCounters();

	smb->decreaseAllocatedMemory(10);
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../smb/packets/packet01.pcap");

	inject(packet);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 168);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

	BOOST_CHECK(info->getCommand() == SMB_CMD_NEGO_PROTO);

	CounterMap c = smb->getCounters();

	// Force a release
	smb->releaseFlowInfo(flow);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../smb/packets/packet02.pcap");

	inject(packet);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 194);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);
	
	BOOST_CHECK(info->getCommand() == SMB_CMD_NEGO_PROTO);
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../smb/packets/packet03.pcap");

	inject(packet);
        
	Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 45);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);
	
	BOOST_CHECK(info->getCommand() == SMB_CMD_CLOSE_FILE);
}

BOOST_AUTO_TEST_CASE (test05)
{
	Packet packet("../smb/packets/packet04.pcap");

	inject(packet);

	Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 96);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);
	
	BOOST_CHECK(info->getCommand() == SMB_CMD_GET_FILE_ATTR);
}

BOOST_AUTO_TEST_CASE (test06)
{
	Packet packet("../smb/packets/packet05.pcap");

	inject(packet);

	Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 348);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

	BOOST_CHECK(info->getCommand() == SMB2_CMD_CREATE_FILE);
}

BOOST_AUTO_TEST_CASE (test07)
{
	Packet packet("../smb/packets/packet06.pcap");

	inject(packet);

	Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 92);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

	BOOST_CHECK(info->getCommand() == SMB_CMD_TREE_CONNECT);
}

BOOST_AUTO_TEST_CASE (test08)
{
	Packet packet("../smb/packets/packet07.pcap");

	inject(packet);

	Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 108);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

	BOOST_CHECK(info->getCommand() == SMB2_CMD_TREE_CONNECT);
}

BOOST_AUTO_TEST_CASE (test09)
{
	Packet packet("../smb/packets/packet08.pcap");

	inject(packet);

	Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 92);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

	BOOST_CHECK(info->getCommand() == SMB2_CMD_CLOSE_FILE);
}

BOOST_AUTO_TEST_CASE (test10)
{
	Packet packet("../smb/packets/packet09.pcap");

	inject(packet);

	Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 324);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

	BOOST_CHECK(info->getCommand() == SMB2_CMD_CREATE_FILE);
        BOOST_CHECK(info->filename != nullptr);

	std::string filename("putty.exe");
	BOOST_CHECK(filename.compare(info->filename->getName()) == 0);

        {
                RedirectOutput r;

                flow->serialize(r.cout);
                flow->showFlowInfo(r.cout);
                r.cout << *(info.get());
        }

        JsonFlow j;
        info->serialize(j);
	
	smb->releaseCache();
	BOOST_CHECK(flow->getSMBInfo() == nullptr);
}

BOOST_AUTO_TEST_CASE (test11)
{
	Packet packet("../smb/packets/packet10.pcap");

	inject(packet);

	Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 109);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

	BOOST_CHECK(info->getCommand() == SMB2_CMD_GET_INFO);
}

BOOST_AUTO_TEST_CASE (test12)
{
	Packet packet("../smb/packets/packet11.pcap");

	inject(packet);

	Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 182);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

	BOOST_CHECK(info->getCommand() == SMB_CMD_TRANS2);
}

BOOST_AUTO_TEST_CASE (test13)
{
	Packet packet("../smb/packets/packet12.pcap");

	inject(packet);

	Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<NetbiosInfo> ninfo = flow->getNetbiosInfo();
        BOOST_CHECK(ninfo == nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 63);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

	BOOST_CHECK(info->getCommand() == SMB_CMD_READ);
}

BOOST_AUTO_TEST_CASE (test14)
{
	Packet packet1("../smb/packets/packet13.pcap");
	Packet packet2("../smb/packets/packet14.pcap");

	inject(packet1);

	Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 117);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

	BOOST_CHECK(info->getCommand() == SMB2_CMD_READ_FILE);
	
	inject(packet2);

	flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 117 + 297);
	BOOST_CHECK(smb->getTotalPackets() == 2);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

	BOOST_CHECK(info->getCommand() == SMB2_CMD_READ_FILE);
}

BOOST_AUTO_TEST_CASE (test15)
{
	Packet packet1("../smb/packets/packet15.pcap");
	Packet packet2("../smb/packets/packet16.pcap");

	inject(packet1);

	Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 2896);
	BOOST_CHECK(smb->getTotalPackets() == 1);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

	BOOST_CHECK(info->getCommand() == SMB2_CMD_WRITE_FILE);
	
	inject(packet2);

	flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(smb->getTotalBytes() == 2896 + 84);
	BOOST_CHECK(smb->getTotalPackets() == 2);
	BOOST_CHECK(smb->getTotalValidPackets() == 1);
	BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

	BOOST_CHECK(info->getCommand() == SMB2_CMD_WRITE_FILE);
}

BOOST_AUTO_TEST_CASE (test16) // malformed packet
{
	Packet packet_tmp("../smb/packets/packet12.pcap");
	uint8_t modbuf[packet_tmp.getLength()]; 

	std::memcpy(&modbuf, packet_tmp.getPayload(), packet_tmp.getLength());

	// modify the version with other byte
	modbuf[14 + 20 + 32 + 4] = 0xaa;

        Packet packet(&modbuf[0], packet_tmp.getLength());

        inject(packet);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(smb->getTotalBytes() == 63);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        PacketAnomalyType pa = flow->getPacketAnomaly();
        BOOST_CHECK(pa == PacketAnomalyType::SMB_BOGUS_HEADER);
        BOOST_CHECK(smb->getTotalEvents() == 1);

	// No command setup
        BOOST_CHECK(info->getCommand() == 0);
}

BOOST_AUTO_TEST_CASE (test17) // malformed packet
{
	Packet packet("../smb/packets/packet12.pcap", 54);
	packet.setPayloadLength(7);
	auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);

        smb->processFlow(flow.get());

        BOOST_CHECK(smb->getTotalBytes() == 7);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 0);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info == nullptr);

        PacketAnomalyType pa = flow->getPacketAnomaly();
        BOOST_CHECK(pa == PacketAnomalyType::SMB_BOGUS_HEADER);
        BOOST_CHECK(smb->getTotalEvents() == 1);
}

BOOST_AUTO_TEST_CASE (test18) // two flows managing the same file
{
	Packet packet("../smb/packets/packet09.pcap", 54);

        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());

        flow1->setFlowDirection(FlowDirection::FORWARD);
        flow1->packet = const_cast<Packet*>(&packet);
        flow2->setFlowDirection(FlowDirection::FORWARD);
        flow2->packet = const_cast<Packet*>(&packet);

        smb->processFlow(flow1.get());
        smb->processFlow(flow2.get());

        SharedPointer<SMBInfo> info1 = flow1->getSMBInfo();
        BOOST_CHECK(info1 != nullptr);
        SharedPointer<SMBInfo> info2 = flow2->getSMBInfo();
        BOOST_CHECK(info2 != nullptr);
        BOOST_CHECK(info1->getCommand() == SMB2_CMD_CREATE_FILE);
        BOOST_CHECK(info2->getCommand() == SMB2_CMD_CREATE_FILE);
        BOOST_CHECK(info1->filename != nullptr);
        BOOST_CHECK(info2->filename != nullptr);
        BOOST_CHECK(info2->filename == info2->filename);
}

BOOST_AUTO_TEST_CASE (test19)
{
	Packet packet("../smb/packets/packet17.pcap");

        inject(packet);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(smb->getTotalBytes() == 164);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        BOOST_CHECK(info->getCommand() == SMB_CMD_SESSION_SETUP);
}

BOOST_AUTO_TEST_CASE (test20) // memory fail
{
	Packet packet("../smb/packets/packet17.pcap");

	smb->decreaseAllocatedMemory(10);

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 164);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info == nullptr);
}

BOOST_AUTO_TEST_CASE (test21) 
{
	Packet packet("../smb/packets/packet18.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 39);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == SMB_CMD_TREE_DISC);
}

BOOST_AUTO_TEST_CASE (test22) 
{
	Packet packet("../smb/packets/packet19.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 43);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == SMB_CMD_LOGOFF);
}

BOOST_AUTO_TEST_CASE (test23) 
{
	Packet packet("../smb/packets/packet20.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 104);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == SMB_CMD_NT_CREATE);
}

BOOST_AUTO_TEST_CASE (test24) // delete file
{
	Packet packet("../smb/packets/packet21.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 56);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == SMB_CMD_DELETE_FILE);
}

BOOST_AUTO_TEST_CASE (test25) // open andx 
{
	Packet packet("../smb/packets/packet22.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 83);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == SMB_CMD_OPEN_ANDX);

        BOOST_CHECK(info->filename != nullptr);

	std::string filename("\\uKKUQIEr.exe");
	BOOST_CHECK(filename.compare(info->filename->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test26) // rename file
{
	Packet packet("../smb/packets/packet23.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 134);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == SMB_CMD_RENAME_FILE);
}

BOOST_AUTO_TEST_CASE (test27) // write andx message 
{
	Packet packet("../smb/packets/packet24.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 51);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == SMB_CMD_WRITE_ANDX);
}

BOOST_AUTO_TEST_CASE (test28) // create message
{
	Packet packet("../smb/packets/packet25.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 102);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == SMB_CMD_CREATE_FILE);
        BOOST_CHECK(info->filename != nullptr);

        std::string filename("\\rawopen\\torture_create.txt");

        BOOST_CHECK(filename.compare(info->filename->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test29) // Flush
{
	Packet packet("../smb/packets/packet26.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 41);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == SMB_CMD_FLUSH_FILES);
}

BOOST_AUTO_TEST_CASE (test30) // set attributes
{
	Packet packet("../smb/packets/packet27.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 126);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == SMB_CMD_SET_FILE_ATTR);
}

BOOST_AUTO_TEST_CASE (test31) // create directory
{
	Packet packet("../smb/packets/packet28.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 88);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == SMB_CMD_CREATE_DIR);
        BOOST_CHECK(info->filename != nullptr);

        std::string filename("\\rawchkpath\\nt\\V S\\VB98");

        BOOST_CHECK(filename.compare(info->filename->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test32) // delete directory
{
	Packet packet("../smb/packets/packet29.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 96);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == SMB_CMD_DELETE_DIR);
}

BOOST_AUTO_TEST_CASE (test33) // process exist
{
	Packet packet("../smb/packets/packet30.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 39);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == 17);
}

BOOST_AUTO_TEST_CASE (test34) // ioctl response error
{
	Packet packet("../smb/packets/packet31.pcap");

        inject(packet);

        BOOST_CHECK(smb->getTotalBytes() == 77);
        BOOST_CHECK(smb->getTotalPackets() == 1);
        BOOST_CHECK(smb->getTotalValidPackets() == 1);
        BOOST_CHECK(smb->getTotalInvalidPackets() == 0);

        Flow *flow = smb->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<SMBInfo> info = flow->getSMBInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == 11);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ipv6_smb_test_suite, StackIPv6SMBtest)

BOOST_AUTO_TEST_CASE (test01)
{
/*
 * TODO
 */
}

BOOST_AUTO_TEST_SUITE_END()
