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
#include "test_mqtt.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE mqtttest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(mqtt_test_suite, StackMQTTtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

        BOOST_CHECK(mqtt->getTotalPackets() == 0);
        BOOST_CHECK(mqtt->getTotalValidPackets() == 0);
        BOOST_CHECK(mqtt->getTotalInvalidPackets() == 0);
        BOOST_CHECK(mqtt->getTotalBytes() == 0);
	BOOST_CHECK(mqtt->processPacket(packet) == true);
	
	CounterMap c = mqtt->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../mqtt/packets/packet01.pcap");

	inject(packet);

        BOOST_CHECK(mqtt->getTotalPackets() == 1);
        BOOST_CHECK(mqtt->getTotalValidPackets() == 1);
        BOOST_CHECK(mqtt->getTotalBytes() == 77);

	BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT));
	BOOST_CHECK(mqtt->getFlags() == 0x00);
	BOOST_CHECK(mqtt->getLength() == 75);

	BOOST_CHECK(mqtt->getTotalClientCommands() == 1);
	BOOST_CHECK(mqtt->getTotalServerCommands() == 0);

        Flow *flow = mqtt->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<MQTTInfo> info = flow->getMQTTInfo();
        BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT));

	mqtt->releaseFlowInfo(flow);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet1("../mqtt/packets/packet01.pcap", 54);
	Packet packet2("../mqtt/packets/packet02.pcap", 54);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet1);
       	mqtt->processFlow(flow.get());
       
	// some checks on the first packet 
        BOOST_CHECK(mqtt->getTotalPackets() == 1);
        BOOST_CHECK(mqtt->getTotalBytes() == 77);

        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT));
        BOOST_CHECK(mqtt->getFlags() == 0x00);
        BOOST_CHECK(mqtt->getLength() == 75);

	flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet2);
       	mqtt->processFlow(flow.get());

        BOOST_CHECK(mqtt->getTotalPackets() == 2);
        BOOST_CHECK(mqtt->getTotalBytes() == 77 + 6);

        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNACK));
        BOOST_CHECK(mqtt->getFlags() == 0x00);
        BOOST_CHECK(mqtt->getLength() == 2);

        BOOST_CHECK(mqtt->getTotalClientCommands() == 1);
        BOOST_CHECK(mqtt->getTotalServerCommands() == 1);

        Flow *curr_flow = mqtt->getCurrentFlow();

        BOOST_CHECK( curr_flow != nullptr);
        SharedPointer<MQTTInfo> info = curr_flow->getMQTTInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNACK));
        BOOST_CHECK(info->getTotalClientCommands() == 1);
        BOOST_CHECK(info->getTotalServerCommands() == 1);
}

BOOST_AUTO_TEST_CASE (test04) 
{
	Packet packet1("../mqtt/packets/packet03.pcap", 54);
	Packet packet2("../mqtt/packets/packet04.pcap", 54);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet1);
        mqtt->processFlow(flow.get());

        SharedPointer<MQTTInfo> info = flow->getMQTTInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_SUBSCRIBE));

        BOOST_CHECK(info->getTotalClientCommands() == 1);
        BOOST_CHECK(info->getTotalServerCommands() == 0);

        flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet2);
        mqtt->processFlow(flow.get());

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_SUBACK));

        BOOST_CHECK(info->getTotalClientCommands() == 1);
        BOOST_CHECK(info->getTotalServerCommands() == 1);
}

BOOST_AUTO_TEST_CASE (test05) 
{
	Packet packet1("../mqtt/packets/packet05.pcap", 54);
	Packet packet2("../mqtt/packets/packet06.pcap", 54);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet1);
        mqtt->processFlow(flow.get());

        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));
        BOOST_CHECK(mqtt->getFlags() == 0x02);
        BOOST_CHECK(mqtt->getLength() == 260);

        SharedPointer<MQTTInfo> info = flow->getMQTTInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));

	BOOST_CHECK(info->topic != nullptr);

	std::string topic("/test");
	BOOST_CHECK(topic.compare(info->topic->getName()) == 0);

        BOOST_CHECK(info->getTotalClientCommands() == 1);
        BOOST_CHECK(info->getTotalServerCommands() == 0);

        flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet2);
        mqtt->processFlow(flow.get());

        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBACK));
        BOOST_CHECK(mqtt->getFlags() == 0x00);
        BOOST_CHECK(mqtt->getLength() == 2);

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBACK));

        BOOST_CHECK(info->getTotalClientCommands() == 1);
        BOOST_CHECK(info->getTotalServerCommands() == 1);
}

BOOST_AUTO_TEST_CASE (test06)
{
	Packet packet1("../mqtt/packets/packet07.pcap", 54);
	Packet packet2("../mqtt/packets/packet08.pcap", 54);
        
	auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet1);
        mqtt->processFlow(flow.get());

	// The first packet have the information and the second is just pure payload
        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));
        BOOST_CHECK(mqtt->getFlags() == 0x02);
        BOOST_CHECK(mqtt->getLength() == 2057);

        SharedPointer<MQTTInfo> info = flow->getMQTTInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));
        BOOST_CHECK(info->getTotalClientCommands() == 1);
        BOOST_CHECK(info->getTotalServerCommands() == 0);
	BOOST_CHECK(info->getHaveData() == true );
	BOOST_CHECK(info->getDataChunkLength() == 595); // The data left to read
	BOOST_CHECK(info->topic != nullptr);

	std::string topic("/test");
	BOOST_CHECK( topic.compare(info->topic->getName()) == 0);

	// This packet just contains data payload
        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet2);
        mqtt->processFlow(flow.get());

	// This are the old values 
        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));
        BOOST_CHECK(mqtt->getFlags() == 0x02);
        BOOST_CHECK(mqtt->getLength() == 2057);

	// the minfo have change
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));
        BOOST_CHECK(info->getTotalClientCommands() == 1);
        BOOST_CHECK(info->getTotalServerCommands() == 0);
	BOOST_CHECK(info->getHaveData() == false );
	BOOST_CHECK(info->getDataChunkLength() == 0); // All the data have been consumed

 	mqtt->releaseCache();	
}

BOOST_AUTO_TEST_CASE (test07)
{
	Packet packet("../mqtt/packets/packet10.pcap", 54);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        mqtt->processFlow(flow.get());

        BOOST_CHECK(mqtt->getTotalPackets() == 1);
        BOOST_CHECK(mqtt->getTotalValidPackets() == 0);
        BOOST_CHECK(mqtt->getTotalBytes() == 2);

        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_DISCONNECT));
        BOOST_CHECK(mqtt->getFlags() == 0x00);
        BOOST_CHECK(mqtt->getLength() == 0);
}

BOOST_AUTO_TEST_CASE (test08)
{
	Packet packet("../mqtt/packets/packet11.pcap");

        inject(packet);

        BOOST_CHECK(mqtt->getTotalPackets() == 1);
        BOOST_CHECK(mqtt->getTotalValidPackets() == 1);
        BOOST_CHECK(mqtt->getTotalBytes() == 19);

        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT));
        BOOST_CHECK(mqtt->getFlags() == 0x00);
        BOOST_CHECK(mqtt->getLength() == 17);

        BOOST_CHECK(mqtt->getTotalClientCommands() == 1);
        BOOST_CHECK(mqtt->getTotalServerCommands() == 0);

        Flow *flow = mqtt->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        SharedPointer<MQTTInfo> info = flow->getMQTTInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT));
}

BOOST_AUTO_TEST_CASE (test09)
{
	Packet packet("../mqtt/packets/packet12.pcap", 54);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
       	mqtt->processFlow(flow.get());

        BOOST_CHECK(mqtt->getTotalPackets() == 1);
        BOOST_CHECK(mqtt->getTotalValidPackets() == 0);
        BOOST_CHECK(mqtt->getTotalBytes() == 86);

        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));
        BOOST_CHECK(mqtt->getFlags() == 0x02);
        BOOST_CHECK(mqtt->getLength() == 84);

        BOOST_CHECK(mqtt->getTotalClientCommands() == 1);
        BOOST_CHECK(mqtt->getTotalServerCommands() == 0);

        Flow *cflow = mqtt->getCurrentFlow();
        BOOST_CHECK( cflow != nullptr);
        SharedPointer<MQTTInfo> info = cflow->getMQTTInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));
	BOOST_CHECK( info->topic != nullptr);

	std::string topic("Bus17Cmd");
	BOOST_CHECK( topic.compare(info->topic->getName()) == 0);

	{
		RedirectOutput r;

        	flow->serialize(r.cout);
        	flow->showFlowInfo(r.cout);
        	r.cout << *(info.get());
	}

	JsonFlow j;
	info->serialize(j);

	//TODO some checks
}

BOOST_AUTO_TEST_CASE (test10) // verify the anomaly on a bogus header
{
	Packet packet("../mqtt/packets/packet05.pcap", 54);
	packet.setPayloadLength(packet.getLength() - 258);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
       	mqtt->processFlow(flow.get());

        BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::MQTT_BOGUS_HEADER);

        SharedPointer<MQTTInfo> info = flow->getMQTTInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));
        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));

	BOOST_CHECK(mqtt->getTotalEvents() == 1);
}

BOOST_AUTO_TEST_CASE (test11)
{
	Packet packet("../mqtt/packets/packet07.pcap", 54);

        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());

        flow1->setFlowDirection(FlowDirection::FORWARD);
        flow1->packet = const_cast<Packet*>(&packet);
        flow2->setFlowDirection(FlowDirection::FORWARD);
        flow2->packet = const_cast<Packet*>(&packet);
        mqtt->processFlow(flow1.get());
        mqtt->processFlow(flow2.get());

        SharedPointer<MQTTInfo> info1 = flow1->getMQTTInfo();
        SharedPointer<MQTTInfo> info2 = flow2->getMQTTInfo();
        BOOST_CHECK(info1 != nullptr);
        BOOST_CHECK(info2 != nullptr);
        BOOST_CHECK(info1 != info2);
        BOOST_CHECK(info1->topic == info2->topic);
}

BOOST_AUTO_TEST_CASE (test12) // Memory failure
{
	Packet packet("../mqtt/packets/packet11.pcap");

	mqtt->decreaseAllocatedMemory(10);

	inject(packet);

	Flow *flow = mqtt->getCurrentFlow();
	BOOST_CHECK(flow == nullptr);
	flow = tcp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->getMQTTInfo() == nullptr);
}

BOOST_AUTO_TEST_CASE (test13) // Extra data off a packet
{
	Packet packet("../mqtt/packets/packet07.pcap");
	packet.setPayloadLength(4);

	auto info = SharedPointer<MQTTInfo>(new MQTTInfo());
        auto flow = SharedPointer<Flow>(new Flow());

	info->setHaveData(true);
	info->setDataChunkLength(10);

	flow->layer7info = info;	
        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        mqtt->processFlow(flow.get());

        BOOST_CHECK(info->getDataChunkLength() == 6);
	BOOST_CHECK(info->getHaveData() == true);
}

BOOST_AUTO_TEST_SUITE_END()

