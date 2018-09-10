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
#include "test_ip6.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE ip6test
#endif

#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(ip6_test_suite, StackEthernetIPv6)

BOOST_AUTO_TEST_CASE (test01)
{
	BOOST_CHECK(ip6->getTotalEvents() == 0);
	BOOST_CHECK(ip6->getCurrentUseMemory() == ip6->getTotalAllocatedMemory());
	BOOST_CHECK(ip6->isDynamicAllocatedMemory() == false); // no implementation for dyn

	ip6->processFlow(nullptr); // nothing to process

        BOOST_CHECK(ip6->getTotalFragPackets() == 0); 
        BOOST_CHECK(ip6->getTotalNoHeaderPackets() == 0);
        BOOST_CHECK(ip6->getTotalExtensionHeaderPackets() == 0);
        BOOST_CHECK(ip6->getTotalOtherExtensionHeaderPackets() == 0);

	CounterMap c = ip6->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
        std::string dstip("ff02::1:3");
        std::string srcip("fe80::9c09:b416:768:ff42");

	Packet packet("../ip6/packets/packet01.pcap");

	inject(packet);

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_IPV6);
        BOOST_CHECK(ip6->isIPver6() == true);
	BOOST_CHECK(ip6->getPayloadLength() == 41);
	BOOST_CHECK(srcip.compare(ip6->getSrcAddrDotNotation()) == 0);
	BOOST_CHECK(dstip.compare(ip6->getDstAddrDotNotation()) == 0);
	BOOST_CHECK(ip6->getProtocol() == IPPROTO_UDP);
	BOOST_CHECK(ip6->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
        std::string srcip("2001:470:d37b:1:214:2aff:fe33:747e");
        std::string dstip("2001:470:d37b:2::6");

        Packet packet("../icmp6/packets/packet01.pcap");

	inject(packet);
        
	BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_IPV6);

        BOOST_CHECK(ip6->isIPver6() == true);
	BOOST_CHECK(ip6->getPayloadLength() == 64);
	BOOST_CHECK(srcip.compare(ip6->getSrcAddrDotNotation()) == 0);
	BOOST_CHECK(dstip.compare(ip6->getDstAddrDotNotation()) == 0);
	BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
	BOOST_CHECK(ip6->getTotalEvents() == 0);
        
	BOOST_CHECK(ip6->getTotalFragPackets() == 0); 
        BOOST_CHECK(ip6->getTotalNoHeaderPackets() == 0);
        BOOST_CHECK(ip6->getTotalExtensionHeaderPackets() == 0);
        BOOST_CHECK(ip6->getTotalOtherExtensionHeaderPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test04) // ethernet -> ip
{
        std::string srcip("2002:4637:d5d3::4637:d5d3");
        std::string dstip("2001:4860:0:2001::68");
       
        Packet packet("../http/packets/packet11.pcap");
	 
	inject(packet);
        
	BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_IPV6);

	BOOST_CHECK(ip6->isIPver6() == true);
	
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == packet.getLength());

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip6->getTotalBytes() == packet.getLength() - 14);

        BOOST_CHECK(ip6->isIPver6() == true);
        BOOST_CHECK(ip6->getPayloadLength() == 797 + 20);
        BOOST_CHECK(srcip.compare(ip6->getSrcAddrDotNotation()) == 0);
        BOOST_CHECK(dstip.compare(ip6->getDstAddrDotNotation()) == 0);
        BOOST_CHECK(ip6->getProtocol() == IPPROTO_TCP);

	BOOST_CHECK(ip6->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_CASE (test05) // ethernet -> ip6 -> dsthdropts -> tcp -> http
{
        std::string srcip("2001:db8:1::2");
        std::string dstip("2001:db8:1::1");

        Packet packet("../ip6/packets/packet02.pcap");

	inject(packet);

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_IPV6);

        BOOST_CHECK(ip6->isIPver6() == true);

        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == packet.getLength());

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip6->getTotalBytes() == packet.getLength() - 14);

        BOOST_CHECK(ip6->isIPver6() == true);
        BOOST_CHECK(ip6->getPayloadLength() == 43);
        BOOST_CHECK(srcip.compare(ip6->getSrcAddrDotNotation()) == 0);
        BOOST_CHECK(dstip.compare(ip6->getDstAddrDotNotation()) == 0);
     
	BOOST_CHECK(mux_ip->getNextProtocolIdentifier() == IPPROTO_TCP);
   	BOOST_CHECK(ip6->getProtocol() == IPPROTO_DSTOPTS);
	
	BOOST_CHECK(ip6->getTotalFragPackets() == 0); 
        BOOST_CHECK(ip6->getTotalNoHeaderPackets() == 0);
        BOOST_CHECK(ip6->getTotalExtensionHeaderPackets() == 1);
        BOOST_CHECK(ip6->getTotalOtherExtensionHeaderPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test06) // ethernet -> ip6 -> fragmented  
{
        Packet packet("../ip6/packets/packet05.pcap");

        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        // Sets the raw packet to a valid ethernet header
        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_IPV6);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(ip6->isIPver6() == true);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip6->getTotalBytes() == packet.getLength() - 14);

        BOOST_CHECK(ip6->isIPver6() == true);
        BOOST_CHECK(ip6->getProtocol() == IPPROTO_FRAGMENT);
	BOOST_CHECK(ip6->getTotalEvents() == 1);
	
	BOOST_CHECK(ip6->getTotalFragPackets() == 1); 
        BOOST_CHECK(ip6->getTotalNoHeaderPackets() == 0);
        BOOST_CHECK(ip6->getTotalExtensionHeaderPackets() == 0);
        BOOST_CHECK(ip6->getTotalOtherExtensionHeaderPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test07) // ethernet -> ip6 -> hophop -> dsthdropts -> tcp -> http
{
	Packet packet("../ip6/packets/packet08.pcap");

        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        // Sets the raw packet to a valid ethernet header
        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_IPV6);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(ip6->isIPver6() == true);
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == packet.getLength());

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip6->getTotalBytes() == packet.getLength() - 14);

        BOOST_CHECK(ip6->isIPver6() == true);
        BOOST_CHECK(ip6->getPayloadLength() == 203);

        BOOST_CHECK(mux_ip->getNextProtocolIdentifier() == IPPROTO_TCP);
        BOOST_CHECK(ip6->getProtocol() == IPPROTO_HOPOPTS);
	
	BOOST_CHECK(ip6->getTotalFragPackets() == 0); 
        BOOST_CHECK(ip6->getTotalNoHeaderPackets() == 0);
        BOOST_CHECK(ip6->getTotalExtensionHeaderPackets() == 2);
        BOOST_CHECK(ip6->getTotalOtherExtensionHeaderPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test08) // ipv6 corrupted packet
{
	Packet packet("../ip6/packets/packet01.pcap");
	packet.setPayloadLength(14 + 20);

        inject(packet);

        BOOST_CHECK(ip6->getTotalPackets() == 0);
        BOOST_CHECK(ip6->getTotalValidPackets() == 0);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 0 );
}

BOOST_AUTO_TEST_CASE (test09) // ipv6 no header
{
	Packet packet("../ip6/packets/packet06.pcap");

        inject(packet);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip6->getTotalBytes() == 40 );

	// Event because there is no header
	BOOST_CHECK(ip6->getTotalEvents() == 1);
	
	BOOST_CHECK(ip6->getTotalFragPackets() == 0); 
        BOOST_CHECK(ip6->getTotalNoHeaderPackets() == 1);
        BOOST_CHECK(ip6->getTotalExtensionHeaderPackets() == 0);
        BOOST_CHECK(ip6->getTotalOtherExtensionHeaderPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test10) // ipv6 with scpt protocol
{
	Packet packet("../ip6/packets/packet07.pcap");

        inject(packet);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip6->getTotalBytes() == 40 + 12 );
	BOOST_CHECK(ip6->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_SUITE_END( )
