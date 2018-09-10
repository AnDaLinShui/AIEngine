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
#include "test_frequency.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE frequencytest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(frequencies_test_suite_static, StackFrequencytest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

	BOOST_CHECK(freq->getTotalBytes() == 0);
	BOOST_CHECK(freq->getTotalValidPackets() == 0);
	BOOST_CHECK(freq->getTotalPackets() == 0);
	BOOST_CHECK(freq->getTotalInvalidPackets() == 0);
	BOOST_CHECK(freq->processPacket(packet) == true);
	
	int64_t mem = freq->getCurrentUseMemory();
	BOOST_CHECK(freq->isDynamicAllocatedMemory() == false);	

	CounterMap c = freq->getCounters();

	Frequencies fe;
	JsonFlow j;
	
	fe.serialize(j);
}

BOOST_AUTO_TEST_CASE (test02)
{
        uint8_t ptr1[] = "\x01\x02\x03\x04";
        uint8_t ptr2[] = "\x04\x00\x00\x04";
        uint8_t ptr3[] = "\xff\xfe\xaa\xbb\xde\xff\xff";
        Frequencies freq1;
        Frequencies freq2;
        Frequencies freq3;
        PacketFrequencies p_freq1;
        PacketFrequencies p_freq2;
        PacketFrequencies p_freq3;

	// Check the Frequencies object
        freq1.addPayload(ptr1, 4);
        freq2.addPayload(ptr2, 4);
        BOOST_CHECK(freq1 != freq2);

        freq3.addPayload(ptr1, 4);
        BOOST_CHECK(!(freq1 != freq3));
        BOOST_CHECK(!(freq1 == freq2));
	
	// Check the PacketFrequencies object
        p_freq1.addPayload(ptr1, 4);
        p_freq2.addPayload(ptr2, 4); // Change this value and overflow :)
        BOOST_CHECK(p_freq1 != p_freq2);

        p_freq3.addPayload(ptr1, 4);
        BOOST_CHECK(!(p_freq1 != p_freq3));
        BOOST_CHECK(!(p_freq1 == p_freq2));

	PacketFrequencies pf;
	
	pf.addPayload(ptr3, 7);

	auto v4 = pf.getEntropy();	
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../ssl/packets/packet01.pcap");
	std::string data(reinterpret_cast<const char*>(packet.getPayload()), packet.getLength());
	Frequencies freqs;

	freqs.addPayload(data);
	BOOST_CHECK(freqs[0] == 66);
	
	freqs.addPayload(data);
	BOOST_CHECK(freqs[0] == 66*2);
}

BOOST_AUTO_TEST_CASE (test04)
{
	uint8_t ptr1[] = "\x01\x02\x03\x04";
	uint8_t ptr2[] = "\x04\x00\x00\x04";
        Frequencies freqs;

        freqs.addPayload(ptr1, 4);
        BOOST_CHECK(freqs[1] == 1);
        BOOST_CHECK(freqs[2] == 1);
        BOOST_CHECK(freqs[3] == 1);
        BOOST_CHECK(freqs[4] == 1);

        BOOST_CHECK(freqs.getDispersion() == 4);
        
	freqs.addPayload(ptr2, 4);
        BOOST_CHECK(freqs[1] == 1);
        BOOST_CHECK(freqs[2] == 1);
        BOOST_CHECK(freqs[3] == 1);
        BOOST_CHECK(freqs[4] == 3);
        
	BOOST_CHECK(freqs.getDispersion() == 5);
}

BOOST_AUTO_TEST_CASE (test05)
{
	uint8_t buffer1[] = "\x00\x00\x00\xff\xff";
	uint8_t buffer2[] = "\xaa\xAA\xaa\xBB\xBB\xCC\xFF";
	std::string data(reinterpret_cast<const char*>(buffer1), 5);

        Frequencies freqs;

        freqs.addPayload(data);
        BOOST_CHECK(freqs[0] == 3);
        BOOST_CHECK(freqs[255] == 2);
	BOOST_CHECK(freqs.getDispersion() == 2);
	
        freqs.addPayload(buffer2, 7);
        BOOST_CHECK(freqs[0] == 3);
	BOOST_CHECK(freqs[170] == 3); // 0xAA
	BOOST_CHECK(freqs[187] == 2); // 0xBB
        BOOST_CHECK(freqs[204] == 1); // 0xCC
        BOOST_CHECK(freqs[255] == 3);

	BOOST_CHECK(freqs.getDispersion() == 5);
}

BOOST_AUTO_TEST_CASE (test06)
{
	Packet packet("../ssl/packets/packet01.pcap");
	std::string data(reinterpret_cast<const char*>(packet.getPayload()), packet.getLength());

        Frequencies freqs1,freqs2;

        freqs1.addPayload(data);

	Frequencies freqs3 = freqs1 + freqs2;

        BOOST_CHECK(freqs3[0] == 66);
	
	freqs3 = freqs3 + 10;

	BOOST_CHECK(freqs3[0] == 76);

	Frequencies freqs4;

        freqs4.addPayload(data);

	BOOST_CHECK(freqs4 == freqs1);
	BOOST_CHECK(freqs4 != freqs2);	

	// operations with shared pointers
	auto f1 = SharedPointer<Frequencies>(new Frequencies());
	auto f2 = SharedPointer<Frequencies>(new Frequencies());

	f1->addPayload(data);

	Frequencies *f1_p = f1.get();
	Frequencies *f2_p = f2.get();
	*f1_p = *f1_p + *f2_p;

	BOOST_CHECK((*f1_p)[0] == 66);

	for (int i = 0; i < 10; ++i)
		f1->addPayload(data);
	
	BOOST_CHECK((*f1_p)[0] == 66 * 11);
}

BOOST_AUTO_TEST_CASE (test07)
{
	Packet packet("../ssl/packets/packet01.pcap");
	std::string data(reinterpret_cast<const char*>(packet.getPayload()), packet.getLength());
	Cache<Frequencies>::CachePtr freqs_cache_(new Cache<Frequencies>);

        SharedPointer<Frequencies> freqs = freqs_cache_->acquire();

	BOOST_CHECK(freqs == nullptr);

	freqs_cache_->create(1);
        freqs = freqs_cache_->acquire();
	BOOST_CHECK( freqs != nullptr);
}

BOOST_AUTO_TEST_CASE (test08)
{
	Packet packet("../ssl/packets/packet01.pcap");

	// Create one Frequency object
	freq->createFrequencies(1);

	inject(packet);	

	// Check the results
	BOOST_CHECK(ip->getTotalPackets() == 1);
	BOOST_CHECK(ip->getTotalValidPackets() == 1);
	BOOST_CHECK(ip->getTotalBytes() == 245);
	BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

	// tcp
	BOOST_CHECK(tcp->getTotalPackets() == 1);
	BOOST_CHECK(tcp->getTotalBytes() == 225);
	BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);

	// frequency
	BOOST_CHECK(freq->getTotalBytes() == 193);
	BOOST_CHECK(freq->getTotalValidPackets() == 1);
	BOOST_CHECK(freq->getTotalPackets() == 1);
	BOOST_CHECK(freq->getTotalInvalidPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test09)
{
	Packet packet("../ssl/packets/packet01.pcap");

        // Create one Frequency object
        freq->createFrequencies(1);

	// Inject the packet 100 times.
	for (int i = 0; i < 100; ++i) 
       		inject(packet);

	BOOST_CHECK(freq->getTotalBytes() == 19300);
	BOOST_CHECK(freq->getTotalValidPackets() == 1);
	BOOST_CHECK(freq->getTotalPackets() == 100);
	BOOST_CHECK(freq->getTotalInvalidPackets() == 0);

	FrequencyCounterPtr fcount = FrequencyCounterPtr(new FrequencyCounter());
 
	auto ft = flow_mng->getFlowTable();
	for (auto it = ft.begin(); it!=ft.end();++it) {
	
		SharedPointer<Flow> flow = *it;
		if (flow->frequencies) {
		
			fcount->addFrequencyComponent(flow->frequencies);
		}
	}
	// nothing to compute on this case
	fcount->compute();

	Frequencies *f1_p = fcount->getFrequencyComponent().lock().get();

	BOOST_CHECK((*f1_p)[0] == 56 * 99);
	BOOST_CHECK((*f1_p)[254] == 99);
}

BOOST_AUTO_TEST_CASE (test10)
{
	Packet packet("../ssl/packets/packet01.pcap");

        // Create one Frequency object
        freq->createFrequencies(1);

	inject(packet);

        FrequencyCounterPtr fcount = FrequencyCounterPtr(new FrequencyCounter());

	// There is only one flow on port 443
	int port = 80;

	auto fb = ([&] (const SharedPointer<Flow> &flow) { return (flow->getDestinationPort()== port); });

	fcount->filterFrequencyComponent(flow_mng, 
		([&] (const SharedPointer<Flow> &flow) { return (flow->getDestinationPort()== port); })
	);
        fcount->compute();

        Frequencies *f1_p = fcount->getFrequencyComponent().lock().get();

        BOOST_CHECK((*f1_p)[0] == 0);
        BOOST_CHECK((*f1_p)[254] == 0);

        port = 443;
	fcount->reset();
        fcount->filterFrequencyComponent(flow_mng,
                ([&] (const SharedPointer<Flow>& flow) { return (flow->getDestinationPort()== port); })
        );
        fcount->compute();

        BOOST_CHECK((*f1_p)[0] == 56);
        BOOST_CHECK((*f1_p)[254] == 1);
}

BOOST_AUTO_TEST_CASE (test11)
{
	Packet packet("../ssl/packets/packet01.pcap");

        // Create one Frequency object
        freq->createFrequencies(1);

	inject(packet);        

	FrequencyGroup<uint16_t> group_by_port;

	group_by_port.agregateFlows(flow_mng,
		([] (const SharedPointer<Flow> &flow) { return flow->getDestinationPort();})
	);
	group_by_port.compute();

	BOOST_CHECK(group_by_port.getTotalProcessFlows() == 1);
	BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 1);
}

BOOST_AUTO_TEST_CASE (test12)
{
	Packet packet("../ssl/packets/packet01.pcap");

        // Create one Frequency object
        freq->createFrequencies(1);

	inject(packet);

        FrequencyGroup<char*> group_by_address;

        group_by_address.agregateFlows(flow_mng,
                ([] (const SharedPointer<Flow>& flow) { return (char*)flow->getDstAddrDotNotation();})
        );
        group_by_address.compute();

	BOOST_CHECK(group_by_address.getTotalProcessFlows() == 1);
	BOOST_CHECK(group_by_address.getTotalComputedFrequencies() == 1);
}

BOOST_AUTO_TEST_CASE (test13)
{
	Packet packet("../ssl/packets/packet01.pcap");

        // Create one Frequency object
        freq->createFrequencies(1);

	inject(packet);

        FrequencyGroup<std::string> group_by_destination_port;

        group_by_destination_port.agregateFlowsByDestinationPort(flow_mng);
        group_by_destination_port.compute();

	BOOST_CHECK(group_by_destination_port.getTotalProcessFlows() == 1);
	BOOST_CHECK(group_by_destination_port.getTotalComputedFrequencies() == 1);
	
	std::vector<WeakPointer<Flow>> flow_list;

	flow_list = group_by_destination_port.getReferenceFlowsByKey("443");
	BOOST_CHECK(flow_list.size() == 1);
}

BOOST_AUTO_TEST_CASE (test14)
{
	Packet packet("../ssl/packets/packet01.pcap");

        // Create one Frequency object
        freq->createFrequencies(1);

	inject(packet);

        FrequencyGroup<std::string> group_by_destination_ip_port;

        group_by_destination_ip_port.agregateFlowsByDestinationAddressAndPort(flow_mng);
        group_by_destination_ip_port.compute();

        BOOST_CHECK(group_by_destination_ip_port.getTotalProcessFlows() == 1);
        BOOST_CHECK(group_by_destination_ip_port.getTotalComputedFrequencies() == 1);

	std::vector<WeakPointer<Flow>> flow_list;

	flow_list = group_by_destination_ip_port.getReferenceFlowsByKey("bla bla");
	BOOST_CHECK(flow_list.size() == 0);
}

BOOST_AUTO_TEST_CASE (test15)
{
	char *cadena = "Buenos";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (cadena);
	std::string data(cadena);
	PacketFrequencies pfreq;

	pfreq.addPayload(data);
	BOOST_CHECK(pfreq.getLength() == 6);

	pfreq.addPayload(pkt, 6);
	BOOST_CHECK(pfreq.getLength() == 12);

	char *header = 	"GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
			"Evd4Y34WVkhvAPWJK1%2F7nJlhnAkhXOPT9GCuPlZLgLnIxANviI%2FgtwRfJ9qh9QWwUS2WvW2JAOlS7bvHoIL9JbgA8"
			"VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB"
			"f7%2BndweWllFJWGr54vsfFJAZtBeEEE%2FZMlWJkvTpfDPJZSXmzzKZHbP6mm5u1jYBlJoDAKByHRjSUXRuauvzq1HDj"
			"9QRoPmYJBXJvOlyH%2Fs6mNArj%2F7y0oT1UkApkjaGawH5zJBYkpq9&av=4.4 HTTP/1.1\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent CFNetwork/609 Darwin/13.0.0\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Host: onedomain.com\r\n"
                        "\r\n";
	uint8_t *pkt1 = reinterpret_cast <uint8_t*> (header);
	std::string data1(header);
	pfreq.addPayload(data1);
	BOOST_CHECK(pfreq.getLength() == 619);
	for (int i = 0; i < 7; ++i)
		pfreq.addPayload(data1);

	BOOST_CHECK(pfreq.getLength() == aiengine::MAX_PACKET_FREQUENCIES_VALUES);

	pfreq.addPayload(data1);
	BOOST_CHECK(pfreq.getLength() == aiengine::MAX_PACKET_FREQUENCIES_VALUES);

	PacketFrequencies pfreq_aux;

	pfreq_aux = pfreq + pfreq_aux;

	BOOST_CHECK (pfreq_aux == pfreq);
	pfreq_aux = pfreq_aux / 1;

	BOOST_CHECK (pfreq_aux == pfreq);
	
	pfreq_aux = pfreq_aux + 10;
	BOOST_CHECK(pfreq_aux != pfreq);
}

BOOST_AUTO_TEST_CASE (test16) // exercise the iterator
{
	Packet packet("../ssl/packets/packet01.pcap");

        // Create one Frequency object
        freq->createFrequencies(1);

	inject(packet);

        FrequencyGroup<std::string> group;

        group.agregateFlowsByDestinationAddressAndPort(flow_mng);
        group.compute();

	for (auto it = group.begin(); it != group.end(); ++it)
	{
		std::string cadena("74.125.24.189:443");

		BOOST_CHECK(cadena.compare(it->first) == 0);	
	}
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_FIXTURE_TEST_SUITE(frequencies_test_suite_dynamic, StackFrequencytest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet("../ssl/packets/packet01.pcap");
	Cache<Frequencies>::CachePtr freqs_cache_(new Cache<Frequencies>);

	freqs_cache_->setDynamicAllocatedMemory(true);

        SharedPointer<Frequencies> freqs = freqs_cache_->acquire();

	BOOST_CHECK(freqs != nullptr);

	freqs_cache_->create(1);
        freqs = freqs_cache_->acquire();
	BOOST_CHECK(freqs != nullptr);
}

BOOST_AUTO_TEST_SUITE_END( )
