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
#include "test_http.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE httptest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(http_test_suite_static, StackHTTPtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

	BOOST_CHECK(http->getTotalPackets() == 0);
	BOOST_CHECK(http->getTotalValidPackets() == 0);
	BOOST_CHECK(http->getTotalInvalidPackets() == 0);
	BOOST_CHECK(http->getTotalBytes() == 0);
	BOOST_CHECK(http->processPacket(packet) == true);
	
	HTTPUriSet hset;
	std::string default_name("Generic HTTP Uri Set");
	BOOST_CHECK(default_name.compare(hset.getName()) == 0);

	int val = hset.getFalsePositiveRate();
}

BOOST_AUTO_TEST_CASE (test02)
{
        Packet packet("../http/packets/packet03.pcap");

	inject(packet);

	BOOST_CHECK(ip->getTotalPackets() == 1);
	BOOST_CHECK(ip->getTotalValidPackets() == 1);
	BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
	BOOST_CHECK(ip->getTotalBytes() == 371);

	BOOST_CHECK(mux_ip->getTotalForwardPackets() == 1);
	BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 1);
	BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);

	BOOST_CHECK(tcp->getTotalPackets() == 1);
	BOOST_CHECK(tcp->getTotalValidPackets() == 1);
	BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(tcp->getTotalBytes() == 351);

	BOOST_CHECK(flow_mng->getTotalFlows() == 1);
	BOOST_CHECK(flow_cache->getTotalFlows() == 0);	
	BOOST_CHECK(flow_cache->getTotalAcquires() == 1);	
	BOOST_CHECK(flow_cache->getTotalReleases() == 0);	
	
	BOOST_CHECK(http->getTotalPackets() == 1);
	BOOST_CHECK(http->getTotalValidPackets() == 1);
	BOOST_CHECK(http->getTotalBytes() == 331);

	BOOST_CHECK(http->getTotalGets() == 0); // there is no memory
	BOOST_CHECK(http->getTotalPosts() == 0);
	BOOST_CHECK(http->getTotalHeads() == 0);
	BOOST_CHECK(http->getTotalConnects() == 0);
	BOOST_CHECK(http->getTotalOptions() == 0);
	BOOST_CHECK(http->getTotalPuts() == 0);
	BOOST_CHECK(http->getTotalDeletes() == 0);
	BOOST_CHECK(http->getTotalTraces() == 0);

        std::string cad("GET / HTTP/1.1");
	std::string header((char*)http->getPayload(), 14);

        BOOST_CHECK(cad.compare(header) == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
        Packet packet("../http/packets/packet02.pcap");
        
	http->increaseAllocatedMemory(1);

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip->getTotalBytes() == 2960 );

        BOOST_CHECK(mux_ip->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 1);
        BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp->getTotalBytes() == 2940);

        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFlows() == 0);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);

        BOOST_CHECK(http->getTotalPackets() == 1);
        BOOST_CHECK(http->getTotalValidPackets() == 1);
        BOOST_CHECK(http->getTotalBytes() == 2920);

	BOOST_CHECK(http->getTotalGets() == 0); 
	BOOST_CHECK(http->getTotalPosts() == 1);
	BOOST_CHECK(http->getTotalHeads() == 0);
	BOOST_CHECK(http->getTotalConnects() == 0);
	BOOST_CHECK(http->getTotalOptions() == 0);
	BOOST_CHECK(http->getTotalPuts() == 0);
	BOOST_CHECK(http->getTotalDeletes() == 0);
	BOOST_CHECK(http->getTotalTraces() == 0);

        std::string cad("POST /submit_highscore?n=C%3A%5CUsers%5Cadmin%5CDocuments%5Cprivate%5Caffair%5Choliday%5CEmiratesETicket2.pdf HTTP/1.1");
        std::ostringstream h;

        h << http->getPayload();

	BOOST_CHECK(http->getHTTPMethodSize() == cad.length() + 2);
        BOOST_CHECK(cad.compare(0, 118, h.str()));

        Flow *flow = http->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();

        std::string domain("ninja-game.org");
        BOOST_CHECK(domain.compare(info->host_name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
	char *method =	"GET / HTTP/1.1\r\n";
	char *params =	"Host: www.google.com\r\n"
			"Connection: close\r\n\r\n";
	std::string header(method);
	header.append(params);
        const uint8_t *pkt = reinterpret_cast <const uint8_t*> (header.c_str());
	Packet packet(pkt, header.length());
	
        auto flow = SharedPointer<Flow>(new Flow());

	flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	BOOST_CHECK(flow->layer7info == nullptr);
	BOOST_CHECK(flow->getHTTPInfo() == nullptr);

	// Verify the size of the Header that should be zero because 
	// there is no memory for process the header
	BOOST_CHECK(http->getHTTPHeaderSize() == 0);
	BOOST_CHECK(http->getTotalL7Bytes() == 0);
	BOOST_CHECK(http->getHTTPMethodSize() == 0);
}

BOOST_AUTO_TEST_CASE (test05)
{
        char *method = 	"GET / HTTP/1.1\r\n"; 		// 16 bytes
	char *params =	"Host: www.google.com\r\n"	// 22 bytes 
			"Connection: close\r\n\r\n";    // 21 bytes
	std::string header(method);
	header.append(params);
        const uint8_t *pkt = reinterpret_cast <const uint8_t*> (header.c_str());

        Packet packet(pkt, header.length());
        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(10);

	flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	BOOST_CHECK(http->getTotalGets() == 1); 
	BOOST_CHECK(http->getTotalPosts() == 0);
	BOOST_CHECK(http->getTotalHeads() == 0);
	BOOST_CHECK(http->getTotalConnects() == 0);
	BOOST_CHECK(http->getTotalOptions() == 0);
	BOOST_CHECK(http->getTotalPuts() == 0);
	BOOST_CHECK(http->getTotalDeletes() == 0);
	BOOST_CHECK(http->getTotalTraces() == 0);

	// Verify the size of the Header
	BOOST_CHECK(http->getHTTPHeaderSize() == header.length());
	BOOST_CHECK(http->getHTTPMethodSize() == 16);
	BOOST_CHECK(http->getHTTPParametersSize() == strlen(params));
	BOOST_CHECK(http->getTotalL7Bytes() == 0);

	SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
	BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->uri != nullptr);
        BOOST_CHECK(info->host_name != nullptr);

	std::string cad("www.google.com");
	std::string uri("/");

	// The host is valid
	BOOST_CHECK(cad.compare(info->host_name->getName()) == 0);
	BOOST_CHECK(uri.compare(info->uri->getName()) == 0);
	BOOST_CHECK(info->getTotalRequests()  == 1);
	BOOST_CHECK(info->getTotalResponses()  == 0);
	BOOST_CHECK(info->ua == nullptr);
}

BOOST_AUTO_TEST_CASE (test06)
{
        char *method = 	"GET /someur-oonnnnn-a-/somefile.php HTTP/1.1\r\n";
	char *params =	"Host: www.g00gle.com\r\n"
			"Connection: close\r\n"
			"User-Agent: LuisAgent\r\n\r\n";
	std::string header(method);
	header.append(params);
        const uint8_t *pkt = reinterpret_cast <const uint8_t*> (header.c_str());

        Packet packet(pkt, header.length());
        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	BOOST_CHECK(http->getHTTPHeaderSize() == header.length());
	BOOST_CHECK(http->getHTTPMethodSize() == strlen(method));
	BOOST_CHECK(http->getHTTPParametersSize() == strlen(params));
	BOOST_CHECK(http->getTotalL7Bytes() == 0);
        
	std::string cad_host("www.g00gle.com");
        std::string cad_ua("LuisAgent");

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->ua != nullptr);
        BOOST_CHECK(info->host_name != nullptr);

	BOOST_CHECK(info->getResponseCode() == 0); // There is no response

        // The host is valid
        BOOST_CHECK(cad_host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(info->ua->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test07)
{
        char *method = 	"GET /someur-oonnnnn-a-/somefile.php HTTP/1.0\r\n";
	char *params =	"Host: www.g00gle.com\r\n"
			"Connection: close\r\n"
			"Accept-Encoding: gzip, deflate\r\n"
			"Accept-Language: en-gb\r\n"
			"Accept: */*\r\n"
			"User-Agent: LuisAgent\r\n\r\n";
	char *data =	"bubu";
	std::string header(method);
	header.append(params);
	header.append(data);

        const uint8_t *pkt = reinterpret_cast <const uint8_t*> (header.c_str());
        Packet packet(pkt, header.length());
        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	std::string cad_uri("/someur-oonnnnn-a-/somefile.php");
        std::string cad_host("www.g00gle.com");
        std::string cad_ua("LuisAgent");

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->ua != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->uri != nullptr);

        BOOST_CHECK(cad_uri.compare(info->uri->getName()) == 0);
        BOOST_CHECK(cad_host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(info->ua->getName()) == 0);
	
	// Verify the size of the Header, now contains 4 extra bytes
	BOOST_CHECK(http->getHTTPHeaderSize() == header.length() - strlen(data));
	BOOST_CHECK(http->getHTTPMethodSize() == strlen(method));
	BOOST_CHECK(http->getHTTPParametersSize() == strlen(params));
	BOOST_CHECK(http->getTotalL7Bytes() == strlen(data));
}

BOOST_AUTO_TEST_CASE (test08)
{
        char *method =  "GET /MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFDmvGLQcAh85EJZW%2FcbTWO90hYuZBBROQ8gddu83U3pP8lhvl"
			"PM44tW93wIQac%2FGD3s1X7nqon4RByZFag%3D%3D HTTP/1.1\r\n";
        //char *method =  "GET /MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFDmvGLQcAh85EJZW2FcbTWO90hYuZBBROQ8gddu83U3pP8lhvl"
	//		"PM44tW93wIQac2FGD3s1X7nqon4RByZFag3D3D HTTP/1.1\r\n";
 	char *params =  "Host: www.g00gle.com\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent CFNetwork/609 Darwin/13.0.0\r\n"
                        "Accept-Language: en-gb\r\n"
			"\r\n";
	std::string header(method);
	header.append(params);
        const uint8_t *pkt = reinterpret_cast <const uint8_t*> (header.c_str());

        Packet packet(pkt, header.length());
        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	// Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header.length());
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params));
        BOOST_CHECK(http->getTotalL7Bytes() == 0);

        std::string cad_host("www.g00gle.com");
        std::string cad_ua("LuisAgent CFNetwork/609 Darwin/13.0.0");

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->ua != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->uri != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(info->ua->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test09)
{
	char *method = 	"GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
			"Evd4Y34WVkhvAPWJK1%2F7nJlhnAkhXOPT9GCuPlZLgLnIxANviI%2FgtwRfJ9qh9QWwUS2WvW2JAOlS7bvHoIL9JbgA8"
			"VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB"
			"f7%2BndweWllFJWGr54vsfFJAZtBeEEE%2FZMlWJkvTpfDPJZSXmzzKZHbP6mm5u1jYBlJoDAKByHRjSUXRuauvzq1HDj"
			"9QRoPmYJBXJvOlyH%2Fs6mNArj%2F7y0oT1UkApkjaGawH5zJBYkpq9&av=4.4 HTTP/1.1\r\n";
        char *params =  "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent CFNetwork/609 Darwin/13.0.0\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Host: onedomain.com\r\n"
                        "\r\n";
	std::string header(method);
	header.append(params);
        const uint8_t *pkt = reinterpret_cast <const uint8_t*> (header.c_str());

        Packet packet(pkt, header.length());
        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        // Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header.length());
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params));
        BOOST_CHECK(http->getTotalL7Bytes() == 0);

        std::string cad_host("onedomain.com");
        std::string cad_ua("LuisAgent CFNetwork/609 Darwin/13.0.0");

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->ua != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->uri != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(info->ua->getName()) == 0);

	BOOST_CHECK(http->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_CASE (test10)
{
        char *method1 =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
                        "Evd4Y34WVkhvAPWJK1%2F7nJlhnAkhXOPT9GCuPlZLgLnIxANviI%2FgtwRfJ9qh9QWwUS2WvW2JAOlS7bvHoIL9JbgA8"
                        "VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB"
                        "f7%2BndweWllFJWGr54vsfFJAZtBeEEE%2FZMlWJkvTpfDPJZSXmzzKZHbP6mm5u1jYBlJoDAKByHRjSUXRuauvzq1HDj"
                        "9QRoPmYJBXJvOlyH%2Fs6mNArj%2F7y0oT1UkApkjaGawH5zJBYkpq9&av=4.4 HTTP/1.1\r\n";
        char *params1 = "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent CFNetwork/609 Darwin/13.0.0\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Host: onedomain.com\r\n"
                        "\r\n";

	std::string header1(method1);
        header1.append(params1);
        const uint8_t *pkt1 = reinterpret_cast <const uint8_t*> (header1.c_str());
        Packet packet1(pkt1, header1.length());
        auto flow1 = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(2);

        flow1->packet = const_cast<Packet*>(&packet1);
        http->processFlow(flow1.get());

        // Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header1.length());
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method1));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params1));
        BOOST_CHECK(http->getTotalL7Bytes() == 0);

        std::string cad_host("onedomain.com");
        std::string cad_ua("LuisAgent CFNetwork/609 Darwin/13.0.0");

        SharedPointer<HTTPInfo> info1 = flow1->getHTTPInfo();
        BOOST_CHECK(info1 != nullptr);

        BOOST_CHECK(info1->ua != nullptr);
        BOOST_CHECK(info1->host_name != nullptr);
        BOOST_CHECK(info1->uri != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(info1->host_name->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(info1->ua->getName()) == 0);

        char *method2 = "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
                        "Evd4Y34WVkhvAPWJK1%2F7nJlhnAkhXOPT9GCuPlZLgLnIxANviI%2FgtwRfJ9qh9QWwUS2WvW2JAOlS7bvHoIL9JbgA8"
                        "9QRoPmYJBXJvOlyH%2Fs6mNArj%2F7y0oT1UkApkjaGawH5zJBYkpq9&av=4.4 HTTP/1.1\r\n";
        char *params2 = "Connection: close\r\n"
                        "User-Agent: LuisAgent CFNetwork/609 Darwin/13.0.0\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept: */*\r\n"
                        "Host: otherdomain.com\r\n"
                        "Accept-Language: en-gb\r\n"
                        "\r\n";
	std::string header2(method2);
        header2.append(params2);
        const uint8_t *pkt2 = reinterpret_cast <const uint8_t*> (header2.c_str());
        Packet packet2(pkt2, header2.length());
        auto flow2 = SharedPointer<Flow>(new Flow());

        flow2->packet = const_cast<Packet*>(&packet2);
        http->processFlow(flow2.get());
         
        // Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header2.length());
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method2));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params2));
        BOOST_CHECK(http->getTotalL7Bytes() == 0);

        SharedPointer<HTTPInfo> info2 = flow2->getHTTPInfo();
        BOOST_CHECK(info2 != nullptr);

        BOOST_CHECK(info2->ua != nullptr);
        BOOST_CHECK(info2->host_name != nullptr);
        BOOST_CHECK(info2->uri != nullptr);

	BOOST_CHECK(info2->getTotalRequests()  == 1);
        BOOST_CHECK(info2->getTotalResponses()  == 0);

	BOOST_CHECK(info1->ua == info2->ua);
}

BOOST_AUTO_TEST_CASE (test11)
{
        char *method1 = "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
                        "Evd4Y34WVkhvAPWJK1%2F7nJlhnAkhXOPT9GCuPlZLgLnIxANviI%2FgtwRfJ9qh9QWwUS2WvW2JAOlS7bvHoIL9JbgA8"
                        "VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB"
                        "f7%2BndweWllFJWGr54vsfFJAZtBeEEE%2FZMlWJkvTpfDPJZSXmzzKZHbP6mm5u1jYBlJoDAKByHRjSUXRuauvzq1HDj"
                        "9QRoPmYJBXJvOlyH%2Fs6mNArj%2F7y0oT1UkApkjaGawH5zJBYkpq9&av=4.4 HTTP/1.1\r\n";
        char *params1 = "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent CFNetwork/609 Darwin/13.0.0\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Host: onedomain.com\r\n"
                        "\r\n";
        std::string header1(method1);
        header1.append(params1);
        const uint8_t *pkt1 = reinterpret_cast <const uint8_t*> (header1.c_str());
        Packet packet1(pkt1, header1.length());
        auto flow1 = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(2);

        flow1->packet = const_cast<Packet*>(&packet1);
        http->processFlow(flow1.get());

        // Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header1.length());
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method1));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params1));
        BOOST_CHECK(http->getTotalL7Bytes() == 0);

        std::string cad_host("onedomain.com");
        std::string cad_ua("LuisAgent CFNetwork/609 Darwin/13.0.0");

        SharedPointer<HTTPInfo> info1 = flow1->getHTTPInfo();
        BOOST_CHECK(info1 != nullptr);

        BOOST_CHECK(info1->ua != nullptr);
        BOOST_CHECK(info1->host_name != nullptr);
        BOOST_CHECK(info1->uri != nullptr);

        BOOST_CHECK(info1->ua != nullptr);
        BOOST_CHECK(info1->host_name != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(info1->host_name->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(info1->ua->getName()) == 0);

        char *method2 = "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
                        "Evd4Y34WVkhvAPWJK1%2F7nJlhnAkhXOPT9GCuPlZLgLnIxANviI%2FgtwRfJ9qh9QWwUS2WvW2JAOlS7bvHoIL9JbgA8"
                        "9QRoPmYJBXJvOlyH%2Fs6mNArj%2F7y0oT1UkApkjaGawH5zJBYkpq9&av=4.4 HTTP/1.1\r\n";
        char *params2 = "Connection: close\r\n"
                        "User-Agent: LuisAgent CFNetwork/609 Darwin/13.2.0\r\n"
                        "Accept: */*\r\n"
                        "Host: onedomain.com\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept-Language: en-gb\r\n"
                        "\r\n";
	char *data2 =	"XXXX";
        std::string header2(method2);
        header2.append(params2);
        header2.append(data2);
        const uint8_t *pkt2 = reinterpret_cast <const uint8_t*> (header2.c_str());
        Packet packet2(pkt2, header2.length());
        auto flow2 = SharedPointer<Flow>(new Flow());

        flow2->packet = const_cast<Packet*>(&packet2);
        http->processFlow(flow2.get());

        // Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header2.length() - strlen(data2));
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method2));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params2));
        BOOST_CHECK(http->getTotalL7Bytes() == strlen(data2));

        std::string cad_ua2("LuisAgent CFNetwork/609 Darwin/13.2.0");

        SharedPointer<HTTPInfo> info2 = flow2->getHTTPInfo();
        BOOST_CHECK(info2 != nullptr);

        BOOST_CHECK(info2->ua != nullptr);
        BOOST_CHECK(info2->host_name != nullptr);
        BOOST_CHECK(info2->uri != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(info2->host_name->getName()) == 0);
        BOOST_CHECK(cad_ua2.compare(info2->ua->getName()) == 0);

	BOOST_CHECK(info1->host_name == info2->host_name);
	BOOST_CHECK(http->getTotalEvents() == 0);
}

// Test the HTTPProtocol with the DomainNameManager attached
BOOST_AUTO_TEST_CASE (test12)
{
        char *header =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
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
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);

	auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
	auto host_name = SharedPointer<DomainName>(new DomainName("example", ".bu.ba.com"));

        Packet packet(pkt,length);
        auto flow = SharedPointer<Flow>(new Flow());

	http->setDomainNameManager(host_mng);
	host_mng->addDomainName(host_name);

	// Dont create any items on the cache
        http->increaseAllocatedMemory(0);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();

        // Size of the header equals 0 
        BOOST_CHECK(http->getHTTPHeaderSize() == 0);
        BOOST_CHECK(info == nullptr);
	BOOST_CHECK(host_name->getMatchs() == 0);
	BOOST_CHECK(http->getTotalEvents() == 0);
}

// Test the HTTPProtocol with the DomainNameManager attached
BOOST_AUTO_TEST_CASE (test13)
{
        char *header =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
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
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);

        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("example", ".bu.ba.com"));

        Packet packet(pkt,length);
        auto flow = SharedPointer<Flow>(new Flow());

        http->setDomainNameManager(host_mng);
        host_mng->addDomainName(host_name);

        // Dont create any items on the cache
        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        // Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header));

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(host_name->getMatchs() == 0);
}

// Test the HTTPProtocol with the DomainNameManager attached
BOOST_AUTO_TEST_CASE (test14)
{
        char *header =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
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
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);

        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("example", "onedomain.com"));

        Packet packet(pkt,length);
        auto flow = SharedPointer<Flow>(new Flow());

        http->setDomainNameManager(host_mng);
        host_mng->addDomainName(host_name);

        // Dont create any items on the cache
        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(info->isBanned() == false);
	BOOST_CHECK(info->uri != nullptr);
	BOOST_CHECK(info->host_name != nullptr);
	BOOST_CHECK(info->ua != nullptr);

	BOOST_CHECK(http->getTotalEvents() == 1);
        BOOST_CHECK(host_name->getMatchs() == 1);
}

BOOST_AUTO_TEST_CASE (test15)
{
        char *header =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
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
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);

        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("example", "onedomain.com"));

        Packet packet(pkt,length);
        auto flow = SharedPointer<Flow>(new Flow());

	http->increaseAllocatedMemory(1);

        http->setDomainNameBanManager(host_mng);
        host_mng->addDomainName(host_name);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        // Verify the size of the Header response
        BOOST_CHECK(http->getHTTPHeaderSize() == length);
	BOOST_CHECK(http->getTotalL7Bytes() == 0);

	BOOST_CHECK(http->getTotalAllowHosts() == 0);
	BOOST_CHECK(http->getTotalBanHosts() == 1);

	// Verify that the flow dont have references in order to save memory
	SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(info->uri == nullptr);
	BOOST_CHECK(info->ua == nullptr);
	BOOST_CHECK(info->host_name == nullptr);
}

// Test the URI functionality
BOOST_AUTO_TEST_CASE (test16)
{
        char *method1 = "GET /someur-oonnnnn-a-/somefile.php HTTP/1.0\r\n";
        char *params1 = "Host: www.bu.com\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent\r\n\r\n";

        char *method2 =	"HTTP/1.1 200 OK\r\n";
        char *params2 = "Server: Pepe\r\n"
                        "Date: Fri, 07 Nov 2015 11:18:45 GMT\r\n"
                        "Content-Type: text/plain;charset=UTF-8\r\n"
                        "Content-Length: 4\r\n"
                        "Connection: keep-alive\r\n"
                        "Accept-Charset: utf-8\r\n"
                        "\r\n";
	char *data2 =	"BUBU";

        char *method3 = "GET /VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB/oonnnnn-a-/otherfile.html HTTP/1.0\r\n";
        char *params3 = "Host: www.bu.com\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent\r\n\r\n"; 

        std::string header1(method1);
        header1.append(params1);
        const uint8_t *pkt1 = reinterpret_cast <const uint8_t*> (header1.c_str());
        Packet packet1(pkt1, header1.length());

        std::string header2(method2);
        header2.append(params2);
        header2.append(data2);
        const uint8_t *pkt2 = reinterpret_cast <const uint8_t*> (header2.c_str());
        Packet packet2(pkt2, header2.length());
	
        std::string header3(method3);
        header3.append(params3);
        const uint8_t *pkt3 = reinterpret_cast <const uint8_t*> (header3.c_str());
        Packet packet3(pkt3, header3.length());

        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

	flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet1);
        http->processFlow(flow.get());

        // Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header1.length());
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method1));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params1));
        BOOST_CHECK(http->getTotalL7Bytes() == 0);

        std::string cad_uri1("/someur-oonnnnn-a-/somefile.php");
        std::string cad_uri2("/VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB/oonnnnn-a-/otherfile.html");

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);
 
        BOOST_CHECK(info->uri != nullptr);
        BOOST_CHECK(cad_uri1.compare(info->uri->getName()) == 0);

	// Inject the response
	flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet2);
        http->processFlow(flow.get());

        // Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header2.length() - strlen(data2));
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method2));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params2));
        BOOST_CHECK(http->getTotalL7Bytes() == strlen(data2));

	// Verify the response
	std::string ct("text/plain");
	BOOST_CHECK(info->ct != nullptr);
        BOOST_CHECK(ct.compare(info->ct->getName()) == 0);

	// Inject the next header
	flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet3);
        http->processFlow(flow.get());

        // Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header3.length());
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method3));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params3));
        BOOST_CHECK(http->getTotalL7Bytes() == strlen(data2)); // is an acumulative

	// There is no uris on the cache so the flow keeps the last uri seen
        BOOST_CHECK(cad_uri1.compare(info->uri->getName()) == 0);
	
	BOOST_CHECK(http->getTotalGets() == 2); 
	BOOST_CHECK(http->getTotalPosts() == 0);
	BOOST_CHECK(http->getTotalHeads() == 0);
	BOOST_CHECK(http->getTotalConnects() == 0);
	BOOST_CHECK(http->getTotalOptions() == 0);
	BOOST_CHECK(http->getTotalPuts() == 0);
	BOOST_CHECK(http->getTotalDeletes() == 0);
	BOOST_CHECK(http->getTotalTraces() == 0);
}

BOOST_AUTO_TEST_CASE (test17)
{
	char *method = 	"HTTP/1.1 200 OK\r\n";
        char *params =	"Server: Cengine\r\n"
			"Date: Fri, 07 Nov 2013 11:18:45 GMT\r\n"
			"Content-Type: text/plain;charset=UTF-8\r\n"
			"Content-Length: 125\r\n"
			"Connection: keep-alive\r\n"
			"Accept-Charset: utf-8\r\n"
			"Access-Control-Allow-Credentials: true\r\n"
			"\r\n";
	char *data = 	"var cb_c847hj = {\"data\":{\"qidan_home\":[],\"dingyue\":[],\"data\":[],\"qidan_cnt\":0,\"watchlater\":[],\"playlist\":[]},\"code\":\"A00000\"}";

        std::string header(method);
        header.append(params);
        header.append(data);
        const uint8_t *pkt = reinterpret_cast <const uint8_t*> (header.c_str());
        Packet packet(pkt, header.length());
	
        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);
	
	flow->setFlowDirection(FlowDirection::BACKWARD);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        // Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header.length() - strlen(data));
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params));
        BOOST_CHECK(http->getTotalL7Bytes() == strlen(data));

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(info->getResponseCode() == 200);
	BOOST_CHECK(info->getContentLength() == 125);
        BOOST_CHECK(info->getTotalRequests()  == 0);
        BOOST_CHECK(info->getTotalResponses()  == 1);
}

BOOST_AUTO_TEST_CASE (test18) 
{
        char *header =  "GET /VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB/oonnnnn-a-/otherfile.html HTTP/1.0\r\n"
                        "Connection: close\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Accept: */*\r\n"
			"Cookie: PREF=ID=765870cb5ff303a3:TM=1209230140:LM=1209255358:GM=1:S=tFGcUUKdZTTlFhg8; "
				"rememberme=true; SID=DQAAAHcAAADymnf27WSdmq8VK7DtQkDCYwpT6yEH1c8p6crrirTO3HsXN"
				"2N_pOcW-T82lcNyvlUHgXiVPsZYrH6TnjQrgCEOLjUSOCrlLFh5I0BdGjioxzmksgWrrfeMV-y7bx1"
				"T1LPCMDOW0Wkw0XFqWOpMlkBCHsdt2Vcsha0j20VpIaw6yg; NID=10=jMYWNkozslA4UaRu8zyFSL"
				"Ens8iWVz4GdkeefkqVm5dFS0F0ztc8hDlNJRllb_WeYe9Wx6a8Yo7MnrFzqwZczgXV5e-RFbCrrJ9dfU5gs79L_v3BSdueIg_OOfjpScSh\r\n"
                        "User-Agent: LuisAgent\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Host: www.bu.com\r\n\r\n";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt,length);
        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	// Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header));
	BOOST_CHECK(http->getTotalL7Bytes() == 0);

        std::string host("www.bu.com");
        std::string ua("LuisAgent");

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->ua != nullptr);
        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(ua.compare(info->ua->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test19) 
{
        char *header1 =  "GET /someur-oonnnnn-a-/somefile.php HTTP/1.0\r\n"
                        "Host: www.bu.com\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent\r\n\r\n";

        char *header2 =  "GET /VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB/oonnnnn-a-/otherfile.html HTTP/1.0\r\n"
                        "Host: www.bu.com\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent\r\n\r\n";

        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (header1);
        int length1 = strlen(header1);
        Packet packet1(pkt1,length1);
        uint8_t *pkt2 = reinterpret_cast <uint8_t*> (header2);
        int length2 = strlen(header2);
        Packet packet2(pkt2,length2);
        auto flow = SharedPointer<Flow>(new Flow());

        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("Banned domain", "bu.com"));

        http->increaseAllocatedMemory(1);

        http->setDomainNameBanManager(host_mng);
        host_mng->addDomainName(host_name);

        http->increaseAllocatedMemory(2);

        flow->packet = const_cast<Packet*>(&packet1);
        http->processFlow(flow.get());

        flow->packet = const_cast<Packet*>(&packet2);
        http->processFlow(flow.get());

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(host_name->getMatchs() == 1);
	BOOST_CHECK(info->isBanned() == true);
        BOOST_CHECK(info->host_name == nullptr);
        BOOST_CHECK(info->uri == nullptr);
        BOOST_CHECK(info->ua == nullptr);

	CounterMap c = http->getCounters();
}

BOOST_AUTO_TEST_CASE (test20) 
{
	char *method =	"POST /open/1 HTTP/1.1\r\n";
	char *params =	"Content-Type: application/x-fcs\r\n"
			"User-Agent: Shockwave Flash\r\n"
			"Host: 86.19.100.102\r\n"
			"Content-Length: 1\r\n"
			"Connection: Keep-Alive\r\n"
			"Cache-Control: no-cache\r\n"
			"\r\n";
	char *data =	".";

       	std::string header(method);
        header.append(params);
        header.append(data);
        const uint8_t *pkt = reinterpret_cast <const uint8_t*> (header.c_str());
        Packet packet(pkt, header.length());

        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        // Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header.length() - strlen(data));
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params));
        BOOST_CHECK(http->getTotalL7Bytes() == strlen(data));

        std::string host("86.19.100.102");
        std::string ua("Shockwave Flash");
	std::string uri("/open/1");
	std::string ct("application/x-fcs");

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->ua != nullptr);
        BOOST_CHECK(info->ct != nullptr);
        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(ua.compare(info->ua->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);
        BOOST_CHECK(ct.compare(info->ct->getName()) == 0);

	BOOST_CHECK(info->getContentLength() == 1);
}

BOOST_AUTO_TEST_CASE (test21) 
{
	char *header =	"HTTP/1.1 200 OK\r\n"
			"Cache-Control: no-cache\r\n"
			"Connection: Keep-Alive\r\n"
			"Content-Length: 17\r\n"
			"Server: FlashCom/3.5.7\r\n"
			"Content-Type: application/x-fcs\r\n"
			"\r\n"
			"Cuomdz02wSLGeYbI.";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);
        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        // Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == length - 17);
	BOOST_CHECK(http->getTotalL7Bytes() == 17);

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(info->getResponseCode() == 200);
        BOOST_CHECK(info->host_name == nullptr);
        BOOST_CHECK(info->ua == nullptr);
        BOOST_CHECK(info->uri == nullptr);

        BOOST_CHECK(info->getContentLength() == 17);
}

BOOST_AUTO_TEST_CASE (test22)
{
        char *method1 = "POST /open/1 HTTP/1.1\r\n";
        char *params1 = "Content-Type: application/x-fcs\r\n"
                        "User-Agent: Shockwave Flash\r\n"
                        "Host: 86.19.100.102\r\n"
                        "Content-Length: 1\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Cache-Control: no-cache\r\n"
                        "\r\n";
        char *data1 =   ".";

        std::string header1(method1);
        header1.append(params1);
        header1.append(data1);
        const uint8_t *pkt1 = reinterpret_cast <const uint8_t*> (header1.c_str());
        Packet packet1(pkt1, header1.length());

        char *method2 = "HTTP/1.1 200 OK\r\n";
        char *params2 = "Cache-Control: no-cache\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Content-Length: 17\r\n"
                        "Server: FlashCom/3.5.7\r\n"
                        "Content-Type: application/x-fcs\r\n"
                        "\r\n";
        char *data2 =   "Cuomdz02wSLGeYbI.";

        std::string header2(method2);
        header2.append(params2);
        header2.append(data2);
        const uint8_t *pkt2 = reinterpret_cast <const uint8_t*> (header2.c_str());
        Packet packet2(pkt2, header2.length());

        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet1);
	flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

        // Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header1.length() - strlen(data1));
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method1));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params1));
        BOOST_CHECK(http->getTotalL7Bytes() == strlen(data1));

	// Some checks
        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

	// Should be true because the data is a dot!!
	BOOST_CHECK(info->getHaveData() == true);

	BOOST_CHECK(http->getTotalL7Bytes() == 1);

	flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet2);
        http->processFlow(flow.get());
        
        // Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header2.length() - strlen(data2));
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method2));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params2));
        BOOST_CHECK(http->getTotalL7Bytes() == strlen(data1) + strlen(data2));

        std::string host("86.19.100.102");
        std::string ua("Shockwave Flash");
        std::string uri("/open/1");
	std::string ct("application/x-fcs");

        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->ua != nullptr);
        BOOST_CHECK(info->uri != nullptr);
        BOOST_CHECK(info->ct != nullptr);
        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(ua.compare(info->ua->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);
        BOOST_CHECK(ct.compare(info->ct->getName()) == 0);

        BOOST_CHECK(info->getContentLength() == 17);
}

BOOST_AUTO_TEST_CASE (test23)
{
        char *header1 = "GET /open/file.xml HTTP/1.1\r\n"
                        "User-Agent: Shockwave Flash\r\n"
                        "Host: 86.19.100.102\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Cache-Control: no-cache\r\n"
                        "\r\n";

        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (header1);
        int length1 = strlen(header1);
        Packet packet1(pkt1, length1);

        char *header2 = "HTTP/1.1 200 OK\r\n"
                        "Cache-Control: no-cache\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Content-Length: 37\r\n"
                        "Server: FlashCom/3.5.7\r\n"
                        "Content-Type: application/x-fcs\r\n"
                        "\r\n"
                        "Cuomdz02wSLGeYbI.";

	char *data1 = "AAAAAAAAAAAAAAAAAAAA";
        uint8_t *data_pkt = reinterpret_cast <uint8_t*> (data1);

        uint8_t *pkt2 = reinterpret_cast <uint8_t*> (header2);
        int length2 = strlen(header2);
        Packet packet2(pkt2, length2);
	Packet packet3(data_pkt, strlen(data1));

        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

	// Process First packet request
        flow->packet = const_cast<Packet*>(&packet1);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        // Should be false because the data is still on the packet
        BOOST_CHECK(info->getHaveData() == false);
        BOOST_CHECK(http->getTotalL7Bytes() == 0);

	// Process second packet response with data
        flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet2);
        http->processFlow(flow.get());

        BOOST_CHECK(http->getTotalL7Bytes() == 17);
        // Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header2) - 17);

	// Process the last packet with data
        flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet3);
        http->processFlow(flow.get());

	// Verify the counters

        BOOST_CHECK(http->getTotalL7Bytes() == 37);
	// No header size
	BOOST_CHECK(info->getResponseCode() == 200);
        BOOST_CHECK(http->getHTTPHeaderSize() == 0);
	BOOST_CHECK(info->getHaveData() == false);
	BOOST_CHECK(info->getDataChunkLength() == 0);
}

BOOST_AUTO_TEST_CASE (test24)
{
        char *header1 =  "POST /open/1 HTTP/1.1\r\n"
                        "Content-Type: application/x-fcs\r\n"
                        "User-Agent: Shockwave Flash\r\n"
                        "Host: 86.19.100.102\r\n"
                        "Content-Length: 290\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Cache-Control: no-cache\r\n"
                        "\r\n"
			"AAAAAAAAAAAAAAAAAAAA"
			"AAAAAAAAAAAAAAAAAAAA"
			"AAAAAAAAAAAAAAAAAAAA"
			"AAAAAAAAAAAAAAAAAAAA"
			"AAAAAAAAAAAAAAAAAAAA";

	char *data1 = 	"AAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAA"
			"AAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAA";

        uint8_t *data_pkt = reinterpret_cast <uint8_t*> (data1);

        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (header1);
        int length1 = strlen(header1);
        Packet packet1(pkt1,length1);

        char *header2 =  "HTTP/1.1 200 OK\r\n"
                        "Cache-Control: no-cache\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Server: FlashCom/3.5.7\r\n"
                        "\r\n";

        uint8_t *pkt2 = reinterpret_cast <uint8_t*> (header2);
        int length2 = strlen(header2);
        Packet packet2(data_pkt,190);
        Packet packet3(pkt2,length2);

        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet1);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);
	
	// Verify values of the first packet
        BOOST_CHECK(http->getTotalL7Bytes() == 100);
        // No header size
        BOOST_CHECK(info->getHaveData() == true);
        BOOST_CHECK(info->getDataChunkLength() == 190);

	// Insert the second packet that is the payload
        flow->packet = const_cast<Packet*>(&packet2);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

        // Verify values of the  packet
        BOOST_CHECK(http->getTotalL7Bytes() == 290);
        // No header size
        BOOST_CHECK(info->getHaveData() == false);
        BOOST_CHECK(info->getDataChunkLength() == 0);
	BOOST_CHECK(http->getHTTPHeaderSize() == 0);

	// Insert the response
        flow->packet = const_cast<Packet*>(&packet3);
        flow->setFlowDirection(FlowDirection::BACKWARD);
        http->processFlow(flow.get());

        BOOST_CHECK(info->getHaveData() == false);
        BOOST_CHECK(http->getTotalL7Bytes() == 290);
	BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header2));
}

// Test the functionality of the HTTPUriSets attached to a DomainName
BOOST_AUTO_TEST_CASE (test25)
{
        char *header1 =  "GET /someur-oonnnnn-a-/somefile.php HTTP/1.0\r\n"
                        "Host: www.bu.com\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent\r\n\r\n";

        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (header1);
        int length1 = strlen(header1);
        Packet packet1(pkt1,length1);
        auto flow = SharedPointer<Flow>(new Flow());

        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("One domain", "bu.com"));
	auto uset = SharedPointer<HTTPUriSet>(new HTTPUriSet());

        http->increaseAllocatedMemory(1);

	uset->addURI("/someur-oonnnnn-a-/somefile.php");

	// Attach the HTTPUriSet to the DomainName
	host_name->setHTTPUriSet(uset);

        http->setDomainNameManager(host_mng);
        host_mng->addDomainName(host_name);

	// Before the execution
	BOOST_CHECK(uset->getTotalURIs() == 1);
	BOOST_CHECK(uset->getTotalLookups() == 0);
	BOOST_CHECK(uset->getTotalLookupsIn() == 0);
	BOOST_CHECK(uset->getTotalLookupsOut() == 0);

        flow->packet = const_cast<Packet*>(&packet1);
        http->processFlow(flow.get());

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(host_name->getMatchs() == 1);
        BOOST_CHECK(info->isBanned() == false);

        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->uri != nullptr);
        BOOST_CHECK(info->ua != nullptr);
	
	BOOST_CHECK(uset->getTotalURIs() == 1);
	BOOST_CHECK(uset->getTotalLookups() == 1);
	BOOST_CHECK(uset->getTotalLookupsIn() == 1);
	BOOST_CHECK(uset->getTotalLookupsOut() == 0);

	BOOST_CHECK(http->getTotalEvents() == 2);

	BOOST_CHECK(info->getWriteUri() == true);

	JsonFlow j;
        info->serialize(j);

	BOOST_CHECK(info->getWriteUri() == false);
}

// Another test for the functionality of the HTTPUriSets attached to a DomainNameManager
BOOST_AUTO_TEST_CASE (test26)
{
        char *header1 =  "GET /someur-oonnnnn-a-/somefile.php HTTP/1.0\r\n"
                        "Host: www.bu.com\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent\r\n\r\n";

        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (header1);
        int length1 = strlen(header1);
        Packet packet1(pkt1,length1);
        auto flow = SharedPointer<Flow>(new Flow());

        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("One domain", "bu.com"));
        auto uset = SharedPointer<HTTPUriSet>(new HTTPUriSet());

        http->increaseAllocatedMemory(1);

        uset->addURI("/someur-oonnnnn-a-/somefile.html");
        uset->addURI("/index.html");
        uset->addURI("/oonnnnn-a-/somefile.html");

        // Attach the HTTPUriSet to the DomainName
        host_name->setHTTPUriSet(uset);

        http->setDomainNameManager(host_mng);
        host_mng->addDomainName(host_name);

        // Before the execution
        BOOST_CHECK(uset->getTotalURIs() == 3);
        BOOST_CHECK(uset->getTotalLookups() == 0);
        BOOST_CHECK(uset->getTotalLookupsIn() == 0);
        BOOST_CHECK(uset->getTotalLookupsOut() == 0);

        flow->packet = const_cast<Packet*>(&packet1);
        http->processFlow(flow.get());

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(host_name->getMatchs() == 1);
        BOOST_CHECK(info->isBanned() == false);

        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->uri != nullptr);
        BOOST_CHECK(info->ua != nullptr);

        BOOST_CHECK(uset->getTotalURIs() == 3);
        BOOST_CHECK(uset->getTotalLookups() == 1);
        BOOST_CHECK(uset->getTotalLookupsIn() == 0);
        BOOST_CHECK(uset->getTotalLookupsOut() == 1);

	BOOST_CHECK(http->getTotalEvents() == 1);
}

// Verify the regex on the payload of http
BOOST_AUTO_TEST_CASE (test27)
{
        char *request = "POST /open/1 HTTP/1.1\r\n"
                        "Content-Type: application/x-fcs\r\n"
                        "User-Agent: Shockwave Flash\r\n"
                        "Host: somedomain.com\r\n"
                        "Content-Length: 290\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Cache-Control: no-cache\r\n"
                        "\r\n"
                        "BEEFAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA";

        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (request);
        int length1 = strlen(request);
        Packet packet1(pkt1,length1);

	auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("One domain", ".somedomain.com"));

	auto rmng = SharedPointer<RegexManager>(new RegexManager());
	auto re = SharedPointer<Regex>(new Regex("payload regex", "^BEEFAAAA.*$"));
        auto flow = SharedPointer<Flow>(new Flow());

	http->setDomainNameManager(host_mng);

	host_mng->addDomainName(host_name);
	host_name->setRegexManager(rmng);

	rmng->addRegex(re);
	
        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet1);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

	BOOST_CHECK(host_name->getMatchs() == 1);
	BOOST_CHECK(host_name->getTotalEvaluates() == 0);
	BOOST_CHECK(re->getMatchs() == 1);
	BOOST_CHECK(re->getTotalEvaluates() == 1);
}

// Verify the regex on the payload of http by using linked regexs
BOOST_AUTO_TEST_CASE (test28)
{
        char *request = "POST /open/1 HTTP/1.1\r\n"
                        "Content-Type: application/x-fcs\r\n"
                        "User-Agent: Shockwave Flash\r\n"
                        "Host: somedomain.com\r\n"
                        "Content-Length: 300\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Cache-Control: no-cache\r\n"
                        "\r\n"
                        "BEEFAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA";

        char *pdu1 =    "HELLAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA";

        char *pdu2 =    "BYEBYEAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA";

        Packet packet1(reinterpret_cast <uint8_t*> (request), strlen(request));
        Packet packet2(reinterpret_cast <uint8_t*> (pdu1), strlen(pdu1));
        Packet packet3(reinterpret_cast <uint8_t*> (pdu2), strlen(pdu2));

        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("One domain", ".somedomain.com"));

        auto rmng = SharedPointer<RegexManager>(new RegexManager());
        auto re1 = SharedPointer<Regex>(new Regex("payload regex", "^BEEFAAAA.*$"));
        auto re2 = SharedPointer<Regex>(new Regex("payload regex", "^HELLAAAA.*$"));
        auto re3 = SharedPointer<Regex>(new Regex("payload regex", "^BYEBYEAA.*$"));
        auto flow = SharedPointer<Flow>(new Flow());

	re1->setNextRegex(re2);
	re2->setNextRegex(re3);

        http->setDomainNameManager(host_mng);

        host_mng->addDomainName(host_name);
        host_name->setRegexManager(rmng);

        rmng->addRegex(re1);

        http->increaseAllocatedMemory(1);

	// Inject the first request
        flow->packet = const_cast<Packet*>(&packet1);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());
        
	flow->packet = const_cast<Packet*>(&packet2);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

	flow->packet = const_cast<Packet*>(&packet3);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

	// Verify the anomaly
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::NONE);

        BOOST_CHECK(host_name->getMatchs() == 1);
        BOOST_CHECK(host_name->getTotalEvaluates() == 0);
        BOOST_CHECK(re1->getMatchs() == 1);
        BOOST_CHECK(re1->getTotalEvaluates() == 1);
        BOOST_CHECK(re2->getMatchs() == 1);
        BOOST_CHECK(re2->getTotalEvaluates() == 1);
        BOOST_CHECK(re3->getMatchs() == 1);
        BOOST_CHECK(re3->getTotalEvaluates() == 1);
	
	BOOST_CHECK(http->getTotalGets() == 0); 
	BOOST_CHECK(http->getTotalPosts() == 1);
	BOOST_CHECK(http->getTotalHeads() == 0);
	BOOST_CHECK(http->getTotalConnects() == 0);
	BOOST_CHECK(http->getTotalOptions() == 0);
	BOOST_CHECK(http->getTotalPuts() == 0);
	BOOST_CHECK(http->getTotalDeletes() == 0);
	BOOST_CHECK(http->getTotalTraces() == 0);
}

// Verify the regex on the payload of http by using linked regexs
BOOST_AUTO_TEST_CASE (test29)
{
        char *request = "GET /open/file.xml HTTP/1.1\r\n"
                        "User-Agent: Shockwave Flash\r\n"
                        "Host: somedomain.com\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Cache-Control: no-cache\r\n"
                        "\r\n";

        char *response = "HTTP/1.1 200 OK\r\n"
                        "Cache-Control: no-cache\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Content-Length: 37\r\n"
                        "Server: FlashCom/3.5.7\r\n"
                        "Content-Type: application/x-fcs\r\n"
                        "\r\n"
                        "Cuomdz02wSLGeYbI.";

        Packet packet1(reinterpret_cast <uint8_t*> (request), strlen(request));
        Packet packet2(reinterpret_cast <uint8_t*> (response), strlen(response));

        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("One domain", ".somedomain.com"));

        auto rmng = SharedPointer<RegexManager>(new RegexManager());
        auto re1 = SharedPointer<Regex>(new Regex("payload regex", "^Cuomdz02wSLGeYbI.$"));
        auto flow = SharedPointer<Flow>(new Flow());

        http->setDomainNameManager(host_mng);

        host_mng->addDomainName(host_name);
        host_name->setRegexManager(rmng);

        rmng->addRegex(re1);

        http->increaseAllocatedMemory(1);

        // Inject the first request
        flow->packet = const_cast<Packet*>(&packet1);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

        flow->packet = const_cast<Packet*>(&packet2);
        flow->setFlowDirection(FlowDirection::BACKWARD);
        http->processFlow(flow.get());

	// Verify the anomaly
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::NONE);

	BOOST_CHECK(host_name->getMatchs() == 1);
        BOOST_CHECK(host_name->getTotalEvaluates() == 0);
        BOOST_CHECK(re1->getMatchs() == 1);
        BOOST_CHECK(re1->getTotalEvaluates() == 1);
}

// Verify the use of malformed uris
BOOST_AUTO_TEST_CASE (test30) 
{
        char *header =  "GET /VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB/oonnnnn-a-/otherfile.html\r\n"
                        "Connection: close\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Accept: */*\r\n"
			"Cookie: PREF=ID=765870cb5ff303a3:TM=1209230140:LM=1209255358:GM=1:S=tFGcUUKdZTTlFhg8; "
				"rememberme=true; SID=DQAAAHcAAADymnf27WSdmq8VK7DtQkDCYwpT6yEH1c8p6crrirTO3HsXN"
				"2N_pOcW-T82lcNyvlUHgXiVPsZYrH6TnjQrgCEOLjUSOCrlLFh5I0BdGjioxzmksgWrrfeMV-y7bx1"
				"T1LPCMDOW0Wkw0XFqWOpMlkBCHsdt2Vcsha0j20VpIaw6yg; NID=10=jMYWNkozslA4UaRu8zyFSL"
				"Ens8iWVz4GdkeefkqVm5dFS0F0ztc8hDlNJRllb_WeYe9Wx6a8Yo7MnrFzqwZczgXV5e-RFbCrrJ9dfU5gs79L_v3BSdueIg_OOfjpScSh\r\n"
                        "User-Agent: LuisAgent\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Host: www.bu.com\r\n\r\n";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);
        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

	// Verify the anomaly
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::HTTP_BOGUS_URI_HEADER);
}

// Verify the use of no headers anomaly
BOOST_AUTO_TEST_CASE (test31) 
{
        char *header1 = "GET /VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB/oonnnnn-a-/otherfile.html HTTP/1.0\r\n"
                        "Host: www.somehost.com\r\n"
                        "\r\n";

        char *response = "HTTP/1.1 200 OK\r\n"
                        "Cache-Control: no-cache\r\n"
                        "Connection: Keep-Alive\r\n"
			"\r\n";

        Packet packetr(reinterpret_cast <uint8_t*> (response),strlen(response));
        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (header1);
        int length1 = strlen(header1);
        Packet packet1(pkt1, length1);
        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet1);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

	// Verify the anomaly
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::NONE);

	// The HTTP response from the server
        flow->packet = const_cast<Packet*>(&packetr);
        flow->setFlowDirection(FlowDirection::BACKWARD);
        http->processFlow(flow.get());

        char *header2 = "GET /VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WF%20%20x3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB/oonnnnn-a-/otherfile.html HTTP/1.0\r\n"
                  	"\r\n";
        
        uint8_t *pkt2 = reinterpret_cast <uint8_t*> (header2);
        int length2 = strlen(header2);
        Packet packet2(pkt2,length2);

	flow->packet = const_cast<Packet*>(&packet2);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

	// Verify the anomaly
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::HTTP_BOGUS_NO_HEADERS);
}

// Verify the extraction of the filename on the content-disposition field
BOOST_AUTO_TEST_CASE (test32)
{
	char *header =	"GET /00015d766423rr9f/1415286120 HTTP/1.1\r\n"
			"Accept: image/jpeg, application/x-ms-application, image/gif, */*\r\n"
			"Referer: http://grannityrektonaver.co.vu/15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html\r\n"
			"Accept-Language: en-US\r\n"
			"User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729\r\n"
			"Accept-Encoding: gzip, deflate\r\n"
			"Host: grannityrektonaver.co.vu\r\n"
			"Connection: Keep-Alive\r\n"
			"\r\n";

        char *response = "HTTP/1.1 200 OK\r\n"
                        "Server: nginx/1.2.1r\n"
			"Date: Thu, 06 Nov 2014 15:03:10 GMT\r\n"
			"Content-Type: application/pdf\r\n"
			"Content-Length: 9940\r\n"
			"Connection: keep-alive\r\n"
			"X-Powered-By: PHP/5.4.33\r\n"
			"Accept-Ranges: bytes\r\n"
			"Content-Disposition: inline; filename=XykpdWhZZ2.pdf\r\n"
			"\r\n"
			"%PDF-1.6\r\n"
			"%....\r\n"
			"1 0 obj\r\n"
			"<<\r\n"
			"/Type /Catalog\r\n"
			"/Version /1.4\r\n"
			"/Pages 2 0 R\r\n"
                        "/AcroForm 3 0 R\r\n"
			">>\r\n"
			"endobj";

        Packet packetr(reinterpret_cast <uint8_t*> (response),strlen(response));
        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (header);
        int length1 = strlen(header);
        Packet packet1(pkt1, length1);
        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet1);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

        flow->packet = const_cast<Packet*>(&packetr);
        flow->setFlowDirection(FlowDirection::BACKWARD);
        http->processFlow(flow.get());

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->getResponseCode() == 200);
        BOOST_CHECK(info->getContentLength() == 9940);

        BOOST_CHECK(info->getTotalRequests()  == 1);
        BOOST_CHECK(info->getTotalResponses()  == 1);

	BOOST_CHECK(info->ct != nullptr);
	BOOST_CHECK(info->filename != nullptr);

	std::string ct("application/pdf");
	std::string filename("XykpdWhZZ2.pdf");

	BOOST_CHECK(ct.compare(info->ct->getName()) == 0);
	BOOST_CHECK(filename.compare(info->filename->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test33)
{
        Packet packet("../http/packets/packet04.pcap");

        http->increaseAllocatedMemory(1);

        inject(packet);

        Flow *flow = http->getCurrentFlow();

	// The packet should contain an anomaly and a host equals *
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();

        std::string domain("*");
        BOOST_CHECK(domain.compare(info->host_name->getName()) == 0);


	// This value varies depending on if the memory is static or no
#if defined(HAVE_STATIC_MEMORY_CACHE)
	BOOST_CHECK(info->uri->getNameSize() == 256);
#else
	BOOST_CHECK(info->uri->getNameSize() > 900);
#endif
	// Verify the anomaly
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::HTTP_BOGUS_NO_HEADERS);
}

BOOST_AUTO_TEST_CASE (test34) // multiple files on the same flow
{
        char *response1 = "HTTP/1.1 200 OK\r\n"
                        "Server: nginx/1.2.1r\n"
			"Date: Thu, 06 Nov 2014 15:03:10 GMT\r\n"
			"Content-Type: application/pdf\r\n"
			"Content-Length: 140\r\n"
			"Connection: keep-alive\r\n"
			"X-Powered-By: PHP/5.4.33\r\n"
			"Accept-Ranges: bytes\r\n"
			"Content-Disposition: inline; filename=\"XykpdWhZZ2.pdf\"\r\n"
			"\r\n"
			"%PDF-1.6\r\n"
			"%....\r\n"
			"1 0 obj\r\n"
			"<<\r\n"
			"/Type /Catalog\r\n"
			"/Version /1.4\r\n"
			"/Pages 2 0 R\r\n"
                        "/AcroForm 3 0 R\r\n"
			">>\r\n"
			"endobj";
        
	char *response2 = "HTTP/1.1 200 OK\r\n"
                        "Server: nginx/1.2.1r\n"
			"Content-Type: application/xxx\r\n"
			"Content-Length: 40\r\n"
			"Content-Disposition: inline; filename=Idont_care.pdf\r\n"
			"\r\n"
			"%PDF-1.6\r\n"
			"%....\r\n"
			"bubu";

        Packet packet1(reinterpret_cast <uint8_t*> (response1), strlen(response1));
        Packet packet2(reinterpret_cast <uint8_t*> (response2), strlen(response2));

        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(2);

        flow->packet = const_cast<Packet*>(&packet1);
        flow->setFlowDirection(FlowDirection::BACKWARD);

        http->processFlow(flow.get());

	// Check the values of the first response
        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->getResponseCode() == 200);
        BOOST_CHECK(info->getContentLength() == 140);
        BOOST_CHECK(info->getTotalRequests()  == 0);
        BOOST_CHECK(info->getTotalResponses()  == 1);

        BOOST_CHECK(info->ct != nullptr);
        BOOST_CHECK(info->filename != nullptr);

        std::string ct("application/pdf");
        std::string filename("XykpdWhZZ2.pdf");

	BOOST_CHECK(ct.compare(info->ct->getName()) == 0);
	BOOST_CHECK(filename.compare(info->filename->getName()) == 0);

	// inject the second packet
        flow->packet = const_cast<Packet*>(&packet2);
        flow->setFlowDirection(FlowDirection::BACKWARD);

	// a trick :)
	info->setHTTPDataDirection(FlowDirection::FORWARD);

        http->processFlow(flow.get());

	// Check the values of the second response and the updated file
        BOOST_CHECK(info->getResponseCode() == 200);
        BOOST_CHECK(info->getContentLength() == 40);
        BOOST_CHECK(info->getTotalRequests()  == 0);
        BOOST_CHECK(info->getTotalResponses()  == 2);

        BOOST_CHECK(info->ct != nullptr);
        BOOST_CHECK(info->filename != nullptr);

        ct = "application/xxx";
        filename = "Idont_care.pdf";

	BOOST_CHECK(ct.compare(info->ct->getName()) == 0);
	BOOST_CHECK(filename.compare(info->filename->getName()) == 0);

	JsonFlow j;
        info->serialize(j);
	
	// Release all
	http->releaseCache();
}

BOOST_AUTO_TEST_CASE (test35) // two flows using the same file
{
        char *response = "HTTP/1.1 200 OK\r\n"
                        "Server: nginx/1.2.1r\n"
			"Date: Thu, 06 Nov 2014 15:03:10 GMT\r\n"
			"Content-Type: application/pdf\r\n"
			"Content-Length: 140\r\n"
			"Connection: keep-alive\r\n"
			"X-Powered-By: PHP/5.4.33\r\n"
			"Accept-Ranges: bytes\r\n"
			"Content-Disposition: inline; filename=\"XykpdWhZZ2.pdf\"\r\n"
			"\r\n"
			"%PDF-1.6\r\n"
			"%....\r\n"
			"1 0 obj\r\n"
			"<<\r\n"
			"/Type /Catalog\r\n"
			"/Version /1.4\r\n"
			"/Pages 2 0 R\r\n"
                        "/AcroForm 3 0 R\r\n"
			">>\r\n"
			"endobj";
        
        Packet packet(reinterpret_cast <uint8_t*> (response), strlen(response));

        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(2);
        
	flow1->packet = const_cast<Packet*>(&packet);
        flow1->setFlowDirection(FlowDirection::BACKWARD);
	flow2->packet = const_cast<Packet*>(&packet);
        flow2->setFlowDirection(FlowDirection::BACKWARD);

        http->processFlow(flow1.get());
        http->processFlow(flow2.get());

	// Check the values 
        SharedPointer<HTTPInfo> info1 = flow1->getHTTPInfo();
        BOOST_CHECK(info1 != nullptr);
        SharedPointer<HTTPInfo> info2 = flow2->getHTTPInfo();
        BOOST_CHECK(info2 != nullptr);

        BOOST_CHECK(info1->getResponseCode() == 200);
        BOOST_CHECK(info1->getContentLength() == 140);
        BOOST_CHECK(info1->getTotalRequests()  == 0);
        BOOST_CHECK(info1->getTotalResponses()  == 1);

        BOOST_CHECK(info1->ct != nullptr);
        BOOST_CHECK(info1->filename != nullptr);

        std::string ct("application/pdf");
        std::string filename("XykpdWhZZ2.pdf");

	BOOST_CHECK(ct.compare(info1->ct->getName()) == 0);
	BOOST_CHECK(filename.compare(info1->filename->getName()) == 0);

	// both flows share the info
	BOOST_CHECK(info1->filename == info2->filename);
	BOOST_CHECK(info1->ct == info2->ct);
}

// Verify the regex on the payload of response http post
BOOST_AUTO_TEST_CASE (test36)
{
        char *request = "POST /open/1 HTTP/1.1\r\n"
                        "Content-Type: application/x-fcs\r\n"
                        "User-Agent: Shockwave Flash\r\n"
                        "Host: somedomain.ru\r\n"
                        "Content-Length: 0\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Cache-Control: no-cache\r\n"
                        "\r\n";

        char *response = "HTTP/1.1 200 OK\r\n"
                        "Server: nginx/1.2.1r\n"
                        "Content-Type: application/xxx\r\n"
                        "\r\n"
                        "%PDF-1.6\r\n"
                        "%....\r\n"
                        "bubu";

        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (request);
        int length1 = strlen(request);
        Packet packet1(pkt1, length1);
        Packet packet2(reinterpret_cast <uint8_t*> (response), strlen(response));

        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("One domain", ".ru"));

        auto rmng = SharedPointer<RegexManager>(new RegexManager());
        auto re = SharedPointer<Regex>(new Regex("payload regex", "^.*bubu.*$"));
        auto flow = SharedPointer<Flow>(new Flow());

        http->setDomainNameManager(host_mng);

        host_mng->addDomainName(host_name);
        host_name->setRegexManager(rmng);

        rmng->addRegex(re);

        http->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet1);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->getTotalRequests()  == 1);
        BOOST_CHECK(info->getTotalResponses()  == 0);

        BOOST_CHECK(host_name->getMatchs() == 1);
        BOOST_CHECK(host_name->getTotalEvaluates() == 0);
        BOOST_CHECK(re->getMatchs() == 0);
        BOOST_CHECK(re->getTotalEvaluates() == 0);
        
	flow->packet = const_cast<Packet*>(&packet2);
        flow->setFlowDirection(FlowDirection::BACKWARD);
        http->processFlow(flow.get());

	BOOST_CHECK(http->getTotalL7Bytes() == 21);

        BOOST_CHECK(info->getTotalRequests()  == 1);
        BOOST_CHECK(info->getTotalResponses()  == 1);

        BOOST_CHECK(host_name->getMatchs() == 1);
        BOOST_CHECK(host_name->getTotalEvaluates() == 0);
        BOOST_CHECK(re->getMatchs() == 1);
        BOOST_CHECK(re->getTotalEvaluates() == 1);
}

// Verify the regex on the payload of requests and response http post
BOOST_AUTO_TEST_CASE (test37)
{
        char *request = "POST /open/1 HTTP/1.1\r\n"
                        "Content-Type: application/x-fcs\r\n"
                        "User-Agent: Shockwave Flash\r\n"
                        "Host: somedomain.ru\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Cache-Control: no-cache\r\n"
                        "\r\n"
			"Some data on the post request";

	char *data =	"Some data on the post request";

        char *pdu1 =    "HELLAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA";

        char *pdu2 =    "BYEBYEAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAAAAA"
                        "AAAAAAAAAAAAAAAAFFFF";

        char *response = "HTTP/1.1 200 OK\r\n"
                        "Server: nginx/1.2.1r\n"
                        "Content-Type: application/xxx\r\n"
                        "\r\n"
                        "%PDF-1.6\r\n"
                        "%....\r\n"
                        "bubu"; // 21 bytes of data

        Packet packet1(reinterpret_cast <uint8_t*> (request), strlen(request));
        Packet packet2(reinterpret_cast <uint8_t*> (pdu1), strlen(pdu1));
        Packet packet3(reinterpret_cast <uint8_t*> (pdu2), strlen(pdu2));
        Packet packet4(reinterpret_cast <uint8_t*> (response), strlen(response));

        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("One domain", ".ru"));

        auto rm = SharedPointer<RegexManager>(new RegexManager());
        auto r1 = SharedPointer<Regex>(new Regex("payload regex", "^.*bubu$"));
        auto r2 = SharedPointer<Regex>(new Regex("payload regex", "^.*FFFF$"));
        auto r3 = SharedPointer<Regex>(new Regex("payload regex", "^HELLA.*$"));
        auto r4 = SharedPointer<Regex>(new Regex("payload regex", "^.*(post request)$"));
        auto flow = SharedPointer<Flow>(new Flow());

        http->setDomainNameManager(host_mng);

        host_mng->addDomainName(host_name);
        host_name->setRegexManager(rm);

        rm->addRegex(r1);
        rm->addRegex(r2);
        rm->addRegex(r3);
        rm->addRegex(r4);

        http->increaseAllocatedMemory(1);

	// Inject the first packet (the post)
        flow->packet = const_cast<Packet*>(&packet1);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->getTotalRequests()  == 1);
        BOOST_CHECK(info->getTotalResponses()  == 0);

	BOOST_CHECK(http->getTotalL7Bytes() == strlen(data));
	BOOST_CHECK(http->getHTTPHeaderSize() == strlen(request) - strlen(data));

        BOOST_CHECK(host_name->getMatchs() == 1);
        BOOST_CHECK(host_name->getTotalEvaluates() == 0);
        BOOST_CHECK(r1->getMatchs() == 0);
        BOOST_CHECK(r1->getTotalEvaluates() == 1);
        BOOST_CHECK(r2->getMatchs() == 0);
        BOOST_CHECK(r2->getTotalEvaluates() == 1);
        BOOST_CHECK(r3->getMatchs() == 0);
        BOOST_CHECK(r3->getTotalEvaluates() == 1);
        BOOST_CHECK(r4->getMatchs() == 1);
        BOOST_CHECK(r4->getTotalEvaluates() == 1);

	// Reset the regex of the flow
	flow->regex.reset();

        // Inject the second packet (the post)
        flow->packet = const_cast<Packet*>(&packet2);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

        BOOST_CHECK(info->getTotalRequests()  == 1);
        BOOST_CHECK(info->getTotalResponses()  == 0);

        BOOST_CHECK(http->getTotalL7Bytes() == strlen(data) + strlen(pdu1));
        BOOST_CHECK(http->getHTTPHeaderSize() == 0);

        BOOST_CHECK(host_name->getMatchs() == 1);
        BOOST_CHECK(host_name->getTotalEvaluates() == 0);
        BOOST_CHECK(r1->getMatchs() == 0);
        BOOST_CHECK(r1->getTotalEvaluates() == 2);
        BOOST_CHECK(r2->getMatchs() == 0);
        BOOST_CHECK(r2->getTotalEvaluates() == 2);
        BOOST_CHECK(r3->getMatchs() == 1);
        BOOST_CHECK(r3->getTotalEvaluates() == 2);
        BOOST_CHECK(r4->getMatchs() == 1);
        BOOST_CHECK(r4->getTotalEvaluates() == 1);

	// Reset the regex of the flow
	flow->regex.reset();

        // Inject the second 3 (the post)
        flow->packet = const_cast<Packet*>(&packet3);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

        BOOST_CHECK(info->getTotalRequests()  == 1);
        BOOST_CHECK(info->getTotalResponses()  == 0);

        BOOST_CHECK(http->getTotalL7Bytes() == strlen(data) + strlen(pdu1) + strlen(pdu2));
        BOOST_CHECK(http->getHTTPHeaderSize() == 0);

        BOOST_CHECK(host_name->getMatchs() == 1);
        BOOST_CHECK(host_name->getTotalEvaluates() == 0);
        BOOST_CHECK(r1->getMatchs() == 0);
        BOOST_CHECK(r1->getTotalEvaluates() == 3);
        BOOST_CHECK(r2->getMatchs() == 1);
        BOOST_CHECK(r2->getTotalEvaluates() == 3);
        BOOST_CHECK(r3->getMatchs() == 1);
        BOOST_CHECK(r3->getTotalEvaluates() == 2);
        BOOST_CHECK(r4->getMatchs() == 1);
        BOOST_CHECK(r4->getTotalEvaluates() == 1);

        // Reset the regex of the flow
        flow->regex.reset();

        // Inject the last packet (the post response)
        flow->packet = const_cast<Packet*>(&packet4);
        flow->setFlowDirection(FlowDirection::BACKWARD);
        http->processFlow(flow.get());

        BOOST_CHECK(info->getTotalRequests()  == 1);
        BOOST_CHECK(info->getTotalResponses()  == 1);

        BOOST_CHECK(http->getTotalL7Bytes() == strlen(data) + strlen(pdu1) + strlen(pdu2) + 21);
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(response) - 21);

        BOOST_CHECK(host_name->getMatchs() == 1);
        BOOST_CHECK(host_name->getTotalEvaluates() == 0);
        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 4);
        BOOST_CHECK(r2->getMatchs() == 1);
        BOOST_CHECK(r2->getTotalEvaluates() == 3);
        BOOST_CHECK(r3->getMatchs() == 1);
        BOOST_CHECK(r3->getTotalEvaluates() == 2);
        BOOST_CHECK(r4->getMatchs() == 1);
        BOOST_CHECK(r4->getTotalEvaluates() == 1);
}

// Long request split in two pdus
BOOST_AUTO_TEST_CASE (test38)
{
	char *method1 =	"GET /w/ygo-mail%3B_ylt=A2KL8weP2MNQbScAURcp89w4?.tsrc=kakoo&.intl=uk&.lang=en-gb HTTP/1.1\r\n";
	char *params1 =	"Host: m.kakoo.com\r\n"
			"Connection: keep-alive\r\n"
			"Referer: http://m.kakoo.com/?.tsrc=kakoo&mobile_view_default=true\r\n"
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
			"x-wap-profile: http://wap.samsungmobile.com/uaprof/GT-I9399.xml\r\n"
			"User-Agent: Mozilla/5.0 (Linux; U; Android 4.0.4; en-ie; SAMSUNG GT-I9300/I9300BUALF1 Build/IMM76D)"
			" AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30\r\n"
			"Accept-Encoding: gzip,deflate\r\n"
			"Accept-Language: en-IE, en-US\r\n"
			"Accept-Charset: utf-8, iso-8859-1, utf-16, gb2312, gbk, *;q=0.7\r\n"
			"Cookie: AO=o=0; F=a=PBNFpFIMvShV.IWE0_SrnL2GH.POvEcGvO.krJX3wgx4BVg6W0Lf5xGLIzdT0ejHzRlyXPg-&b=k2J7;"
			" PH=logout=LnNyYz1jZGdtJi5pbnRsPXVr&l=en-GB;"
			" Y=v=1&n=3n6c6ffhmd7ga&l=03a84bo/o&p=f2lvvie013000000&iz=NA&r=es&lg=en-GB&intl=uk&np=1;"
			" T=z=3yvwQB3GX1QB22tjnVvjhsMNjA2MgY2Mzc3MjcyMU4x&a=QAE&sk=DAAa2GKfuaDsmt&ks=EAA.bTFRz14167pzZMD9f_qYQ-"
			"-~E&d=c2wBTVRjeE5RRXhOREF3TlRBMU5qazIBYQFRQUUBZwFaSUJBUUs1M0lBWU1OT042VFk2R1AySjRLNAF6egEzeXZ3UUJBN0UBdGlwAWl0WThRRA--;"
			" YM=v=2&u=dvWBeYCWs16H3sWhChcEA7BtmTgqFeMwwP7Vlg--&d=&f=CAA&t=3yvwQB&s=PwSK;"
			" B=5veflul8a43mt&b=4&d=8jiSY51pYF5FUbKSPh8ZzXGa8.8-&s=7m&i=VU6FVipYz8ymPQGsxM6G;"
			" U=mt=4eWxyp2MhYh679YOHQ.cTL4e5W4wfRn5ZTViPj8-&ux=Li9wQB&un=3n6c6ffhmd7ga;"
			" DK=v=2&m=fp1&r=fp1&p=OHwxMDA1NHxTYW1zdW5nfEdULUk5MzAwfEFuZHJvaWR8NC4wLjQ-";

      	std::string header1(method1);
        header1.append(params1);
        const uint8_t *pkt1 = reinterpret_cast <const uint8_t*> (header1.c_str());

	char *request2 ="Uk5MzAwfEFuZHJvaWR8NC4wLjQ-\r\n\r\n";

        Packet packet1(pkt1, header1.length());
        Packet packet2(reinterpret_cast <uint8_t*> (request2), strlen(request2));
        auto flow = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(1);

        // Inject the first packet 
        flow->packet = const_cast<Packet*>(&packet1);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->getTotalRequests()  == 1);
        BOOST_CHECK(info->getTotalResponses()  == 0);

        // Verify the size of the Header integrity
        BOOST_CHECK(http->getHTTPHeaderSize() == header1.length());
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method1));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params1));
        BOOST_CHECK(http->getTotalL7Bytes() == 0);

	// Inject the second packet 
        flow->packet = const_cast<Packet*>(&packet2);
        flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

        // Verify the size of the Header integrity
        BOOST_CHECK(http->getHTTPHeaderSize() == 0);
        BOOST_CHECK(http->getHTTPMethodSize() == 0);
        BOOST_CHECK(http->getHTTPParametersSize() == 0);
        BOOST_CHECK(http->getTotalL7Bytes() == strlen(request2));
}

// Verify the extraction of the last parameter if is with not delimiters
BOOST_AUTO_TEST_CASE (test39)
{
        char *method1 =	"GET /w/ygo-mail%3B_ylt=A2KL8weP2MNQbScAURcp89w4?.tsrc=kakoo&.intl=uk HTTP/1.1\r\n";
        char *params1 = "Host: m.pepe.com\r\n";

        char *method2 =	"GET /w/ygo-mail%3B_ylt=A2KL8weP2MNQbScAURcp89w4?.tsrc=kakoo&.intl=uk&.lang=en-gb HTTP/1.1\r\n";
        char *params2 = "Host: m.otherpepe.com";

        char *method3 =	"GET /w/ygo-mail%3B_ylt=A2KL8weP2MNQbScAURcp89w4?.tsrc=kakoo&.lang=en-gb HTTP/1.1\r\n";
        char *params3 = "Host: m.otherpepe.com\r";

        std::string header1(method1);
        header1.append(params1);
        const uint8_t *pkt1 = reinterpret_cast <const uint8_t*> (header1.c_str());
        Packet packet1(pkt1, header1.length());

        std::string header2(method2);
        header2.append(params2);
        const uint8_t *pkt2 = reinterpret_cast <const uint8_t*> (header2.c_str());
        Packet packet2(pkt2, header2.length());

        std::string header3(method3);
        header3.append(params3);
        const uint8_t *pkt3 = reinterpret_cast <const uint8_t*> (header3.c_str());
        Packet packet3(pkt3, header3.length());

        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());
        auto flow3 = SharedPointer<Flow>(new Flow());

        http->increaseAllocatedMemory(3);

        // Inject the first packet 
        flow1->packet = const_cast<Packet*>(&packet1);
        flow1->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow1.get());

        SharedPointer<HTTPInfo> info1 = flow1->getHTTPInfo();
        BOOST_CHECK(info1 != nullptr);
	BOOST_CHECK(info1->host_name != nullptr);
	BOOST_CHECK(info1->uri != nullptr);
	BOOST_CHECK(info1->ct == nullptr);
	BOOST_CHECK(info1->ua == nullptr);

	std::string host("m.pepe.com");
	BOOST_CHECK(host.compare(info1->host_name->getName()) == 0);

        BOOST_CHECK(info1->getTotalRequests() == 1);
        BOOST_CHECK(info1->getTotalResponses() == 0);

        // Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header1.length());
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method1));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params1));
        BOOST_CHECK(http->getTotalL7Bytes() == 0);

	// Inject the second packet
        flow2->packet = const_cast<Packet*>(&packet2);
        flow2->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow2.get());

        SharedPointer<HTTPInfo> info2 = flow2->getHTTPInfo();
        BOOST_CHECK(info2 != nullptr);
        BOOST_CHECK(info2->host_name == nullptr); // We can not determine if is complete
        BOOST_CHECK(info2->uri != nullptr);
        BOOST_CHECK(info2->ct == nullptr);
        BOOST_CHECK(info2->ua == nullptr);
        
	// Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header2.length());
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method2));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params2));
        BOOST_CHECK(http->getTotalL7Bytes() == 0);

	// Inject the thrid packet
        flow3->packet = const_cast<Packet*>(&packet3);
        flow3->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow3.get());

        SharedPointer<HTTPInfo> info3 = flow3->getHTTPInfo();
        BOOST_CHECK(info3 != nullptr);
        BOOST_CHECK(info3->host_name == nullptr); // We can not determine if is complete
        BOOST_CHECK(info3->uri != nullptr);
        BOOST_CHECK(info3->ct == nullptr);
        BOOST_CHECK(info3->ua == nullptr);
	
	// Verify the integrity of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == header3.length());
        BOOST_CHECK(http->getHTTPMethodSize() == strlen(method3));
        BOOST_CHECK(http->getHTTPParametersSize() == strlen(params3));
        BOOST_CHECK(http->getTotalL7Bytes() == 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(http_test_suite_ipv6, StackIPv6HTTPtest)

BOOST_AUTO_TEST_CASE (test01)
{
        Packet packet("../http/packets/packet11.pcap");

	inject(packet);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip6->getTotalBytes() == 797 + 20 + 40);

        BOOST_CHECK(mux_ip->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 1);
        BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp->getTotalBytes() == 797 + 20);

        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFlows() == 0);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);

        BOOST_CHECK(http->getTotalPackets() == 1);
        BOOST_CHECK(http->getTotalValidPackets() == 1);
        BOOST_CHECK(http->getTotalBytes() == 797);

        std::string cad("GET / HTTP/1.1");
        std::string header((char*)http->getPayload(), cad.length());

        BOOST_CHECK(cad.compare(header) == 0);
}

BOOST_AUTO_TEST_CASE (test02)
{
        Packet packet1("../http/packets/packet11.pcap");
        Packet packet2("../http/packets/packet12.pcap");

	inject(packet1);
	inject(packet2);

        BOOST_CHECK(ip6->getTotalPackets() == 2);
        BOOST_CHECK(ip6->getTotalValidPackets() == 2);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(mux_ip->getTotalForwardPackets() == 2);
        BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 2);
        BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 2);
        BOOST_CHECK(tcp->getTotalValidPackets() == 2);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFlows() == 0);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);

	// Probably need to improve more.
}

BOOST_AUTO_TEST_CASE (test03)
{
        Packet packet("../ip6/packets/packet02.pcap");

	inject(packet);

        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFlows() == 0);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);

	// The http request contains a non valid minimum http header
	// GET bad.html
	// For performance issues this header is determined as valid
        BOOST_CHECK(http->getTotalInvalidPackets() == 0);
        BOOST_CHECK(http->getTotalValidPackets() == 1);
        BOOST_CHECK(http->getTotalBytes() == 15);

}

// Release items to their corresponding cache test with a emppy cache
BOOST_AUTO_TEST_CASE (test04)
{
        Packet packet("../http/packets/packet11.pcap");

        // Dont create any items on the cache
        http->increaseAllocatedMemory(0);

	inject(packet);

	auto fm = tcp->getFlowManager();

	for (auto &f: fm->getFlowTable()) {
		BOOST_CHECK(f->layer7info == nullptr);
	}

	http->releaseCache(); // Nothing to release

        for (auto &f: fm->getFlowTable()) {
                BOOST_CHECK(f->getHTTPInfo() == nullptr);
        }
}

// Release items to their corresponding cache test 
BOOST_AUTO_TEST_CASE (test05)
{
        Packet packet("../http/packets/packet11.pcap");

        // create any items on the cache
        http->increaseAllocatedMemory(1);

	inject(packet);

        auto fm = tcp->getFlowManager();

        for (auto &f: fm->getFlowTable()) {
                BOOST_CHECK(f->getHTTPInfo() != nullptr);
                BOOST_CHECK(f->getHTTPInfo()->uri != nullptr);
                BOOST_CHECK(f->getHTTPInfo()->ua != nullptr);
        }
        http->releaseCache(); 

        for (auto &f: fm->getFlowTable()) {
                BOOST_CHECK(f->getHTTPInfo() == nullptr);
                BOOST_CHECK(f->layer7info == nullptr);
        }
}

BOOST_AUTO_TEST_CASE (test06)
{
	Packet packet("../ip6/packets/packet08.pcap");

	inject(packet);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip6->getTotalBytes() == 155 + 32 + 56);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp->getTotalBytes() == 155 + 32);

        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFlows() == 0);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);

        BOOST_CHECK(http->getTotalPackets() == 1);
        BOOST_CHECK(http->getTotalValidPackets() == 1);
        BOOST_CHECK(http->getTotalBytes() == 155);

        std::string cad("GET / HTTP/1.1");
        std::string header((char*)http->getPayload(), cad.length());

        BOOST_CHECK(cad.compare(header) == 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(http_suite2, StackIPv6HTTPtest)

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(http_ipv6_suite_dynamic, StackIPv6HTTPtest)

BOOST_AUTO_TEST_CASE (test01)
{
        Packet packet("../http/packets/packet11.pcap");

        // Dont create any items on the cache
        http->increaseAllocatedMemory(0);

	// Make the memory dynamic
	http->setDynamicAllocatedMemory(true);

	inject(packet);

	auto fm = tcp->getFlowManager();

	for (auto &f: fm->getFlowTable()) {
		BOOST_CHECK(f->layer7info != nullptr);
	}

	http->releaseCache(); // Nothing to release

        for (auto &f: fm->getFlowTable()) {
                BOOST_CHECK(f->getHTTPInfo() == nullptr);
        }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(http_suite_dynamic, StackHTTPtest)

BOOST_AUTO_TEST_CASE (test01)
{
	char *header = 	"GET / HTTP/1.1\r\n"
			"Host: www.google.com\r\n"
			"Connection: close\r\n\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
	Packet packet(pkt,length);

	http->setDynamicAllocatedMemory(true);

        auto flow = SharedPointer<Flow>(new Flow());

	flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	BOOST_CHECK(flow->layer7info != nullptr);
	BOOST_CHECK(flow->getHTTPInfo() != nullptr);
}

BOOST_AUTO_TEST_CASE (test02)
{
        char *header =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
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
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);

	auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
	auto host_name = SharedPointer<DomainName>(new DomainName("example", ".bu.ba.com"));

	http->setDynamicAllocatedMemory(true);

        Packet packet(pkt,length);
        auto flow = SharedPointer<Flow>(new Flow());

	http->setDomainNameManager(host_mng);
	host_mng->addDomainName(host_name);

	// Dont create any items on the cache
        http->increaseAllocatedMemory(0);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();

        // Size of the header equals 607 
	BOOST_CHECK(http->getHTTPHeaderSize() == 607);
        BOOST_CHECK(info != nullptr);
	BOOST_CHECK(host_name->getMatchs() == 0);
}

BOOST_AUTO_TEST_CASE (test03) // Options method 
{
        Packet packet("../http/packets/packet05.pcap");

	http->setDynamicAllocatedMemory(true);

	inject(packet);

	BOOST_CHECK(http->getTotalGets() == 0); 
	BOOST_CHECK(http->getTotalPosts() == 0);
	BOOST_CHECK(http->getTotalHeads() == 0);
	BOOST_CHECK(http->getTotalConnects() == 0);
	BOOST_CHECK(http->getTotalOptions() == 1);
	BOOST_CHECK(http->getTotalPuts() == 0);
	BOOST_CHECK(http->getTotalDeletes() == 0);
	BOOST_CHECK(http->getTotalTraces() == 0);
}

BOOST_AUTO_TEST_CASE (test04) // head method 
{
        Packet packet("../http/packets/packet06.pcap");

	http->setDynamicAllocatedMemory(true);

	inject(packet);

	BOOST_CHECK(http->getTotalGets() == 0); 
	BOOST_CHECK(http->getTotalPosts() == 0);
	BOOST_CHECK(http->getTotalHeads() == 1);
	BOOST_CHECK(http->getTotalConnects() == 0);
	BOOST_CHECK(http->getTotalOptions() == 0);
	BOOST_CHECK(http->getTotalPuts() == 0);
	BOOST_CHECK(http->getTotalDeletes() == 0);
	BOOST_CHECK(http->getTotalTraces() == 0);
}

BOOST_AUTO_TEST_CASE (test05) // connect method 
{
        Packet packet("../http/packets/packet07.pcap");

	http->setDynamicAllocatedMemory(true);

	inject(packet);

	BOOST_CHECK(http->getTotalGets() == 0); 
	BOOST_CHECK(http->getTotalPosts() == 0);
	BOOST_CHECK(http->getTotalHeads() == 0);
	BOOST_CHECK(http->getTotalConnects() == 1);
	BOOST_CHECK(http->getTotalOptions() == 0);
	BOOST_CHECK(http->getTotalPuts() == 0);
	BOOST_CHECK(http->getTotalDeletes() == 0);
	BOOST_CHECK(http->getTotalTraces() == 0);
}

BOOST_AUTO_TEST_CASE (test06) // put method 
{
        Packet packet("../http/packets/packet08.pcap");

	http->setDynamicAllocatedMemory(true);

	inject(packet);

        Flow *flow = http->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        std::string host("192.168.10.17");
        std::string ct("application/x-www-form-urlencoded");

        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(ct.compare(info->ct->getName()) == 0);

	BOOST_CHECK(http->getTotalGets() == 0); 
	BOOST_CHECK(http->getTotalPosts() == 0);
	BOOST_CHECK(http->getTotalHeads() == 0);
	BOOST_CHECK(http->getTotalConnects() == 0);
	BOOST_CHECK(http->getTotalOptions() == 0);
	BOOST_CHECK(http->getTotalPuts() == 1);
	BOOST_CHECK(http->getTotalDeletes() == 0);
	BOOST_CHECK(http->getTotalTraces() == 0);
}

BOOST_AUTO_TEST_CASE (test07) // trace method 
{
        Packet packet("../http/packets/packet09.pcap");

	http->setDynamicAllocatedMemory(true);

	inject(packet);

	BOOST_CHECK(http->getTotalGets() == 0); 
	BOOST_CHECK(http->getTotalPosts() == 0);
	BOOST_CHECK(http->getTotalHeads() == 0);
	BOOST_CHECK(http->getTotalConnects() == 0);
	BOOST_CHECK(http->getTotalOptions() == 0);
	BOOST_CHECK(http->getTotalPuts() == 0);
	BOOST_CHECK(http->getTotalDeletes() == 0);
	BOOST_CHECK(http->getTotalTraces() == 1);
}

BOOST_AUTO_TEST_CASE (test08) // delete method 
{
        Packet packet("../http/packets/packet10.pcap");

	http->setDynamicAllocatedMemory(true);

	inject(packet);

	BOOST_CHECK(http->getTotalGets() == 0); 
	BOOST_CHECK(http->getTotalPosts() == 0);
	BOOST_CHECK(http->getTotalHeads() == 0);
	BOOST_CHECK(http->getTotalConnects() == 0);
	BOOST_CHECK(http->getTotalOptions() == 0);
	BOOST_CHECK(http->getTotalPuts() == 0);
	BOOST_CHECK(http->getTotalDeletes() == 1);
	BOOST_CHECK(http->getTotalTraces() == 0);

        Flow *flow = http->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);

        std::string host("127.0.0.1");
        std::string ct("text/html");
        std::string ua("Mu Dynamics/HTTP");
        std::string uri("/");

        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(ct.compare(info->ct->getName()) == 0);
        BOOST_CHECK(ua.compare(info->ua->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test09) // Verify the operator * on http
{
        char *header =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
                        "9QRoPmYJBXJvOlyH%2Fs6mNArj%2F7y0oT1UkApkjaGawH5zJBYkpq9&av=4.4 HTTP/1.1\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: CFNetwork/609 Darwin/13.0.0\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Host: onedomain.com\r\n"
                        "\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);

        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("All", "*"));

        http->setDynamicAllocatedMemory(true);

        Packet packet(pkt,length);
        auto flow1 = SharedPointer<Flow>(new Flow());

        http->setDomainNameManager(host_mng);
        host_mng->addDomainName(host_name);

        flow1->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow1.get());

        SharedPointer<HTTPInfo> info = flow1->getHTTPInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(host_name->getMatchs() == 1);
	BOOST_CHECK(info->matched_domain_name == host_name);

	// Remove the * domain
	host_mng->removeDomainName(host_name);

        auto flow2 = SharedPointer<Flow>(new Flow());

        flow2->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow2.get());

        info = flow2->getHTTPInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(host_name->getMatchs() == 1);
	BOOST_CHECK(info->matched_domain_name == nullptr);
}

BOOST_AUTO_TEST_CASE (test10) // Verify the operator * on http with different domains
{
        char *header1 =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873 HTTP/1.1\r\n"
                        "Connection: close\r\n"
                        "User-Agent: CFNetwork/609 Darwin/13.0.0\r\n"
                        "Host: onedomain.com\r\n"
                        "\r\n";
        char *header2 =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873 HTTP/1.1\r\n"
                        "Connection: close\r\n"
                        "User-Agent: CFNetwork/609 Darwin/13.0.0\r\n"
                        "Host: other.com\r\n"
                        "\r\n";
        char *header3 =  "GET /access/file.mp4 HTTP/1.1\r\n"
                        "Host: other.net\r\n"
                        "\r\n";
        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (header1);
        int length1 = strlen(header1);
        uint8_t *pkt2 = reinterpret_cast <uint8_t*> (header2);
        int length2 = strlen(header2);
        uint8_t *pkt3 = reinterpret_cast <uint8_t*> (header3);
        int length3 = strlen(header3);

        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto dall = SharedPointer<DomainName>(new DomainName("All", "*"));
        auto d1 = SharedPointer<DomainName>(new DomainName("the coms", ".com"));

        http->setDynamicAllocatedMemory(true);

        Packet packet1(pkt1, length1);
        Packet packet2(pkt2, length2);
        Packet packet3(pkt3, length3);
        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());
        auto flow3 = SharedPointer<Flow>(new Flow());

        http->setDomainNameManager(host_mng);
        host_mng->addDomainName(d1);
        host_mng->addDomainName(dall);

        flow1->packet = const_cast<Packet*>(&packet1);
        flow2->packet = const_cast<Packet*>(&packet2);
        flow3->packet = const_cast<Packet*>(&packet3);

	// Inject the three flows
        http->processFlow(flow1.get());
        http->processFlow(flow2.get());
        http->processFlow(flow3.get());

        SharedPointer<HTTPInfo> info1 = flow1->getHTTPInfo();
        SharedPointer<HTTPInfo> info2 = flow2->getHTTPInfo();
        SharedPointer<HTTPInfo> info3 = flow3->getHTTPInfo();
        BOOST_CHECK(info1 != nullptr);
        BOOST_CHECK(info2 != nullptr);
        BOOST_CHECK(info3 != nullptr);
        BOOST_CHECK(dall->getMatchs() == 1);
        BOOST_CHECK(d1->getMatchs() == 2);
        BOOST_CHECK(info1->matched_domain_name == d1);
        BOOST_CHECK(info2->matched_domain_name == d1);
        BOOST_CHECK(info3->matched_domain_name == dall);
}

BOOST_AUTO_TEST_CASE (test11) // Verify the operator * on http with different long domains
{
        char *header1 =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873 HTTP/1.1\r\n"
                        "Connection: close\r\n"
                        "User-Agent: CFNetwork/609 Darwin/13.0.0\r\n"
                        "Host: a.b.c.onedomain.com\r\n"
                        "\r\n";
        char *header2 =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873 HTTP/1.1\r\n"
                        "Connection: close\r\n"
                        "User-Agent: CFNetwork/609 Darwin/13.0.0\r\n"
                        "Host: b.c.onedomain.com\r\n"
                        "\r\n";
        char *header3 =  "GET /access/file.mp4 HTTP/1.1\r\n"
                        "Host: onedomain.com\r\n"
                        "\r\n";
        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (header1);
        int length1 = strlen(header1);
        uint8_t *pkt2 = reinterpret_cast <uint8_t*> (header2);
        int length2 = strlen(header2);
        uint8_t *pkt3 = reinterpret_cast <uint8_t*> (header3);
        int length3 = strlen(header3);

        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto dall = SharedPointer<DomainName>(new DomainName("All", "*"));
        auto d1 = SharedPointer<DomainName>(new DomainName("the coms", ".onedomain.com"));

        http->setDynamicAllocatedMemory(true);

        Packet packet1(pkt1, length1);
        Packet packet2(pkt2, length2);
        Packet packet3(pkt3, length3);
        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());
        auto flow3 = SharedPointer<Flow>(new Flow());

        http->setDomainNameManager(host_mng);
        host_mng->addDomainName(d1);
        host_mng->addDomainName(dall);

        flow1->packet = const_cast<Packet*>(&packet1);
        flow2->packet = const_cast<Packet*>(&packet2);
        flow3->packet = const_cast<Packet*>(&packet3);

        // Inject the three flows
        http->processFlow(flow1.get());
        http->processFlow(flow2.get());
        http->processFlow(flow3.get());

        SharedPointer<HTTPInfo> info1 = flow1->getHTTPInfo();
        SharedPointer<HTTPInfo> info2 = flow2->getHTTPInfo();
        SharedPointer<HTTPInfo> info3 = flow3->getHTTPInfo();
        BOOST_CHECK(info1 != nullptr);
        BOOST_CHECK(info2 != nullptr);
        BOOST_CHECK(info3 != nullptr);
        BOOST_CHECK(dall->getMatchs() == 0);
        BOOST_CHECK(d1->getMatchs() == 3);
}
        
BOOST_AUTO_TEST_CASE (test12) // split header 
{
        Packet packet("../http/packets/packet13.pcap");

        http->setDynamicAllocatedMemory(true);

        inject(packet);

        BOOST_CHECK(http->getTotalGets() == 1);
        BOOST_CHECK(http->getTotalPosts() == 0);
        BOOST_CHECK(http->getTotalHeads() == 0);
        BOOST_CHECK(http->getTotalConnects() == 0);
        BOOST_CHECK(http->getTotalOptions() == 0);
        BOOST_CHECK(http->getTotalPuts() == 0);
        BOOST_CHECK(http->getTotalDeletes() == 0);
        BOOST_CHECK(http->getTotalTraces() == 0);

        Flow *flow = http->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->ua != nullptr);
        BOOST_CHECK(info->uri != nullptr);
        BOOST_CHECK(info->ct == nullptr);

        std::string host("b.huffingtonpost.com");
        std::string ct("text/html");
        std::string ua("Mozilla/5.0 (Windows NT 6.1; rv:53.0) Gecko/20100101 Firefox/53.0");
        std::string uris("/click?ts="); // head of uri
	std::string urie("inYP=27&pgvis=1"); // tail of uri
	std::string uri(info->uri->getName());

        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
	BOOST_CHECK(uri.compare(0, uris.length(), uris) == 0);
	BOOST_CHECK(uri.compare(uri.length() - urie.length(), urie.length(), urie) == 0);
       	BOOST_CHECK(ua.compare(info->ua->getName()) == 0);
}
                                                      
BOOST_AUTO_TEST_CASE (test13) // split header 
{
        Packet packet("../http/packets/packet14.pcap");

        http->setDynamicAllocatedMemory(true);

        inject(packet);

        BOOST_CHECK(http->getTotalGets() == 1);
        BOOST_CHECK(http->getTotalPosts() == 0);
        BOOST_CHECK(http->getTotalHeads() == 0);
        BOOST_CHECK(http->getTotalConnects() == 0);
        BOOST_CHECK(http->getTotalOptions() == 0);
        BOOST_CHECK(http->getTotalPuts() == 0);
        BOOST_CHECK(http->getTotalDeletes() == 0);
        BOOST_CHECK(http->getTotalTraces() == 0);

        Flow *flow = http->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->ua != nullptr);
        BOOST_CHECK(info->uri != nullptr);
        BOOST_CHECK(info->ct == nullptr);

        std::string host("b.scorecardresearch.com");
        std::string ct("text/html");
        std::string ua("Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.107 Safari/537.36");
        std::string uris("/p?c1=2&c2=7241469&ns_site=yahoo-video"); // head of uri
        std::string urie("limelight&y_ap=1"); // tail of uri
        std::string uri(info->uri->getName());

        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(uri.compare(0, uris.length(), uris) == 0);
        BOOST_CHECK(uri.compare(uri.length() - urie.length(), urie.length(), urie) == 0);
        BOOST_CHECK(ua.compare(info->ua->getName()) == 0);
}
 
BOOST_AUTO_TEST_SUITE_END()
