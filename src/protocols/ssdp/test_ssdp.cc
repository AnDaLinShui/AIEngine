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
#include "test_ssdp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE ssdptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(ssdp_test_suite, StackSSDPtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

	BOOST_CHECK(ssdp->getTotalEvents() == 0);
	BOOST_CHECK(ssdp->getTotalPackets() == 0); 
	BOOST_CHECK(ssdp->getTotalBytes() == 0); 
	BOOST_CHECK(ssdp->getTotalValidPackets() == 0); 
	BOOST_CHECK(ssdp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(ssdp->processPacket(packet) == true);

	CounterMap c = ssdp->getCounters();
        
	BOOST_CHECK(ssdp->getTotalNotifies() == 0);
        BOOST_CHECK(ssdp->getTotalMSearchs() == 0);
        BOOST_CHECK(ssdp->getTotalSubscribes() == 0);
        BOOST_CHECK(ssdp->getTotalSSDPPs() == 0); 
}

BOOST_AUTO_TEST_CASE (test02)
{
        char *header =  "M-SEARCH * HTTP/1.1\r\n"
                        "Host: 239.255.255.250:1900\r\n"
                        "ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                        "Man:\"ssdp:discover\"\r\n"
                        "MX:3\r\n"
                        "\r\n";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);

        Packet packet(pkt, length);
        auto flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        ssdp->processFlow(flow.get());

        auto info = flow->getSSDPInfo();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->uri != nullptr);

        std::string host("239.255.255.250:1900");
        std::string uri("*");

        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);

	BOOST_CHECK(info->getTotalRequests() == 1);
	BOOST_CHECK(info->getTotalResponses() == 0);
	BOOST_CHECK(info->getResponseCode() == 0);
	BOOST_CHECK(ssdp->getTotalEvents() == 0);
	BOOST_CHECK(ssdp->getTotalValidPackets() == 0); // Can not be validated :)
	BOOST_CHECK(ssdp->getTotalInvalidPackets() == 0);
        
	BOOST_CHECK(ssdp->getTotalMSearchs() == 1);
}

BOOST_AUTO_TEST_CASE (test03)
{
        char *header =  "NOTIFY * HTTP/1.1\r\n"
                        "HOST: 239.255.255.250:1900\r\n"
                        "CACHE-CONTROL: max-age=3000\r\n"
                        "LOCATION: http://192.168.25.1:5431/igdevicedesc.xml\r\n"
                        "SERVER: UPnP/1.0 BLR-TX4S/1.0\r\n"
                        "NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                        "USN: uuid:f5c1d177-62e5-45d1-a6e7-c0a0bb0fc2ce::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                        "NTS: ssdp:alive\r\n"
                        "\r\n";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);

        Packet packet(pkt, length);
        auto flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        ssdp->processFlow(flow.get());

        SharedPointer<SSDPInfo> info = flow->getSSDPInfo();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->uri != nullptr);

        std::string host("239.255.255.250:1900");
        std::string uri("*");

        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);

        BOOST_CHECK(info->getTotalRequests() == 1);
        BOOST_CHECK(info->getTotalResponses() == 0);
        BOOST_CHECK(info->getResponseCode() == 0);
	BOOST_CHECK(ssdp->getTotalEvents() == 0);
	
	BOOST_CHECK(ssdp->getTotalNotifies() == 1);
}

BOOST_AUTO_TEST_CASE (test04)
{
        char *request = "M-SEARCH * HTTP/1.1\r\n"
                        "HOST: 239.255.255.250:1900\r\n"
                        "MAN: \"ssdp:discover\"\r\n"
                        "ST: upnp:rootdevice\r\n"
                        "MX: 3\r\n"
                        "\r\n";

	char *response ="HTTP/1.1 200 OK\r\n"
                        "CACHE-CONTROL:max-age=1800\r\n"
                        "EXT:\r\n"
                        "LOCATION:http://192.168.1.254:80/upnp/IGD.xml\r\n"
                        "SERVER:SpeedTouch BTHH 6.2.6.H UPnP/1.0 (00-14-7F-BF-24-B5)\r\n"
                        "ST:upnp:rootdevice\r\n"
                        "USN:uuid:UPnP_SpeedTouchBTHH-1_00-14-7F-BF-24-B5::upnp:rootdevice\r\n"
                        "\r\n";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (request);
        int length = strlen(request);

        Packet packet_req(pkt, length);
        auto flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet_req);
        ssdp->processFlow(flow.get());

	pkt = reinterpret_cast <uint8_t*> (response);
	length = strlen(response);

	Packet packet_res(pkt, length);
        flow->packet = const_cast<Packet*>(&packet_res);
        ssdp->processFlow(flow.get());

        SharedPointer<SSDPInfo> info = flow->getSSDPInfo();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->uri != nullptr);

        std::string host("239.255.255.250:1900");
        std::string uri("*");

        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);

        BOOST_CHECK(info->getTotalRequests() == 1);
        BOOST_CHECK(info->getTotalResponses() == 1);
        BOOST_CHECK(info->getResponseCode() == 200);
}

BOOST_AUTO_TEST_CASE (test05)
{
        char *request = "SUBSCRIBE dude HTTP/1.1\r\n"
                        "Host: iamthedude:203\r\n"
                        "NT: <upnp:toaster>\r\n"
                        "Callback: <http://blah/bar:923>\r\n"
                        "Scope: <http://iamthedude/dude:203>\r\n"
                        "Timeout: Infinite\r\n"
                        "\r\n";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (request);
        int length = strlen(request);

        Packet packet(pkt, length);
        auto flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        ssdp->processFlow(flow.get());

        SharedPointer<SSDPInfo> info = flow->getSSDPInfo();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->uri != nullptr);

        std::string host("iamthedude:203");
        std::string uri("dude");

        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);

        BOOST_CHECK(info->getTotalRequests() == 1);
        BOOST_CHECK(info->getTotalResponses() == 0);
        BOOST_CHECK(info->getResponseCode() == 0);
	BOOST_CHECK(ssdp->getTotalEvents() == 0);
        
	BOOST_CHECK(ssdp->getTotalSubscribes() == 1);
}

BOOST_AUTO_TEST_CASE (test06)
{
        char *request = "SUBSCRIBE /one/resource HTTP/1.1\r\n"
                        "Host: iamthedude:203\r\n"
                        "NT: <upnp:toaster>\r\n"
                        "Callback: <http://blah/bar:923>\r\n"
                        "Scope: <http://iamthedude/dude:203>\r\n"
                        "Timeout: Infinite\r\n"
                        "\r\n";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (request);
        int length = strlen(request);
        Packet packet(pkt, length);
        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());

        flow1->packet = const_cast<Packet*>(&packet);
        flow2->packet = const_cast<Packet*>(&packet);
        ssdp->processFlow(flow1.get());
        ssdp->processFlow(flow2.get());

        SharedPointer<SSDPInfo> info1 = flow1->getSSDPInfo();
        SharedPointer<SSDPInfo> info2 = flow2->getSSDPInfo();

        BOOST_CHECK(info1 != nullptr);
        BOOST_CHECK(info2 != nullptr);
        BOOST_CHECK(info1->host_name == info2->host_name);
        BOOST_CHECK(info1->uri == info2->uri);

	// some outputs
        std::filebuf fb;
        fb.open ("/dev/null",std::ios::out);
        std::ostream outp(&fb);
        outp << *info1.get();
        flow1->serialize(outp);
        flow1->showFlowInfo(outp);
        fb.close();

        JsonFlow j;
        info1->serialize(j);
}

BOOST_AUTO_TEST_CASE (test07) // memory failure
{
        char *request = "SUBSCRIBE /one/resource HTTP/1.1\r\n"
                        "Host: iamthedude:203\r\n"
                        "NT: <upnp:toaster>\r\n"
                        "Callback: <http://blah/bar:923>\r\n"
                        "Scope: <http://iamthedude/dude:203>\r\n"
                        "Timeout: Infinite\r\n"
                        "\r\n";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (request);
        int length = strlen(request);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

	ssdp->decreaseAllocatedMemory(100);

        flow->packet = const_cast<Packet*>(&packet);
        ssdp->processFlow(flow.get());

        SharedPointer<SSDPInfo> info = flow->getSSDPInfo();
        BOOST_CHECK(info == nullptr);
}

BOOST_AUTO_TEST_CASE (test08) // The method dont exits
{
        char *response ="MAFORMED_HTTP/1.1 200 OK\r\n"
                        "CACHE-CONTROL:max-age=1800\r\n"
                        "EXT:\r\n"
                        "LOCATION:http://192.168.1.254:80/upnp/IGD.xml\r\n"
                        "SERVER:SpeedTouch BTHH 6.2.6.H UPnP/1.0 (00-14-7F-BF-24-B5)\r\n"
                        "ST:upnp:rootdevice\r\n"
                        "USN:uuid:UPnP_SpeedTouchBTHH-1_00-14-7F-BF-24-B5::upnp:rootdevice\r\n"
                        "\r\n";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (response);
        int length = strlen(response);

        Packet packet(pkt, length);
        auto flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        ssdp->processFlow(flow.get());

        SharedPointer<SSDPInfo> info = flow->getSSDPInfo();
        BOOST_CHECK(info != nullptr);
}

BOOST_AUTO_TEST_CASE (test09) // match a given domain
{
        char *header =  "M-SEARCH * HTTP/1.1\r\n"
                        "Host: 239.255.255.250:1900\r\n"
                        "ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                        "Man:\"ssdp:discover\"\r\n"
                        "MX:3\r\n"
                        "\r\n";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
	auto dom = SharedPointer<DomainName>(new DomainName("bu", "239.255.255.250:1900"));
	auto dm = SharedPointer<DomainNameManager>(new DomainNameManager());

	dm->addDomainName(dom);

	ssdp->setDomainNameManager(dm);

        Packet packet(pkt, length);
        auto flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        ssdp->processFlow(flow.get());

        auto info = flow->getSSDPInfo();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->uri != nullptr);
	BOOST_CHECK(info->matched_domain_name == dom);
        std::string host("239.255.255.250:1900");
        std::string uri("*");

        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);

        BOOST_CHECK(info->getTotalRequests() == 1);
        BOOST_CHECK(info->getTotalResponses() == 0);
        BOOST_CHECK(info->getResponseCode() == 0);
        BOOST_CHECK(ssdp->getTotalEvents() == 1);

        // some outputs
        std::filebuf fb;
        fb.open ("/dev/null",std::ios::out);
        std::ostream outp(&fb);
        outp << *info.get();
        flow->serialize(outp);
        flow->showFlowInfo(outp);
        fb.close();

        JsonFlow j;
        info->serialize(j);
}

BOOST_AUTO_TEST_CASE (test10) // SSDPC message
{
        char *header =  "SSDPC * HTTP/1.1\r\n"
                        "Host: 239.255.255.250:1900\r\n"
                        "PN: 0.001\r\n"
                        "USN: someunique:idscheme3\r\n"
                        "\r\n";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);
        auto flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        ssdp->processFlow(flow.get());

        auto info = flow->getSSDPInfo();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->uri != nullptr);
	BOOST_CHECK(info->matched_domain_name == nullptr);
        std::string host("239.255.255.250:1900");
        std::string uri("*");

        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);

        BOOST_CHECK(info->getTotalRequests() == 1);
        BOOST_CHECK(info->getTotalResponses() == 0);
        BOOST_CHECK(info->getResponseCode() == 0);
        BOOST_CHECK(ssdp->getTotalEvents() == 0);
        BOOST_CHECK(ssdp->getTotalSSDPPs() == 1); 
}

BOOST_AUTO_TEST_SUITE_END( )

