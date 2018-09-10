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
#include <string>
#include <fstream>
#include "Packet.h"
#include "RegexManager.h"
#include "Regex.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE regextest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_AUTO_TEST_SUITE(regex_suite)

BOOST_AUTO_TEST_CASE (test01)
{
	auto rm = RegexManagerPtr(new RegexManager());

	BOOST_CHECK(rm->getTotalRegexs() == 0);
	BOOST_CHECK(rm->getTotalMatchingRegexs() == 0);
	BOOST_CHECK(rm->getMatchedRegex() == nullptr);
}

BOOST_AUTO_TEST_CASE (test02)
{
	auto rm = RegexManagerPtr(new RegexManager());

	rm->addRegex("hello", "^hello.*$");
        BOOST_CHECK(rm->getTotalRegexs()  == 1);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 0);
        BOOST_CHECK(rm->getMatchedRegex() == nullptr);

	boost::string_ref buffer("hello world");
	bool value = false;

	rm->evaluate(buffer,&value);
	BOOST_CHECK(value == true);
	BOOST_CHECK(rm->getMatchedRegex() != nullptr);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 1);
}

BOOST_AUTO_TEST_CASE (test03)
{
        auto rm = RegexManagerPtr(new RegexManager());
	auto r = SharedPointer<Regex>(new Regex("name", "^.*(some hex).*$"));

	BOOST_CHECK(r->getShowPacket() == false);
	BOOST_CHECK(r.use_count() == 1);

        rm->addRegex(r);
	BOOST_CHECK(r.use_count() == 2);
        BOOST_CHECK(rm->getTotalRegexs()  == 1);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 0);
        BOOST_CHECK(rm->getMatchedRegex() == nullptr);

        boost::string_ref buffer("hello world im not a hex, but some hex yes");
        bool value = false;

        rm->evaluate(buffer,&value);
        BOOST_CHECK(value == true);
        BOOST_CHECK(rm->getMatchedRegex() != nullptr);
        BOOST_CHECK(rm->getMatchedRegex().get() != nullptr);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 1);

	std::string exp_mng(rm->getMatchedRegex()->getExpression());
	std::string exp_sig(r->getExpression());
	BOOST_CHECK(exp_sig.compare(exp_mng)== 0);
	BOOST_CHECK(r.use_count() == 3);
}

BOOST_AUTO_TEST_CASE (test04)
{
        auto rm = RegexManagerPtr(new RegexManager());
	auto r1 = SharedPointer<Regex>(new Regex("name1", "^.*(some hex).*$"));
	auto r2 = SharedPointer<Regex>(new Regex("name2", "^.*(some hex).*$"));

	BOOST_CHECK(r1->isTerminal() == true);
	BOOST_CHECK(r2->isTerminal() == true);

	r1->setNextRegex(r2);

	BOOST_CHECK(r1->isTerminal() == false);
	BOOST_CHECK(r2->isTerminal() == true);

	BOOST_CHECK(r1->getNextRegex() == r2);

        rm->addRegex(r1);
        rm->addRegex(r2);
}

BOOST_AUTO_TEST_CASE (test05)
{
        auto rm = RegexManagerPtr(new RegexManager());
	auto re1 = SharedPointer<Regex>(new Regex("name1", "^.*\xaa\xbb\xff\xff.*$"));
	auto re2 = SharedPointer<Regex>(new Regex("name2", "^.*\xee$"));
	uint8_t buffer1[] = "\x00\x00\x00\xaa\xbb\xcc\xdd";
	uint8_t buffer2[] = "\x00\x00\x00\xaa\xbb\x00\x00\xcc\xdd";
	uint8_t buffer3[] = "\x00\x00\x00\xaa\xbb\x00\x00\xcc\xdd\xaa\xbb\x00\x00\x00\x00\xff\xff";
	uint8_t buffer4[] = "\x00\x00\x00\xaa\xbb\x00\x00\xcc\xdd\xaa\xaa\xff\xff\x00\x00\xff\xff\xee";
	bool value;

        rm->addRegex(re1);
        rm->addRegex(re2);

        value = false;
	boost::string_ref data1(reinterpret_cast<const char*>(buffer1), 6);
        rm->evaluate(data1, &value);
        BOOST_CHECK(value == false);
        BOOST_CHECK(rm->getMatchedRegex() == nullptr);

	// Check the regex status
	BOOST_CHECK(re1->getMatchs() == 0);
	BOOST_CHECK(re2->getMatchs() == 0);
	BOOST_CHECK(re1->getTotalEvaluates() == 1);
	BOOST_CHECK(re2->getTotalEvaluates() == 1);

	value = false;
	boost::string_ref data2(reinterpret_cast<const char*>(buffer2), 9);
        rm->evaluate(data2, &value);
        BOOST_CHECK(value == false);
        BOOST_CHECK(rm->getMatchedRegex() == nullptr);
	
	// Check the regex status
	BOOST_CHECK(re1->getMatchs() == 0);
	BOOST_CHECK(re2->getMatchs() == 0);
	BOOST_CHECK(re1->getTotalEvaluates() == 2);
	BOOST_CHECK(re2->getTotalEvaluates() == 2);

	value = false;
	boost::string_ref data3(reinterpret_cast<const char*>(buffer3), 17);
        rm->evaluate(data3, &value);
        BOOST_CHECK(value == false);
        BOOST_CHECK(rm->getMatchedRegex() == nullptr);

	// Check the regex status
	BOOST_CHECK(re1->getMatchs() == 0);
	BOOST_CHECK(re2->getMatchs() == 0);
	BOOST_CHECK(re1->getTotalEvaluates() == 3);
	BOOST_CHECK(re2->getTotalEvaluates() == 3);

	value = false;
	boost::string_ref data4(reinterpret_cast<const char*>(buffer4), 18);
        rm->evaluate(data4, &value);
        BOOST_CHECK(value == true);
        BOOST_CHECK(rm->getMatchedRegex() == re2);
	
	// Check the regex status
	BOOST_CHECK(re1->getMatchs() == 0);
	BOOST_CHECK(re2->getMatchs() == 1);
	BOOST_CHECK(re1->getTotalEvaluates() == 4);
	BOOST_CHECK(re2->getTotalEvaluates() == 4);
}

BOOST_AUTO_TEST_CASE (test06)
{
	uint8_t buffer_text[] = 
		"\x69\x74\x73\x20\x70\x65\x61\x6e\x75\x74\x20\x62\x75\x74\x74\x65"
		"\x72\x20\x26\x20\x73\x65\x6d\x65\x6d\x20\x74\x69\x6d\x65\x0a";
        auto rm = RegexManagerPtr(new RegexManager());
	auto r1 = SharedPointer<Regex>(new Regex("r1", "^(its peanut).*$"));
	auto r2 = SharedPointer<Regex>(new Regex("r2", "^.*(its peanut).*$"));

        rm->addRegex(r1);

        bool value = false;
	Packet packet("../protocols/ip6/packets/packet09.pcap");

	const char *dataptr = reinterpret_cast<const char*>(packet.getPayload());

        boost::string_ref data1(dataptr, packet.getLength());
        boost::string_ref data2(reinterpret_cast<const char*>(buffer_text), 31);

        rm->evaluate(data1, &value);
        BOOST_CHECK(value == false);
        BOOST_CHECK(rm->getMatchedRegex() == nullptr);

        rm->evaluate(data2, &value);
        BOOST_CHECK(value == true);
        BOOST_CHECK(rm->getMatchedRegex() == r1);
	
        rm->addRegex(r2);
        
	rm->evaluate(data1, &value);
        BOOST_CHECK(value == true);
        BOOST_CHECK(rm->getMatchedRegex() == r2);
}

BOOST_AUTO_TEST_CASE (test07)
{
	std::string text1("GET some/data/i/want/to/retrieve HTTP");
	std::string text2("GET data/leches/retrieve/adios HTTP\r\ny mucho mas");
        auto r1 = SharedPointer<Regex>(new Regex("r1", "^GET .* HTTP$"));
        auto r2 = SharedPointer<Regex>(new Regex("r2", "^.*data.*retrieve.*$"));

	bool value = r1->matchAndExtract(text1);
	BOOST_CHECK(value == true);
	BOOST_CHECK(text1.compare(r1->getExtract()) == 0);
	
	value = r2->matchAndExtract(text1);
	BOOST_CHECK(value == true);
	BOOST_CHECK(text1.compare(r2->getExtract()) == 0);
	
	value = r1->matchAndExtract(text2);
	BOOST_CHECK( value == false);
	
	value = r2->matchAndExtract(text2);
	BOOST_CHECK(value == true);
	BOOST_CHECK(text2.compare(r2->getExtract()) == 0);
}

BOOST_AUTO_TEST_CASE (test08)
{
        boost::string_ref text("GET some/data/i/want/to/retrieve HTTP");
        auto rm = RegexManagerPtr(new RegexManager());
        auto r = SharedPointer<Regex>(new Regex("r1", "^GET .* HTTP$"));
	bool result = false;

	rm->addRegex(r);
	rm->evaluate(text, &result);

        BOOST_CHECK(result == true);

        std::streambuf* oldCout = std::cout.rdbuf();
        std::ostringstream strCout;

        std::cout.rdbuf(strCout.rdbuf());
        rm->statistics();
        rm->statistics("r1");
        rm->statistics("r2");
        std::cout.rdbuf(oldCout);
}

BOOST_AUTO_TEST_CASE (test09)
{
        uint8_t buffer_text[] =
                "\x69\x74\x73\x20\x70\x65\x61\x6e\x75\x74\x20\x62\x75\x74\x74\x65"
                "\x72\x20\x26\x20\x73\x65\x6d\x65\x6d\x20\x74\x69\x6d\x65\x0a";
        auto rm = RegexManagerPtr(new RegexManager());
        auto r1 = SharedPointer<Regex>(new Regex("r1", "^(its peanut).*$"));
        auto r2 = SharedPointer<Regex>(new Regex("r2", "^.*(its peanut).*$"));

        rm->addRegex(r1);

	Packet packet("../protocols/ip6/packets/packet09.pcap");

	const char *dataptr = reinterpret_cast<const char*>(packet.getPayload());

	boost::string_ref data1(dataptr, packet.getLength());
        bool value = false;
        boost::string_ref data2(reinterpret_cast<const char*>(buffer_text), 31);

        rm->evaluate(data1, &value);
        BOOST_CHECK(value == false);
        BOOST_CHECK(rm->getMatchedRegex() == nullptr);

        rm->evaluate(data2, &value);
        BOOST_CHECK(value == true);
        BOOST_CHECK(rm->getMatchedRegex() == r1);

        rm->addRegex(r2);

        rm->evaluate(data1, &value);
        BOOST_CHECK(value == true);
        BOOST_CHECK(rm->getMatchedRegex() == r2);
}

BOOST_AUTO_TEST_CASE (test10)
{
        auto r1 = SharedPointer<Regex>(new Regex("r1", "^(its peanut).*$"));
        auto r2 = SharedPointer<Regex>(new Regex("r2", "^.*(its peanut).*$"));
        auto r3 = SharedPointer<Regex>(new Regex("r2", "^.*(its peanut).*$"));
        auto r4 = SharedPointer<Regex>(new Regex("other", "^.*(its peanut).*$"));
        auto r5 = SharedPointer<Regex>(new Regex("other r5", "^.*(its peanut).*$"));

        auto rm = RegexManagerPtr(new RegexManager());

	rm->addRegex(r1);
	rm->addRegex(r2);
	rm->addRegex(r3);
	rm->addRegex(r4);
	rm->addRegex(r5);
	rm->addRegex(r5);

	BOOST_CHECK(rm->getTotalRegexs() == 6);
	BOOST_CHECK(r1.use_count() == 2);
	BOOST_CHECK(r2.use_count() == 2);
	BOOST_CHECK(r3.use_count() == 2);
	BOOST_CHECK(r4.use_count() == 2);
	BOOST_CHECK(r5.use_count() == 3);

	// Remove two regex
	rm->removeRegex("r2", "^.*(its peanut).*$");
	
	BOOST_CHECK(rm->getTotalRegexs() == 4);
	BOOST_CHECK(r1.use_count() == 2);
	BOOST_CHECK(r2.use_count() == 1);
	BOOST_CHECK(r3.use_count() == 1);
	BOOST_CHECK(r4.use_count() == 2);
	BOOST_CHECK(r5.use_count() == 3);

	// Remove one regex that have been added two times
	rm->removeRegex(r5);

	BOOST_CHECK(rm->getTotalRegexs() == 2);
	BOOST_CHECK(r1.use_count() == 2);
	BOOST_CHECK(r2.use_count() == 1);
	BOOST_CHECK(r3.use_count() == 1);
	BOOST_CHECK(r4.use_count() == 2);
	BOOST_CHECK(r5.use_count() == 1);
}

BOOST_AUTO_TEST_CASE (test11)
{
        auto r1 = SharedPointer<Regex>(new Regex("r1", "^(its peanut).*$"));
        auto r2 = SharedPointer<Regex>(new Regex("r2", "^.*(its peanut).*$"));
        auto r3 = SharedPointer<Regex>(new Regex("r2", "^.*(its peanut).*$"));
        auto r4 = SharedPointer<Regex>(new Regex("other", "^.*(its peanut).*$"));
        auto r5 = SharedPointer<Regex>(new Regex("other r5", "^.*(its peanut).*$"));

        auto rm = RegexManagerPtr(new RegexManager());

	r1->setNextRegex(r2);
	r3->setNextRegex(r4); r4->setNextRegex(r5);

        rm->addRegex(r1);
        rm->addRegex(r3);

        BOOST_CHECK(rm->getTotalRegexs() == 2);
        BOOST_CHECK(r1.use_count() == 2);
        BOOST_CHECK(r2.use_count() == 2);
        BOOST_CHECK(r3.use_count() == 2);
        BOOST_CHECK(r4.use_count() == 2);
        BOOST_CHECK(r5.use_count() == 2);

	// Remove one regex
        rm->removeRegex("r2", "^.*(its peanut).*$");

        BOOST_CHECK(rm->getTotalRegexs() == 1);
        BOOST_CHECK(r1.use_count() == 2);
        BOOST_CHECK(r2.use_count() == 2);
        BOOST_CHECK(r3.use_count() == 1);
        BOOST_CHECK(r4.use_count() == 2);
        BOOST_CHECK(r5.use_count() == 2);

	// re4 dont exists on the manager is just linked to another regex
        rm->removeRegex(r4);

        BOOST_CHECK(rm->getTotalRegexs() == 1);
        BOOST_CHECK(r1.use_count() == 2);
        BOOST_CHECK(r2.use_count() == 2);
        BOOST_CHECK(r3.use_count() == 1);
        BOOST_CHECK(r4.use_count() == 2);
        BOOST_CHECK(r5.use_count() == 2);
}

BOOST_AUTO_TEST_CASE (test12)
{
        auto r1 = SharedPointer<Regex>(new Regex("r1", "^(its peanut).*$"));
        auto r2 = SharedPointer<Regex>(new Regex("r2", "^.*(its peanut).*$"));
        auto r3 = SharedPointer<Regex>(new Regex("r2", "^.*(its peanut).*$"));
        auto r4 = SharedPointer<Regex>(new Regex("other", "^.*(its peanut).*$"));
        auto r5 = SharedPointer<Regex>(new Regex("other r5", "^.*(its peanut).*$"));

        auto rm = RegexManagerPtr(new RegexManager());

	rm->addRegex(r1);
	rm->addRegex(r2);
	rm->addRegex(r3);

	auto r6 = r1;
	
	rm->addRegex("other more", "bu bu");

        BOOST_CHECK(rm->getTotalRegexs() == 4);
        BOOST_CHECK(r1.use_count() == 3);
        BOOST_CHECK(r2.use_count() == 2);
        BOOST_CHECK(r3.use_count() == 2);
        BOOST_CHECK(r4.use_count() == 1);
        BOOST_CHECK(r5.use_count() == 1);

	rm.reset();

	BOOST_CHECK(rm == nullptr);
        BOOST_CHECK(r1.use_count() == 2);
        BOOST_CHECK(r2.use_count() == 1);
        BOOST_CHECK(r3.use_count() == 1);
}

BOOST_AUTO_TEST_CASE (test13)
{
        auto r1 = SharedPointer<Regex>(new Regex("r1", "^(its peanut).*$"));
        auto r2 = SharedPointer<Regex>(new Regex("r2", "^.*(its peanut).*$", r1));
        auto r3 = SharedPointer<Regex>(new Regex("r2", "^.*(its peanut).*$", r2));

	BOOST_CHECK(r1->isTerminal() == true);
	BOOST_CHECK(r2->isTerminal() == false);	
	BOOST_CHECK(r3->isTerminal() == false);	
}

BOOST_AUTO_TEST_CASE (test14) // Exercise the screen outputs
{
        auto rm1 = RegexManagerPtr(new RegexManager());
        auto rm2 = RegexManagerPtr(new RegexManager());
        auto r1 = SharedPointer<Regex>(new Regex("r1", "^(its peanut).*$"));
        auto r2 = SharedPointer<Regex>(new Regex("r2", "^.*(its peanut).*$", r1));
        auto r3 = SharedPointer<Regex>(new Regex("r3", "^.*(its peanut).*$", r2));
        auto r4 = SharedPointer<Regex>(new Regex("r4", "^.*(its peanut).*$", r3));

	rm1->addRegex(r3);
	rm2->addRegex(r4);
	
        std::filebuf fb;
        fb.open ("/dev/null", std::ios::out);
        std::ostream outp(&fb);

	outp << *rm1.get();
	outp << *rm2.get();
        fb.close();
        
	BOOST_CHECK(rm1.use_count() == 1);
        BOOST_CHECK(rm2.use_count() == 1);
        BOOST_CHECK(r1.use_count() == 2);
        BOOST_CHECK(r2.use_count() == 2);
        BOOST_CHECK(r3.use_count() == 3);
        BOOST_CHECK(r4.use_count() == 2);
}

BOOST_AUTO_TEST_CASE (test15) // Complex regexs
{
        auto rm1 = RegexManagerPtr(new RegexManager());
        auto rm2 = RegexManagerPtr(new RegexManager());

        auto r1 = SharedPointer<Regex>(new Regex("r1", "^(its peanut).*$"));
        auto r2 = SharedPointer<Regex>(new Regex("r2", "^.*(its peanut).*$", r1));
        auto r3 = SharedPointer<Regex>(new Regex("r3", "^.*(its peanut).*$", r2));
        auto r4 = SharedPointer<Regex>(new Regex("r4", "^.*(its peanut).*$", r3));
        auto r5 = SharedPointer<Regex>(new Regex("r5", "^.*(its peanut).*$"));

	BOOST_CHECK(rm1.use_count() == 1);
        BOOST_CHECK(rm2.use_count() == 1);
        BOOST_CHECK(r1.use_count() == 2);
        BOOST_CHECK(r2.use_count() == 2);
        BOOST_CHECK(r3.use_count() == 2);
        BOOST_CHECK(r4.use_count() == 1);
        BOOST_CHECK(r5.use_count() == 1);

	rm1->addRegex(r4);

        BOOST_CHECK(r4.use_count() == 2);

	r1->setNextRegexManager(rm2);
        
	BOOST_CHECK(rm2.use_count() == 2);

        std::filebuf fb;
        fb.open ("/dev/null", std::ios::out);
        std::ostream outp(&fb);

	outp << *rm1.get();
	outp << *rm2.get();
        fb.close();
	
	BOOST_CHECK(rm1.use_count() == 1);
        BOOST_CHECK(rm2.use_count() == 2);
        BOOST_CHECK(r1.use_count() == 2);
        BOOST_CHECK(r2.use_count() == 2);
        BOOST_CHECK(r3.use_count() == 2);
        BOOST_CHECK(r4.use_count() == 2);
        BOOST_CHECK(r5.use_count() == 1);
}

class my_exception{};

BOOST_AUTO_TEST_CASE (test16) // Test incorrect regex that throw exceptions
{
	std::string errorstr("missing terminating ] for character class");

        auto rm = RegexManagerPtr(new RegexManager());

	try {
        	auto r = SharedPointer<Regex>(new Regex("r1", "\x03[[^^^^$(its peanut).*$"));
	} catch (const char *msg) {
		BOOST_CHECK(errorstr.compare(msg) == 0);
	}

	try {
        	rm->addRegex("r2", "\x03[[^^^^$(its peanut).*$");
	} catch (const char *msg) {
		BOOST_CHECK(errorstr.compare(msg) == 0);
	}
	BOOST_CHECK(rm->getTotalRegexs() == 0);
}

BOOST_AUTO_TEST_SUITE_END( )

