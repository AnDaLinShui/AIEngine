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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <fstream>
#include <iostream>
#include <functional>
#include <cctype>
#include <csignal>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <fstream>
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#include "log4cxx/basicconfigurator.h"
#endif
#include "PacketDispatcher.h"
#include "protocols/frequency/FrequencyGroup.h"
#include "learner/LearnerEngine.h"
#include "System.h"
#include "StackLan.h"
#include "StackMobile.h"
#include "StackLanIPv6.h"
#include "StackVirtual.h"
#include "StackOpenFlow.h"
#include "StackMobileIPv6.h"
#include <boost/date_time/posix_time/posix_time_io.hpp>

using namespace aiengine;

#ifdef HAVE_LIBLOG4CXX
using namespace log4cxx;
using namespace log4cxx::helpers;
#endif

aiengine::SystemPtr system_stats;
aiengine::PacketDispatcherPtr pktdis;
aiengine::NetworkStackPtr stack;
aiengine::RegexManagerPtr sm;
aiengine::FrequencyGroup<std::string> group;
aiengine::LearnerEngine learner;

/* Factory of NetworkStacks implemented with lambdas */
std::map<std::string, std::function<aiengine::NetworkStackPtr()>> stack_factory {
	{ "lan",	[](){return aiengine::NetworkStackPtr(new aiengine::StackLan()); }},
	{ "mobile",	[](){return aiengine::NetworkStackPtr(new aiengine::StackMobile()); }},
	{ "lan6",	[](){return aiengine::NetworkStackPtr(new aiengine::StackLanIPv6()); }},
	{ "virtual",	[](){return aiengine::NetworkStackPtr(new aiengine::StackVirtual()); }},
	{ "oflow",	[](){return aiengine::NetworkStackPtr(new aiengine::StackOpenFlow()); }},
	{ "mobile6",	[](){return aiengine::NetworkStackPtr(new aiengine::StackMobileIPv6()); }}
};

std::string option_link_type_tag;
std::string option_learner_key;
std::string option_stack_name;
std::string option_input;
std::string option_interface;
std::string option_freqs_group_value;
std::string option_freqs_type_flows;
std::string option_regex_type_flows;
std::vector<std::string> vector_regex;
std::string option_selected_protocols;
std::string option_release_cache_protocol;
std::string option_show_flows_name;
bool option_show_flows = false;
bool option_show_matched_regex = false;
bool option_show_matched_packet = false;
bool option_enable_frequencies = false;
bool option_enable_regex = false;
bool option_enable_learner = false;
bool option_show_pstatistics = false;
bool option_release_caches = false;
bool option_generate_yara = false;
bool option_reject_flows_regex = false;
bool option_enable_regex_evidence = false;
bool option_continue_regex = false;
bool option_show_protocol_summary = false;
bool option_keep_flows_in_memory = false;
int tcp_flows_cache = 0;
int udp_flows_cache = 0;
int option_statistics_level = 0;
int option_flows_timeout = FlowManager::flowTimeout;
int learner_buffer_size = LearnerEngine::maxBufferSize;
int learner_byte_quality = LearnerEngine::byteQuality;

void signalHandler(int signum) {

        exit(signum);
}

void signalHandlerShowStackStatistics(int signum) {

        boost::posix_time::ptime nowt = boost::posix_time::second_clock::local_time();
	boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
	static std::locale loc(std::cout.getloc(), new boost::posix_time::time_facet("%Y%m%d_%H%M%S"));
	std::basic_stringstream<char> ss;
	
	ss.imbue(loc);
	ss << "statistics.stack." << now << ".dat"; 

	std::ofstream outfile(ss.str());

        std::cout << "[" << nowt << "] ";
	std::cout << "Dumping stack information into " << ss.str() << std::endl;
	if (stack) 
	        if (option_statistics_level > 0)
                	stack->statistics(outfile);

	outfile.close();
}


void signalHandlerShowFlowsStatistics(int signum) {

        boost::posix_time::ptime nowt = boost::posix_time::second_clock::local_time();
        boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
        static std::locale loc(std::cout.getloc(), new boost::posix_time::time_facet("%Y%m%d_%H%M%S"));
        std::basic_stringstream<char> ss;

        ss.imbue(loc);
        ss << "flows.stack." << now << ".dat";

        std::ofstream outfile(ss.str());

        std::cout << "[" << nowt << "] ";
        std::cout << "Dumping flows information into " << ss.str() << std::endl;
        if (stack )
		stack->showFlows(outfile);

        outfile.close();
}

bool computeFrequencyGroup () {

	bool computed = false;
        FlowManagerPtr flow_t;

        if (option_freqs_type_flows.compare("tcp") == 0) flow_t = stack->getTCPFlowManager().lock();
        if (option_freqs_type_flows.compare("udp") == 0) flow_t = stack->getUDPFlowManager().lock();

        if (!flow_t) return computed;

	group.reset();

        if (option_freqs_group_value.compare("src-port") == 0) {
                group.setName("by source port");
                std::cout << "Aggregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsBySourcePort(flow_t);
              	computed = true; 
        }
        if (option_freqs_group_value.compare("dst-port") == 0) {
                group.setName("by destination port");
                std::cout << "Aggregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsByDestinationPort(flow_t);
              	computed = true; 
        }
        if (option_freqs_group_value.compare("src-ip") == 0) {
                group.setName("by source IP");
                std::cout << "Aggregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsBySourceAddress(flow_t);
              	computed = true; 
        }
        if (option_freqs_group_value.compare("dst-ip") == 0) {
                group.setName("by destination IP");
                std::cout << "Aggregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsByDestinationAddress(flow_t);
              	computed = true; 
        }
        if (option_freqs_group_value.compare("src-ip,src-port") == 0) {
                group.setName("by source IP and port");
                std::cout << "Aggregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsBySourceAddressAndPort(flow_t);
              	computed = true; 
        }
        if (option_freqs_group_value.compare("dst-ip,dst-port") == 0) {
                group.setName("by destination IP and port");
                std::cout << "Aggregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsByDestinationAddressAndPort(flow_t);
              	computed = true; 
        }

	if (computed) {
                std::cout << "Computing "<< group.getTotalProcessFlows() << " frequencies " << group.getName() << std::endl;
                group.compute();
	}

	return computed;
}

void showFrequencyResults() {

	if (computeFrequencyGroup()) {
		std::cout << group;
	} else {
		std::cout << "Can not compute the frequencies" << std::endl;
	}
}

void generateYaraRule(const char *regex, const char *keys) {

	boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();
	std::ostringstream out;

	out << "rule generated_by_aiengine {" << std::endl;
	out << "    meta:" << std::endl;
	out << "       author=\"aiengine\"" << std::endl;
	out << "       description=\"Flows generated on "<< keys << "\"" << std::endl;
	out << "       date=\""<< now.date().day() << "/" << static_cast<int>(now.date().month()) << "/" << now.date().year() << "\"" << std::endl;
	out << "    strings:" << std::endl;
	out << "       $a=\"" << regex << "\"" << std::endl;
	out << "    condition:" << std::endl;
	out << "       $a" << std::endl; // all of them , $a and $b, etc...
	out << "}" << std::endl;
	std::cout << out.str();
}

void showLearnerResults() {

	std::vector<WeakPointer<Flow>> flow_list;

	flow_list = group.getReferenceFlowsByKey(option_learner_key);
	if (flow_list.size() > 0) {
		learner.reset();
		learner.setMaxBufferSize(learner_buffer_size);
		std::cout << "Agregating "<< flow_list.size() << " to the LearnerEngine" << std::endl;
		learner.agregateFlows(flow_list);
		learner.setRegexByteQuality(learner_byte_quality);
		learner.compute();
		std::cout << "Regular expression generated with key:" << option_learner_key << " buffer size:" << learner_buffer_size;
		std::cout << " quality:" << learner_byte_quality << "%" << std::endl;
		std::cout << "Regex:" << learner.getRegularExpression() <<std::endl;
		std::cout << "Ascii buffer:" << learner.getAsciiExpression() << std::endl;	

		if (option_generate_yara) {
			std::cout << "Generating yara signature" << std::endl;
			generateYaraRule(learner.getRegularExpression().c_str(), option_learner_key.c_str());
		}
	}
}

void learnerCallback() {

	if (computeFrequencyGroup()) {
		showLearnerResults();
	}
}

void showStackStatistics() {

	pktdis->statistics();
	std::cout << std::endl;
       	if (option_statistics_level > 0) {
        	if (option_selected_protocols.length() > 0) {
			std::vector<std::string> items;
		
			boost::split(items, option_selected_protocols, boost::is_any_of(","));
		
			for (auto &p: items) {	
                		stack->statistics(p);
				std::cout << std::endl;
			}
               	} else {
                	stack->statistics();
               	}
       	}
}

void showAvailableStacks() {

	std::cout << "Available network stacks\n";
	for (auto &item: stack_factory) {
		std::cout << "\t" << item.first << std::endl;
	}
}


void aiengineExit() {

	if (stack) {
		pktdis->stop();

		showStackStatistics();

		if (option_show_flows) {
			if (option_show_flows_name.length() > 0)
				stack->showFlows(option_show_flows_name);
			else
              			stack->showFlows();
		}

		if (option_enable_frequencies) {
			showFrequencyResults();
			if (option_enable_learner)
				showLearnerResults();
		}

		if (option_release_caches) {
			stack->releaseCaches();
		} else { 
			if (option_release_cache_protocol.length() > 0) {
				stack->releaseCache(option_release_cache_protocol);
			}
		}

        	if (option_enable_regex) {
			sm->statistics();
			std::cout << std::endl;
        	}

		if (option_show_protocol_summary)
			stack->showProtocolSummary(std::cout);

		if (option_show_pstatistics)	
			if (system_stats)	
				system_stats->statistics();
       	}
	std::cout << "Exiting process" << std::endl;
}

void show_gpl_banner() {

	std::cout << "Please report bugs to <" << PACKAGE_BUGREPORT << ">" << std::endl;
	std::cout << "Copyright (C) 2013-2018 Luis Campo Giralte <" PACKAGE_BUGREPORT <<">" << std::endl;
	std::cout << "License: GNU GPL version 2" << std::endl;
	std::cout << "This is free software: you are free to change and redistribute it." << std::endl;
	std::cout << "There is NO WARRANTY, to the extent permitted by law." << std::endl;
}

void show_package_banner() {

	std::cout << "\tGCC version:" << __GNUG__ << "." << __GNUC_MINOR__ << "." << __GNUC_PATCHLEVEL__ << std::endl;
	std::cout << "\tPcap version:" << pcap_lib_version() << std::endl;
	std::cout << "\tPcre version:" << PCRE_MAJOR << "." << PCRE_MINOR << std::endl;;
	std::cout << "\tBoost version:" << BOOST_VERSION / 100000 << "." << BOOST_VERSION / 100 % 1000 << std::endl;
        std::cout << "\tStatic memory support:";
#if defined(HAVE_STATIC_MEMORY_CACHE)
        std::cout << "yes";
#else
        std::cout << "no";
#endif
        std::cout << std::endl;
}

int main(int argc, char* argv[]) {

	namespace po = boost::program_options;
	po::variables_map var_map;

	po::options_description mandatory_ops("Mandatory arguments");
	mandatory_ops.add_options()
		("input,i",   po::value<std::string>(&option_input),
			"Sets the network interface ,pcap file or directory with pcap files.")
        	;

        po::options_description optional_ops_tag("Link Layer optional arguments");
        optional_ops_tag.add_options()
                ("tag,q",    po::value<std::string>(&option_link_type_tag)->default_value(""),
                        "Selects the tag type of the ethernet layer (vlan, mpls, pppoe).")
                ;

	po::options_description optional_ops_tcp("TCP optional arguments");
	optional_ops_tcp.add_options()
		("tcp-flows,t",    po::value<int>(&tcp_flows_cache)->default_value(0),
		  	"Sets the number of TCP flows on the pool.")
		;
	
	po::options_description optional_ops_udp("UDP optional arguments");
	optional_ops_udp.add_options()
		("udp-flows,u",    	po::value<int>(&udp_flows_cache)->default_value(0),
		  			"Sets the number of UDP flows on the pool.")
		;

	po::options_description optional_ops_sigs("Regex optional arguments");
	optional_ops_sigs.add_options()
                ("enable-regex,R", 	"Enables the Regex engine.") 
		("regex,r",    		po::value<std::vector<std::string>>()->multitoken(),
		  			"Sets the regexs for evaluate agains the flows.")
                ("flow-class,c",  	po::value<std::string>(&option_regex_type_flows)->default_value("all"),
					"Uses tcp, udp or all for matches the signature on the flows.") 
                ("matched-flows,m",  	"Shows the flows that matchs with the regex.")
                ("matched-packet,M",  	"Shows the packet payload that matchs with the regex.")
                ("continue,C",  	"Continue evaluating the regex with the next packets of the Flow.")
                ("reject-flows,j",  	"Rejects the flows that matchs with the regex.")
                ("evidence,w",  	"Generates a pcap file with the matching regex for forensic analysis.")
		;

        po::options_description optional_ops_freq("Frequencies optional arguments");
        optional_ops_freq.add_options()
                ("enable-frequencies,F",  	"Enables the Frequency engine.") 
                ("group-by,g",  	po::value<std::string>(&option_freqs_group_value)->default_value("dst-port"),
					"Groups frequencies by src-ip, dst-ip, src-port and dst-port.") 
                ("flow-type,f",  	po::value<std::string>(&option_freqs_type_flows)->default_value("tcp"),
					"Uses tcp or udp flows.") 
                ("enable-learner,L",  	"Enables the Learner engine.") 
                ("key-learner,k",  	po::value<std::string>(&option_learner_key)->default_value("80"),
					"Sets the key for the Learner engine.") 
                ("buffer-size,b",  	po::value<int>(&learner_buffer_size)->default_value(learner_buffer_size),
					"Sets the size of the internal buffer for generate the regex.") 
                ("byte-quality,Q",  	po::value<int>(&learner_byte_quality)->default_value(learner_byte_quality),
					"Sets the minimum quality for the bytes of the generated regex.") 
                ("enable-yara,y",  	"Generates a yara signature.") 
                ;

	mandatory_ops.add(optional_ops_tag);
	mandatory_ops.add(optional_ops_tcp);
	mandatory_ops.add(optional_ops_udp);
	mandatory_ops.add(optional_ops_sigs);
	mandatory_ops.add(optional_ops_freq);

	po::options_description optional_ops("Optional arguments");
	optional_ops.add_options()
		("stack,n",		po::value<std::string>(&option_stack_name)->default_value("lan"),
				      	"Sets the network stack (lan, mobile, lan6, virtual, oflow, mobile6).")
		("dumpflows,d",      	po::value<std::string>(&option_show_flows_name)->implicit_value(""),
					"Dumps the specific flow type to stdout.")
		("statistics,s",	po::value<int>(&option_statistics_level)->default_value(0),
					"Show statistics of the network stack (5 levels).")
		("timeout,T",		po::value<int>(&option_flows_timeout)->default_value(option_flows_timeout),
					"Sets the flows timeout.")
               	("protocol,P",          po::value<std::string>(&option_selected_protocols)->default_value(""),
                                       	"Show statistics of specific protocols of the network stack.")
                ("release,e",  		"Release the caches.") 
                ("release-cache,l",  	po::value<std::string>(&option_release_cache_protocol)->default_value(""),
					"Release a specific cache.") 
		("pstatistics,p",      	"Show statistics of the process.")
		("keep-flows,K",      	"Keep the flows in memory for analisys.")
		("summary,o",      	"Show protocol summmary statistics (bytes, packets, % bytes, cache miss, memory).")
		("help,h",     		"Show help.")
		("version,v",   	"Show version string.")
		;

	mandatory_ops.add(optional_ops);

	try {
	
        	po::store(po::parse_command_line(argc, argv, mandatory_ops), var_map);

        	if (var_map.count("help")) {
            		std::cout << PACKAGE " " VERSION << std::endl;
            		std::cout << mandatory_ops << std::endl;
			std::cout << std::endl;
			show_gpl_banner();
            		exit(0);
        	}
        	if (var_map.count("version")) {
            		std::cout << PACKAGE " " VERSION << std::endl;
			std::cout << std::endl;
			show_gpl_banner();
			std::cout << std::endl;
			show_package_banner();
            		exit(0);
        	}
		if (var_map.count("input") == 0) {
            		std::cout << PACKAGE " " VERSION << std::endl;
            		std::cout << mandatory_ops << std::endl;
			exit(-1);
		}

		if (var_map.count("dumpflows")) option_show_flows = true;
		if (var_map.count("pstatistics")) option_show_pstatistics = true;
		if (var_map.count("enable-learner")) option_enable_learner = true;
		if (var_map.count("release")) option_release_caches = true;
		if (var_map.count("enable-yara")) option_generate_yara = true; 
		if (var_map.count("continue")) option_continue_regex = true;
		if (var_map.count("matched-flows")) option_show_matched_regex = true;
		if (var_map.count("matched-packet")) option_show_matched_packet = true;
		if (var_map.count("reject-flows")) option_reject_flows_regex = true;
		if (var_map.count("evidence")) option_enable_regex_evidence = true;
		if (var_map.count("summary")) option_show_protocol_summary = true;
		if (var_map.count("keep-flows")) option_keep_flows_in_memory = true;

        	po::notify(var_map);
    	
	} catch(boost::program_options::required_option& e) {
            	std::cout << PACKAGE " " VERSION << std::endl;
        	std::cerr << "Error: " << e.what() << std::endl;
		std::cout << mandatory_ops << std::endl;
        	exit(-1);
	} catch(std::exception& e) {
            	std::cout << PACKAGE " " VERSION << std::endl;
        	std::cerr << "Unsupported option." << e.what() << std::endl;
		std::cout << mandatory_ops << std::endl;
        	exit(-2);
    	}

    	signal(SIGINT, signalHandler);  
    	signal(SIGUSR1, signalHandlerShowStackStatistics);  
    	signal(SIGUSR2, signalHandlerShowFlowsStatistics);  

	try {
        	system_stats = SystemPtr(new System());

        	// Some cool banners
		std::ostringstream banner;
        	banner << "AIEngine running on " << system_stats->getOSName();
        	banner << " kernel " << system_stats->getReleaseName();
        	banner << " " << system_stats->getVersionName();
        	banner << " " << system_stats->getMachineName();
        	aiengine::warning_message(banner.str());
		show_package_banner();

#if defined(__x86_64__) || defined(_M_X64)

        	// TODO Garbage 
        	__asm__ volatile (
        		"push %rax\n"
               		"xor %rax,%rax\n"
               		"pop %rax\n"
        	);
#endif

#ifdef HAVE_LIBLOG4CXX
		BasicConfigurator::configure();
#endif	
		system_stats->lockMemory();
	
		pktdis = PacketDispatcherPtr(new PacketDispatcher());

		auto item = stack_factory.at(option_stack_name);
		stack = item();
	} catch (std::out_of_range &e) {
		std::ostringstream msg;
		msg << "Unknown stack " << option_stack_name;

		aiengine::error_message(msg.str()); 
		showAvailableStacks();
		exit(-3);
	} catch(std::exception& e) {
        	std::cerr << e.what() << std::endl;
        	exit(-3);
    	}

	stack->setStatisticsLevel(option_statistics_level);
	stack->setFlowsTimeout(option_flows_timeout);

        if ((tcp_flows_cache == 0) and (udp_flows_cache == 0)) {
		// The memory now is manage dynamically
		stack->setDynamicAllocatedMemory(true);
	} else {
		stack->setDynamicAllocatedMemory(false);
		stack->setTotalTCPFlows(tcp_flows_cache);	
		stack->setTotalUDPFlows(udp_flows_cache);	
	}

	// Check if AIEngine is gonna work as signature extractor or as a regular packet inspector
	if (var_map.count("enable-regex") == 1) {
        	sm = RegexManagerPtr(new RegexManager());
		
		if (!var_map["regex"].empty()) {
			// Generate a list of regex
			vector_regex = var_map["regex"].as<std::vector<std::string>>();
			auto topr = SharedPointer<Regex>(new Regex("experimental0", vector_regex[0]));
			auto prevr = topr;	
	
			for (int i = 1; i < vector_regex.size(); ++i) {
				std::ostringstream name;
				
				name << "experimental" << i;
				auto r = SharedPointer<Regex>(new Regex(name.str(), vector_regex[i]));

				prevr->setNextRegex(r);
				prevr = r;
			}
			topr->setShowMatch(option_show_matched_regex);
			topr->setShowPacket(option_show_matched_packet);
			topr->setRejectConnection(option_reject_flows_regex);	
			topr->setEvidence(option_enable_regex_evidence);
			topr->setContinue(option_continue_regex);
			sm->addRegex(topr);	
        	}

		if (option_regex_type_flows.compare("all") == 0) {
			stack->setUDPRegexManager(sm);
			stack->setTCPRegexManager(sm);
		} else {
			if (option_regex_type_flows.compare("tcp") == 0) stack->setTCPRegexManager(sm);
			if (option_regex_type_flows.compare("udp") == 0) stack->setUDPRegexManager(sm);
		}
		stack->enableNIDSEngine(true);
		option_enable_regex = true;
		if (option_enable_regex_evidence) {
			pktdis->setEvidences(true);
		}
	}

	if ((var_map.count("enable-frequencies") == 1)&&(option_enable_regex == false)) {
		stack->enableFrequencyEngine(true);
		option_enable_frequencies = true;
	}

	if (option_link_type_tag.length() > 0)
		stack->enableLinkLayerTagging(option_link_type_tag);	

	// connect with the stack
        pktdis->setStack(stack);

	atexit(aiengineExit);

	std::vector<std::string> inputs;
	namespace fs = boost::filesystem;

	try {
		if (fs::is_directory(option_input.c_str())) {
			fs::recursive_directory_iterator it(option_input.c_str());
    			fs::recursive_directory_iterator endit;
    
			while (it != endit) {
      				if (fs::is_regular_file(*it)and((it->path().extension() == ".pcap")
					or(it->path().extension() == ".cap") 
					or(it->path().extension() == ".pcapng"))) {
					std::ostringstream os;
			
					os << it->path().c_str();
      					inputs.push_back(os.str());
				} else {
					it.no_push();
				}
				++it;
			}
			sort(inputs.begin(), inputs.end());
		} else {
			inputs.push_back (option_input.c_str());
		}
	} catch (std::exception const&  ex) {
		std::ostringstream msg;

		msg << "Can not read " << option_input.c_str() << " Reason:" << ex.what();
		aiengine::error_message(msg.str()); 
		exit(0);
	}

	if (option_enable_frequencies) // Sets the callback for learn.
		pktdis->setIdleFunction(std::bind(learnerCallback));

	if (option_keep_flows_in_memory) { // The user wants to keep the flows in memory 
		FlowManagerPtr fm_tcp = stack->getTCPFlowManager().lock();
		FlowManagerPtr fm_udp = stack->getUDPFlowManager().lock();

		fm_tcp->setReleaseFlows(false);
		fm_udp->setReleaseFlows(false);
	}

	for (auto& entry: inputs) {

        	pktdis->open(entry);
		try {
			pktdis->run();
		
		} catch (std::exception& e) {
			std::ostringstream msg;

			msg << "Error: " << e.what() << " on packet number " << pktdis->getTotalPackets(); 
			aiengine::error_message(msg.str()); 
			pktdis->showCurrentPayloadPacket(std::cout);
		}
		pktdis->close();
	}

	return 0;
}

