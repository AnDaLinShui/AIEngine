%module(directors="1") jaaiengine 
%include <std_string.i>
%include <std_map.i>
%include <stdint.i>

%{
#include <iostream>
#include "PacketDispatcher.h"
#include "regex/RegexManager.h"
#include "regex/Regex.h"
#include "ipset/IPSetManager.h"
#include "ipset/IPSet.h"
#include "ipset/IPRadixTree.h"
#include "NetworkStack.h"
#include "JaiCallback.h"
#include "Flow.h"
#include "StackLan.h"
#include "StackMobile.h"
#include "StackLanIPv6.h"
#include "StackVirtual.h"
#include "StackOpenFlow.h"
#include "StackMobileIPv6.h"
#include "names/DomainNameManager.h"
#include "names/DomainName.h"
#include "learner/LearnerEngine.h"
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#include "log4cxx/basicconfigurator.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
#endif
%}

%template(Counters) std::map<std::string,int32_t>;

%ignore operator+;
%ignore operator[];
%ignore operator==;
%ignore operator!=;
%ignore operator/;

%ignore aiengine::FlowTable;
%ignore aiengine::free_list;

%ignore aiengine::JsonFlow;
%ignore aiengine::FlowDirection;
%ignore aiengine::FlowInfo;
%ignore aiengine::Callback;

%ignore aiengine::RegexManager::addRegex(const SharedPointer<Regex>& sig);
%ignore aiengine::RegexManager::removeRegex(const SharedPointer<Regex>& sig);
%ignore aiengine::RegexManager::getMatchedRegex;

%ignore aiengine::Signature::setName;
%ignore aiengine::Signature::setExpression;
%ignore aiengine::Signature::incrementMatchs;
%ignore aiengine::Signature::total_matchs_;
%ignore aiengine::Signature::total_evaluates_;

%ignore aiengine::Regex::Regex(const std::string &name, const std::string& exp,const SharedPointer<Regex>& re);
%ignore aiengine::Regex::evaluate;
%ignore aiengine::Regex::isTerminal;
%ignore aiengine::Regex::matchAndExtract;
%ignore aiengine::Regex::getExtract;
%ignore aiengine::Regex::getShowMatch;
%ignore aiengine::Regex::setShowMatch;
%ignore aiengine::Regex::setNextRegex(const SharedPointer<Regex>& reg);
%ignore aiengine::Regex::getNextRegex;
%ignore aiengine::Regex::setNextRegexManager(const SharedPointer<RegexManager>& regex_mng);
%ignore aiengine::Regex::getNextRegexManager;

%ignore aiengine::PacketDispatcher::setStack(const SharedPointer<NetworkStack>& stack);
%ignore aiengine::PacketDispatcher::setDefaultMultiplexer;
%ignore aiengine::PacketDispatcher::setIdleFunction;

%ignore aiengine::NetworkStack::setName;
%ignore aiengine::NetworkStack::setLinkLayerMultiplexer;
%ignore aiengine::NetworkStack::getLinkLayerMultiplexer;
%ignore aiengine::NetworkStack::enableFlowForwarders;
%ignore aiengine::NetworkStack::disableFlowForwarders;
%ignore aiengine::NetworkStack::setTCPRegexManager(const SharedPointer<RegexManager>& sig);
%ignore aiengine::NetworkStack::setUDPRegexManager(const SharedPointer<RegexManager>& sig);
%ignore aiengine::NetworkStack::setTCPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng);
%ignore aiengine::NetworkStack::setUDPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng);
%ignore aiengine::NetworkStack::addProtocol;
%ignore aiengine::NetworkStack::infoMessage;
%ignore aiengine::NetworkStack::setPacketDispatcher;
%ignore aiengine::NetworkStack::setDomainNameManager(const SharedPointer<DomainNameManager>& dnm, const std::string& name);
%ignore aiengine::NetworkStack::setDomainNameManager(const SharedPointer<DomainNameManager>& dnm, const std::string& name, bool allow);

%ignore aiengine::StackLan::setLinkLayerMultiplexer;
%ignore aiengine::StackLan::getLinkLayerMultiplexer;
%ignore aiengine::StackLan::getTCPRegexManager;
%ignore aiengine::StackLan::getUDPRegexManager;

%ignore aiengine::StackMobile::setLinkLayerMultiplexer;
%ignore aiengine::StackMobile::getLinkLayerMultiplexer;
%ignore aiengine::StackMobile::getTCPRegexManager;
%ignore aiengine::StackMobile::getUDPRegexManager;

%ignore aiengine::StackLanIPv6::setLinkLayerMultiplexer;
%ignore aiengine::StackLanIPv6::getLinkLayerMultiplexer;
%ignore aiengine::StackLanIPv6::getTCPRegexManager;
%ignore aiengine::StackLanIPv6::getUDPRegexManager;

%ignore aiengine::StackVirtual::setLinkLayerMultiplexer;
%ignore aiengine::StackVirtual::getLinkLayerMultiplexer;
%ignore aiengine::StackVirtual::getTCPRegexManager;
%ignore aiengine::StackVirtual::getUDPRegexManager;

%ignore aiengine::StackOpenFlow::setLinkLayerMultiplexer;
%ignore aiengine::StackOpenFlow::getLinkLayerMultiplexer;
%ignore aiengine::StackOpenFlow::getTCPRegexManager;
%ignore aiengine::StackOpenFlow::getUDPRegexManager;

%ignore aiengine::StackMobileIPv6::setLinkLayerMultiplexer;
%ignore aiengine::StackMobileIPv6::getLinkLayerMultiplexer;
%ignore aiengine::StackMobileIPv6::getTCPRegexManager;
%ignore aiengine::StackMobileIPv6::getUDPRegexManager;

%ignore aiengine::IPSetManager::addIPSet(const SharedPointer<IPAbstractSet>& ipset);
%ignore aiengine::IPSetManager::removeIPSet(const SharedPointer<IPAbstractSet>& ipset);
%ignore aiengine::IPSetManager::getMatchedIPSet;
%ignore aiengine::IPSetManager::lookupIPAddress;

%ignore aiengine::IPAbstractSet::setRegexManager(const SharedPointer<RegexManager>& rmng);
%ignore aiengine::IPAbstractSet::getRegexManager;
%ignore aiengine::IPAbstractSet::lookupIPAddress;

%ignore aiengine::FlowManager::addFlow;
%ignore aiengine::FlowManager::removeFlow;
%ignore aiengine::FlowManager::findFlow;
%ignore aiengine::FlowManager::updateTimers;
%ignore aiengine::FlowManager::setFlowCache;
%ignore aiengine::FlowManager::setTCPInfoCache;
%ignore aiengine::FlowManager::getFlowTable;
%ignore aiengine::FlowManager::getLastProcessFlow;
%ignore aiengine::FlowManager::setProtocol;
%ignore aiengine::FlowManager::updateFlowTime;
%ignore aiengine::FlowManager::setCacheManager;

%ignore aiengine::DomainNameManager::removeDomainName(const SharedPointer<DomainName>& domain);
%ignore aiengine::DomainNameManager::addDomainName(const SharedPointer<DomainName>& domain);
%ignore aiengine::DomainNameManager::getDomainName;

%ignore aiengine::DomainName::setHTTPUriSet(const SharedPointer<HTTPUriSet>& uset);
%ignore aiengine::DomainName::getHTTPUriSet;
%ignore aiengine::DomainName::setRegexManager(const SharedPointer<RegexManager>& rmng);
%ignore aiengine::DomainName::getRegexManager;
%ignore aiengine::DomainName::setHTTPUriRegexManager;
%ignore aiengine::DomainName::getHTTPUriRegexManager;

%ignore aiengine::Flow::setPacketAnomaly;
%ignore aiengine::Flow::getPacketAnomaly;
%ignore aiengine::Flow::ipset;
%ignore aiengine::Flow::layer4info;
%ignore aiengine::Flow::layer7info;
%ignore aiengine::Flow::getTCPInfo;
%ignore aiengine::Flow::getPOPInfo;
%ignore aiengine::Flow::getIMAPInfo;
%ignore aiengine::Flow::getSMTPInfo;
%ignore aiengine::Flow::getSSLInfo;
%ignore aiengine::Flow::getDNSInfo;
%ignore aiengine::Flow::getHTTPInfo;
%ignore aiengine::Flow::getGPRSInfo;
%ignore aiengine::Flow::getSSDPInfo;
%ignore aiengine::Flow::getSIPInfo;
%ignore aiengine::Flow::getBitcoinInfo;
%ignore aiengine::Flow::getCoAPInfo;
%ignore aiengine::Flow::getMQTTInfo;
%ignore aiengine::Flow::getNetbiosInfo;
%ignore aiengine::Flow::getDHCPInfo;
%ignore aiengine::Flow::getDHCPv6Info;
%ignore aiengine::Flow::getSMBInfo;
%ignore aiengine::Flow::getSSHInfo;
%ignore aiengine::Flow::getDCERPCInfo;
%ignore aiengine::Flow::packet;
%ignore aiengine::Flow::regex;
%ignore aiengine::Flow::frequencies;
%ignore aiengine::Flow::packet_frequencies;
%ignore aiengine::Flow::forwarder;
%ignore aiengine::Flow::regex_mng;
%ignore aiengine::Flow::setId;
%ignore aiengine::Flow::getId;
%ignore aiengine::Flow::setFlowDirection;
%ignore aiengine::Flow::getFlowDirection;
%ignore aiengine::Flow::getPrevFlowDirection;
%ignore aiengine::Flow::setFiveTuple;
%ignore aiengine::Flow::setFiveTuple6;
%ignore aiengine::Flow::setArriveTime;
%ignore aiengine::Flow::setLastPacketTime;
%ignore aiengine::Flow::frequency_engine_inspected;
%ignore aiengine::Flow::reset;
%ignore aiengine::Flow::serialize;
%ignore aiengine::Flow::deserialize;
%ignore aiengine::Flow::showFlowInfo;
%ignore aiengine::Flow::getSourceAddress;
%ignore aiengine::Flow::getDestinationAddress;
%ignore aiengine::Flow::haveTag;
%ignore aiengine::Flow::setTag;
%ignore aiengine::Flow::getTotalBytes;
%ignore aiengine::Flow::getLastPacketTime;
%ignore aiengine::Flow::getDuration;
%ignore aiengine::Flow::getFrequencies;
%ignore aiengine::Flow::getPacketFrequencies;
%ignore aiengine::Flow::getFlowAnomaly;
%ignore aiengine::Flow::getTotalPackets;
%ignore aiengine::Flow::getTotalPacketsLayer7;
%ignore aiengine::Flow::getAddress;

%ignore aiengine::Frequencies::reset;
%ignore aiengine::Frequencies::serialize;

%ignore aiengine::HTTPInfo::reset;
%ignore aiengine::HTTPInfo::serialize;
%ignore aiengine::HTTPInfo::resetStrings;
%ignore aiengine::HTTPInfo::getContentLength;
%ignore aiengine::HTTPInfo::setContentLength;
%ignore aiengine::HTTPInfo::getDataChunkLength;
%ignore aiengine::HTTPInfo::setDataChunkLength;
%ignore aiengine::HTTPInfo::setIsBanned;
%ignore aiengine::HTTPInfo::setHaveData;
%ignore aiengine::HTTPInfo::getHaveData;
%ignore aiengine::HTTPInfo::incTotalRequests;
%ignore aiengine::HTTPInfo::incTotalResponses;
%ignore aiengine::HTTPInfo::setResponseCode;
%ignore aiengine::HTTPInfo::uri;
%ignore aiengine::HTTPInfo::host_name;
%ignore aiengine::HTTPInfo::ua;
%ignore aiengine::HTTPInfo::ct;
%ignore aiengine::HTTPInfo::filename;
%ignore aiengine::HTTPInfo::matched_domain_name;
%ignore aiengine::HTTPInfo::getTotalRequests;
%ignore aiengine::HTTPInfo::getTotalResponses;
%ignore aiengine::HTTPInfo::getResponseCode;
%ignore aiengine::HTTPInfo::setBanAndRelease;
%ignore aiengine::HTTPInfo::setIsRelease;
%ignore aiengine::HTTPInfo::getIsRelease;
%ignore aiengine::HTTPInfo::setHTTPDataDirection;
%ignore aiengine::HTTPInfo::getHTTPDataDirection;

%ignore aiengine::BitcoinInfo::reset;
%ignore aiengine::BitcoinInfo::serialize;
%ignore aiengine::BitcoinInfo::incTransactions;

%ignore aiengine::MQTTInfo::reset;
%ignore aiengine::MQTTInfo::serialize;
%ignore aiengine::MQTTInfo::topic;

%ignore aiengine::SIPInfo::reset;
%ignore aiengine::SIPInfo::serialize;
%ignore aiengine::SIPInfo::resetStrings;
%ignore aiengine::SIPInfo::uri;
%ignore aiengine::SIPInfo::from;
%ignore aiengine::SIPInfo::to;
%ignore aiengine::SIPInfo::via;

%ignore aiengine::DNSInfo::name;
%ignore aiengine::DNSInfo::serialize;
%ignore aiengine::DNSInfo::addIPAddress;
%ignore aiengine::DNSInfo::begin;
%ignore aiengine::DNSInfo::end;
%ignore aiengine::DNSInfo::reset;
%ignore aiengine::DNSInfo::resetStrings;
%ignore aiengine::DNSInfo::getQueryType;
%ignore aiengine::DNSInfo::setQueryType;
%ignore aiengine::DNSInfo::matched_domain_name;

%ignore aiengine::SSLInfo::reset;
%ignore aiengine::SSLInfo::serialize;
%ignore aiengine::SSLInfo::host_name;
%ignore aiengine::SSLInfo::issuer;
%ignore aiengine::SSLInfo::setIsBanned;
%ignore aiengine::SSLInfo::isBanned;
%ignore aiengine::SSLInfo::incDataPdus;
%ignore aiengine::SSLInfo::getTotalDataPdus;
%ignore aiengine::SSLInfo::matched_domain_name;

%ignore aiengine::SMTPInfo::reset;
%ignore aiengine::SMTPInfo::serialize;
%ignore aiengine::SMTPInfo::resetStrings;
%ignore aiengine::SMTPInfo::setIsBanned;
%ignore aiengine::SMTPInfo::isBanned;
%ignore aiengine::SMTPInfo::setCommand;
%ignore aiengine::SMTPInfo::from;
%ignore aiengine::SMTPInfo::to;
%ignore aiengine::SMTPInfo::matched_domain_name;

%ignore aiengine::IMAPInfo::reset;
%ignore aiengine::IMAPInfo::serialize;
%ignore aiengine::IMAPInfo::setIsBanned;
%ignore aiengine::IMAPInfo::isBanned;
%ignore aiengine::IMAPInfo::incClientCommands;
%ignore aiengine::IMAPInfo::incServerCommands;
%ignore aiengine::IMAPInfo::user_name;

%ignore aiengine::POPInfo::reset;
%ignore aiengine::POPInfo::serialize;
%ignore aiengine::POPInfo::setIsBanned;
%ignore aiengine::POPInfo::isBanned;
%ignore aiengine::POPInfo::incClientCommands;
%ignore aiengine::POPInfo::incServerCommands;
%ignore aiengine::POPInfo::user_name;
%ignore aiengine::POPInfo::resetStrings;

%ignore aiengine::SSDPInfo::reset;
%ignore aiengine::SSDPInfo::serialize;
%ignore aiengine::SSDPInfo::resetStrings;
%ignore aiengine::SSDPInfo::incTotalRequests;
%ignore aiengine::SSDPInfo::incTotalResponses;
%ignore aiengine::SSDPInfo::setResponseCode;
%ignore aiengine::SSDPInfo::uri;
%ignore aiengine::SSDPInfo::host_name;
%ignore aiengine::SSDPInfo::matched_domain_name;
%ignore aiengine::SSDPInfo::getTotalRequests;
%ignore aiengine::SSDPInfo::getTotalResponses;

%ignore aiengine::CoAPInfo::reset;
%ignore aiengine::CoAPInfo::serialize;
%ignore aiengine::CoAPInfo::host_name;
%ignore aiengine::CoAPInfo::uri;
%ignore aiengine::CoAPInfo::matched_domain_name;
%ignore aiengine::CoAPInfo::setIsBanned;
%ignore aiengine::CoAPInfo::isBanned;

%ignore aiengine::NetbiosInfo::reset;
%ignore aiengine::NetbiosInfo::serialize;
%ignore aiengine::NetbiosInfo::netbios_name;

%ignore aiengine::DHCPInfo::reset;
%ignore aiengine::DHCPInfo::serialize;
%ignore aiengine::DHCPInfo::host_name;
%ignore aiengine::DHCPInfo::ip;

%ignore aiengine::SMBInfo::reset;
%ignore aiengine::SMBInfo::serialize;
%ignore aiengine::SMBInfo::filename;

%ignore aiengine::DHCPv6Info::reset;
%ignore aiengine::DHCPv6Info::serialize;
%ignore aiengine::DHCPv6Info::host_name;
%ignore aiengine::DHCPv6Info::ip6;
%ignore aiengine::DHCPv6Info::setLifetime;
%ignore aiengine::DHCPv6Info::getT1;
%ignore aiengine::DHCPv6Info::getT2;

%ignore aiengine::SSHInfo::reset;
%ignore aiengine::SSHInfo::serialize;
%ignore aiengine::SSHInfo::setClientHandshake;
%ignore aiengine::SSHInfo::setServerHandshake;
%ignore aiengine::SSHInfo::addEncryptedBytes;

%ignore aiengine::DCERPCInfo::reset;
%ignore aiengine::DCERPCInfo::serialize;
%ignore aiengine::DCERPCInfo::uuid;

%ignore operator<<;

%feature("director") JaiCallback;
%feature("director") DatabaseAdaptor;

%include "Callback.h"
%include "JaiCallback.h"
%include "Signature.h"
%include "regex/Regex.h"
%include "regex/RegexManager.h"
%include "protocols/http/HTTPUriSet.h"
%include "names/DomainName.h"
%include "names/DomainNameManager.h"
%include "ipset/IPAbstractSet.h"
%include "ipset/IPSet.h"
%include "ipset/IPRadixTree.h"
%include "ipset/IPSetManager.h"
%include "DatabaseAdaptor.h"
%include "flow/FlowManager.h"
%include "NetworkStack.h"
%include "StackLan.h"
%include "StackMobile.h"
%include "StackLanIPv6.h"
%include "StackVirtual.h"
%include "StackOpenFlow.h"
%include "StackMobileIPv6.h"
%include "PacketDispatcher.h"
%include "protocols/http/HTTPInfo.h"
%include "protocols/sip/SIPInfo.h"
%include "protocols/frequency/Frequencies.h"
%include "protocols/frequency/PacketFrequencies.h"
%include "protocols/dns/DNSInfo.h"
%include "protocols/ssl/SSLInfo.h"
%include "protocols/smtp/SMTPInfo.h"
%include "protocols/imap/IMAPInfo.h"
%include "protocols/pop/POPInfo.h"
%include "protocols/ssdp/SSDPInfo.h"
%include "protocols/bitcoin/BitcoinInfo.h"
%include "protocols/coap/CoAPInfo.h"
%include "protocols/mqtt/MQTTInfo.h"
%include "protocols/netbios/NetbiosInfo.h"
%include "protocols/dhcp/DHCPInfo.h"
%include "protocols/smb/SMBInfo.h"
%include "protocols/dhcp6/DHCPv6Info.h"
%include "protocols/ssh/SSHInfo.h"
%include "protocols/dcerpc/DCERPCInfo.h"
%include "Flow.h"

%pragma(java) jniclassimports=%{
import java.lang.*;
%}

%pragma(java) jniclasscode=%{
  static {
    try {
      String osPath = System.getProperty("user.dir");
      System.load(osPath + "/jaaiengine.so");  
    } catch (UnsatisfiedLinkError e) {
      System.err.println("Native code library failed to load. \n" + e);
      System.exit(1);
    }
  }
%}

