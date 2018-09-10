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
#include "NetworkStack.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr NetworkStack::logger(log4cxx::Logger::getLogger("aiengine.stack"));
#endif

NetworkStack::NetworkStack():
	/* LCOV_EXCL_START Looks that coverage dont like this */
        mux_eth(MultiplexerPtr(new Multiplexer())),
        mux_vlan(MultiplexerPtr(new Multiplexer())),
        mux_mpls(MultiplexerPtr(new Multiplexer())),
        mux_pppoe(MultiplexerPtr(new Multiplexer())),
        mux_ip(MultiplexerPtr(new Multiplexer())),
	// Allocate the link layer protocols
        eth(EthernetProtocolPtr(new EthernetProtocol())),
        vlan(VLanProtocolPtr(new VLanProtocol())),
        mpls(MPLSProtocolPtr(new MPLSProtocol())),
        pppoe(PPPoEProtocolPtr(new PPPoEProtocol())),
	// Allocate the layer 7 protocols
        http(HTTPProtocolPtr(new HTTPProtocol())),
        ssl(SSLProtocolPtr(new SSLProtocol())),
        dns(DNSProtocolPtr(new DNSProtocol())),
        sip(SIPProtocolPtr(new SIPProtocol())),
        dhcp(DHCPProtocolPtr(new DHCPProtocol())),
        ntp(NTPProtocolPtr(new NTPProtocol())),
        snmp(SNMPProtocolPtr(new SNMPProtocol())),
        ssdp(SSDPProtocolPtr(new SSDPProtocol())),
        smtp(SMTPProtocolPtr(new SMTPProtocol())),
        imap(IMAPProtocolPtr(new IMAPProtocol())),
        pop(POPProtocolPtr(new POPProtocol())),
	bitcoin(BitcoinProtocolPtr(new BitcoinProtocol())),
	modbus(ModbusProtocolPtr(new ModbusProtocol())),
	coap(CoAPProtocolPtr(new CoAPProtocol())),
	rtp(RTPProtocolPtr(new RTPProtocol())),
	mqtt(MQTTProtocolPtr(new MQTTProtocol())),
	netbios(NetbiosProtocolPtr(new NetbiosProtocol())),
	quic(QuicProtocolPtr(new QuicProtocol())),
	smb(SMBProtocolPtr(new SMBProtocol())),
	ssh(SSHProtocolPtr(new SSHProtocol())),
	dcerpc(DCERPCProtocolPtr(new DCERPCProtocol())),
        tcp_generic(TCPGenericProtocolPtr(new TCPGenericProtocol())),
        udp_generic(UDPGenericProtocolPtr(new UDPGenericProtocol())),
        freqs_tcp(FrequencyProtocolPtr(new FrequencyProtocol("TCPFrequencyProtocol", "tcpfrequency"))),
        freqs_udp(FrequencyProtocolPtr(new FrequencyProtocol("UDPFrequencyProtocol", "udpfrequency"))),
	// Common FlowForwarders
        ff_http(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_ssl(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_dns(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_sip(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_dhcp(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_ntp(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_snmp(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_ssdp(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_smtp(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_imap(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_pop(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_bitcoin(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_ssh(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_modbus(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_coap(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_rtp(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_mqtt(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_netbios(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_quic(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_smb(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_dcerpc(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_tcp_generic(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_udp_generic(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_tcp_freqs(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_udp_freqs(SharedPointer<FlowForwarder>(new FlowForwarder())),
	anomaly_(SharedPointer<AnomalyManager>(new AnomalyManager())),
	// Private section
	stats_level_(0),
	name_(""),
	proto_vector_(),
	domain_mng_list_(),
	tcp_regex_mng_(),
	udp_regex_mng_(),
	tcp_ipset_mng_(),
	udp_ipset_mng_(),
	ff_udp_current_(),
	ff_tcp_current_(),
	link_layer_tag_name_()
	/* LCOV_EXCL_STOP */
	{

        //configure the Ethernet Layer 
        eth->setMultiplexer(mux_eth);
        mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
        mux_eth->setProtocolIdentifier(0);
        mux_eth->setHeaderSize(eth->getHeaderSize());
        mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker, eth, std::placeholders::_1));

        //configure the VLan tagging Layer 
        vlan->setMultiplexer(mux_vlan);
        mux_vlan->setProtocol(static_cast<ProtocolPtr>(vlan));
        mux_vlan->setProtocolIdentifier(ETHERTYPE_VLAN);
        mux_vlan->setHeaderSize(vlan->getHeaderSize());
        mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker, vlan, std::placeholders::_1));
        mux_vlan->addPacketFunction(std::bind(&VLanProtocol::processPacket, vlan, std::placeholders::_1));

        //configure the MPLS Layer 
        mpls->setMultiplexer(mux_mpls);
        mux_mpls->setProtocol(static_cast<ProtocolPtr>(mpls));
        mux_mpls->setProtocolIdentifier(ETHERTYPE_MPLS);
        mux_mpls->setHeaderSize(mpls->getHeaderSize());
        mux_mpls->addChecker(std::bind(&MPLSProtocol::mplsChecker, mpls, std::placeholders::_1));
        mux_mpls->addPacketFunction(std::bind(&MPLSProtocol::processPacket, mpls, std::placeholders::_1));

        //configure the PPPoE Layer 
        pppoe->setMultiplexer(mux_pppoe);
        mux_pppoe->setProtocol(static_cast<ProtocolPtr>(pppoe));
        mux_pppoe->setProtocolIdentifier(ETHERTYPE_PPPOE);
        mux_pppoe->setHeaderSize(pppoe->getHeaderSize());
        mux_pppoe->addChecker(std::bind(&PPPoEProtocol::pppoeChecker, pppoe, std::placeholders::_1));
        mux_pppoe->addPacketFunction(std::bind(&PPPoEProtocol::processPacket, pppoe, std::placeholders::_1));

        // configure the HTTP Layer
        http->setFlowForwarder(ff_http);
        ff_http->setProtocol(static_cast<ProtocolPtr>(http));
        ff_http->addChecker(std::bind(&HTTPProtocol::httpChecker, http, std::placeholders::_1));
        ff_http->addFlowFunction(std::bind(&HTTPProtocol::processFlow, http, std::placeholders::_1));

        // configure the SSL Layer
        ssl->setFlowForwarder(ff_ssl);
        ff_ssl->setProtocol(static_cast<ProtocolPtr>(ssl));
        ff_ssl->addChecker(std::bind(&SSLProtocol::sslChecker, ssl, std::placeholders::_1));
        ff_ssl->addFlowFunction(std::bind(&SSLProtocol::processFlow, ssl, std::placeholders::_1));

        // configure the DNS Layer
        dns->setFlowForwarder(ff_dns);
        ff_dns->setProtocol(static_cast<ProtocolPtr>(dns));
        ff_dns->addChecker(std::bind(&DNSProtocol::dnsChecker, dns, std::placeholders::_1));
        ff_dns->addFlowFunction(std::bind(&DNSProtocol::processFlow, dns, std::placeholders::_1));

        // configure the SIP Layer
        sip->setFlowForwarder(ff_sip);
        ff_sip->setProtocol(static_cast<ProtocolPtr>(sip));
        ff_sip->addChecker(std::bind(&SIPProtocol::sipChecker, sip, std::placeholders::_1));
        ff_sip->addFlowFunction(std::bind(&SIPProtocol::processFlow, sip, std::placeholders::_1));

        // Configure the DHCP 
        dhcp->setFlowForwarder(ff_dhcp);
        ff_dhcp->setProtocol(static_cast<ProtocolPtr>(dhcp));
        ff_dhcp->addChecker(std::bind(&DHCPProtocol::dhcpChecker, dhcp, std::placeholders::_1));
        ff_dhcp->addFlowFunction(std::bind(&DHCPProtocol::processFlow, dhcp, std::placeholders::_1));

        // Configure the NTP 
        ntp->setFlowForwarder(ff_ntp);
        ff_ntp->setProtocol(static_cast<ProtocolPtr>(ntp));
        ff_ntp->addChecker(std::bind(&NTPProtocol::ntpChecker, ntp, std::placeholders::_1));
        ff_ntp->addFlowFunction(std::bind(&NTPProtocol::processFlow, ntp, std::placeholders::_1));

        // Configure the SNMP 
        snmp->setFlowForwarder(ff_snmp);
        ff_snmp->setProtocol(static_cast<ProtocolPtr>(snmp));
        ff_snmp->addChecker(std::bind(&SNMPProtocol::snmpChecker, snmp, std::placeholders::_1));
        ff_snmp->addFlowFunction(std::bind(&SNMPProtocol::processFlow, snmp, std::placeholders::_1));

        // Configure the SSDP 
        ssdp->setFlowForwarder(ff_ssdp);
        ff_ssdp->setProtocol(static_cast<ProtocolPtr>(ssdp));
        ff_ssdp->addChecker(std::bind(&SSDPProtocol::ssdpChecker, ssdp, std::placeholders::_1));
        ff_ssdp->addFlowFunction(std::bind(&SSDPProtocol::processFlow, ssdp, std::placeholders::_1));

        // Configure the netbios
        netbios->setFlowForwarder(ff_netbios);
        ff_netbios->setProtocol(static_cast<ProtocolPtr>(netbios));
        ff_netbios->addChecker(std::bind(&NetbiosProtocol::netbiosChecker, netbios, std::placeholders::_1));
        ff_netbios->addFlowFunction(std::bind(&NetbiosProtocol::processFlow, netbios, std::placeholders::_1));

        // Configure the quic
        quic->setFlowForwarder(ff_quic);
        ff_quic->setProtocol(static_cast<ProtocolPtr>(quic));
        ff_quic->addChecker(std::bind(&QuicProtocol::quicChecker, quic, std::placeholders::_1));
        ff_quic->addFlowFunction(std::bind(&QuicProtocol::processFlow, quic, std::placeholders::_1));

	// Configure the CoAP
        coap->setFlowForwarder(ff_coap);
        ff_coap->setProtocol(static_cast<ProtocolPtr>(coap));
        ff_coap->addChecker(std::bind(&CoAPProtocol::coapChecker, coap, std::placeholders::_1));
        ff_coap->addFlowFunction(std::bind(&CoAPProtocol::processFlow, coap, std::placeholders::_1));

        // configure the RTP 
        rtp->setFlowForwarder(ff_rtp);
        ff_rtp->setProtocol(static_cast<ProtocolPtr>(rtp));
        ff_rtp->addChecker(std::bind(&RTPProtocol::rtpChecker, rtp, std::placeholders::_1));
        ff_rtp->addFlowFunction(std::bind(&RTPProtocol::processFlow, rtp, std::placeholders::_1));

        // Configure the SMTP 
        smtp->setFlowForwarder(ff_smtp);
        ff_smtp->setProtocol(static_cast<ProtocolPtr>(smtp));
        ff_smtp->addChecker(std::bind(&SMTPProtocol::smtpChecker, smtp, std::placeholders::_1));
        ff_smtp->addFlowFunction(std::bind(&SMTPProtocol::processFlow, smtp, std::placeholders::_1));

        // Configure the IMAP 
        imap->setFlowForwarder(ff_imap);
        ff_imap->setProtocol(static_cast<ProtocolPtr>(imap));
        ff_imap->addChecker(std::bind(&IMAPProtocol::imapChecker, imap, std::placeholders::_1));
        ff_imap->addFlowFunction(std::bind(&IMAPProtocol::processFlow, imap, std::placeholders::_1));

        // Configure the POP 
        pop->setFlowForwarder(ff_pop);
        ff_pop->setProtocol(static_cast<ProtocolPtr>(pop));
        ff_pop->addChecker(std::bind(&POPProtocol::popChecker, pop, std::placeholders::_1));
        ff_pop->addFlowFunction(std::bind(&POPProtocol::processFlow, pop, std::placeholders::_1));

        // Configure the Bitcoin 
        bitcoin->setFlowForwarder(ff_bitcoin);
        ff_bitcoin->setProtocol(static_cast<ProtocolPtr>(bitcoin));
        ff_bitcoin->addChecker(std::bind(&BitcoinProtocol::bitcoinChecker, bitcoin, std::placeholders::_1));
        ff_bitcoin->addFlowFunction(std::bind(&BitcoinProtocol::processFlow, bitcoin, std::placeholders::_1));

        // Configure the Modbus 
        modbus->setFlowForwarder(ff_modbus);
        ff_modbus->setProtocol(static_cast<ProtocolPtr>(modbus));
        ff_modbus->addChecker(std::bind(&ModbusProtocol::modbusChecker, modbus, std::placeholders::_1));
        ff_modbus->addFlowFunction(std::bind(&ModbusProtocol::processFlow, modbus, std::placeholders::_1));

        // Configure the MQTT 
        mqtt->setFlowForwarder(ff_mqtt);
        ff_mqtt->setProtocol(static_cast<ProtocolPtr>(mqtt));
        ff_mqtt->addChecker(std::bind(&MQTTProtocol::mqttChecker, mqtt, std::placeholders::_1));
        ff_mqtt->addFlowFunction(std::bind(&MQTTProtocol::processFlow, mqtt, std::placeholders::_1));

        // Configure the smb 
        smb->setFlowForwarder(ff_smb);
        ff_smb->setProtocol(static_cast<ProtocolPtr>(smb));
        ff_smb->addChecker(std::bind(&SMBProtocol::smbChecker, smb, std::placeholders::_1));
        ff_smb->addFlowFunction(std::bind(&SMBProtocol::processFlow, smb, std::placeholders::_1));

        // Configure the SSH
        ssh->setFlowForwarder(ff_ssh);
        ff_ssh->setProtocol(static_cast<ProtocolPtr>(ssh));
        ff_ssh->addChecker(std::bind(&SSHProtocol::sshChecker, ssh, std::placeholders::_1));
        ff_ssh->addFlowFunction(std::bind(&SSHProtocol::processFlow, ssh, std::placeholders::_1));

        // configure the dcerpc 
        dcerpc->setFlowForwarder(ff_dcerpc);
        ff_dcerpc->setProtocol(static_cast<ProtocolPtr>(dcerpc));
        ff_dcerpc->addChecker(std::bind(&DCERPCProtocol::dcerpcChecker, dcerpc, std::placeholders::_1));
        ff_dcerpc->addFlowFunction(std::bind(&DCERPCProtocol::processFlow, dcerpc, std::placeholders::_1));

        // configure the TCP generic Layer
        tcp_generic->setFlowForwarder(ff_tcp_generic);
        ff_tcp_generic->setProtocol(static_cast<ProtocolPtr>(tcp_generic));
        ff_tcp_generic->addChecker(std::bind(&TCPGenericProtocol::tcpGenericChecker, tcp_generic, std::placeholders::_1));
        ff_tcp_generic->addFlowFunction(std::bind(&TCPGenericProtocol::processFlow, tcp_generic, std::placeholders::_1));

        // configure the UDP generic Layer
        udp_generic->setFlowForwarder(ff_udp_generic);
        ff_udp_generic->setProtocol(static_cast<ProtocolPtr>(udp_generic));
        ff_udp_generic->addChecker(std::bind(&UDPGenericProtocol::udpGenericChecker, udp_generic, std::placeholders::_1));
        ff_udp_generic->addFlowFunction(std::bind(&UDPGenericProtocol::processFlow, udp_generic, std::placeholders::_1));

        // configure the TCP frequencies
        freqs_tcp->setFlowForwarder(ff_tcp_freqs);
        ff_tcp_freqs->setProtocol(static_cast<ProtocolPtr>(freqs_tcp));
        ff_tcp_freqs->addChecker(std::bind(&FrequencyProtocol::freqChecker, freqs_tcp, std::placeholders::_1));
        ff_tcp_freqs->addFlowFunction(std::bind(&FrequencyProtocol::processFlow, freqs_tcp, std::placeholders::_1));

        // configure the UDP frequencies
        freqs_udp->setFlowForwarder(ff_udp_freqs);
        ff_udp_freqs->setProtocol(static_cast<ProtocolPtr>(freqs_udp));
        ff_udp_freqs->addChecker(std::bind(&FrequencyProtocol::freqChecker, freqs_udp, std::placeholders::_1));
        ff_udp_freqs->addFlowFunction(std::bind(&FrequencyProtocol::processFlow, freqs_udp, std::placeholders::_1));

	// Sets the AnomalyManager on protocols that could generate an anomaly
        dns->setAnomalyManager(anomaly_);
        snmp->setAnomalyManager(anomaly_);
        coap->setAnomalyManager(anomaly_);
        rtp->setAnomalyManager(anomaly_);
        sip->setAnomalyManager(anomaly_);
        http->setAnomalyManager(anomaly_);
        ssl->setAnomalyManager(anomaly_);
        smtp->setAnomalyManager(anomaly_);
        pop->setAnomalyManager(anomaly_);
        imap->setAnomalyManager(anomaly_);
        mqtt->setAnomalyManager(anomaly_);
        netbios->setAnomalyManager(anomaly_);
        dhcp->setAnomalyManager(anomaly_);
}

NetworkStack::~NetworkStack() {

	name_.clear(); 
        tcp_regex_mng_.reset();
        udp_regex_mng_.reset();
        tcp_ipset_mng_.reset();
        udp_ipset_mng_.reset();
        ff_udp_current_.reset();
        ff_tcp_current_.reset();
}

ProtocolPtr NetworkStack::get_protocol(const std::string &name) const {

	ProtocolPtr pp;

	for (auto &p: proto_vector_) {
		ProtocolPtr proto = p.second;

		if ((boost::iequals(name, proto->getName()))or(boost::iequals(name, proto->getShortName()))) {
			pp = proto;
			break;
		}
       	} 
	return pp;
}

void NetworkStack::addProtocol(ProtocolPtr proto) { 

	ProtocolPair pp(proto->getName(), proto);

	proto_vector_.push_back(pp);
}

void NetworkStack::addProtocol(ProtocolPtr proto, bool active) {

	proto->setActive(active);
	addProtocol(proto);
}

int64_t NetworkStack::getAllocatedMemory() const {

	int64_t value = 0;

	for (auto &p: proto_vector_) {
		value += (p.second)->getAllocatedMemory();
	}

	return value;
} 

int64_t NetworkStack::getTotalAllocatedMemory() const {

	int64_t value = 0;

	for (auto &p: proto_vector_) {
		value += (p.second)->getTotalAllocatedMemory();
	}

	return value;
} 

void NetworkStack::statistics(const std::string &name, int level) const {

	if (level > 0) {
		ProtocolPtr proto = get_protocol(name);

		if ((proto)and(proto->isActive())) {
			proto->statistics(OutputManager::getInstance()->out(), level);
			OutputManager::getInstance()->out() << std::endl;
		}
	}
}

void NetworkStack::statistics(const std::string &name) const {

	statistics(name, stats_level_);
}

void NetworkStack::statistics(std::basic_ostream<char> &out, int level) const {

	if (level > 0) {
		std::for_each (proto_vector_.begin(), proto_vector_.end(), [&] (ProtocolPair const &pp) {
			ProtocolPtr proto = pp.second;

			if (proto->isActive()) {
				proto->statistics(out, level);
				out << std::endl;
			}
		});
		anomaly_->statistics(out);	
		out << std::endl;
	}
}

void NetworkStack::statistics(int level) const {

	statistics(OutputManager::getInstance()->out(), level);
}

void NetworkStack::setStatisticsLevel(int level) {

        stats_level_ = level;

	std::for_each (proto_vector_.begin(), proto_vector_.end(), [&] (ProtocolPair const &pp) {
		ProtocolPtr proto = pp.second;

		proto->setStatisticsLevel(level);
	});	
}

std::ostream& operator<< (std::ostream &out, const NetworkStack &ns) {

	ns.statistics(out, ns.stats_level_);
        
        return out;
}

// This method is only executed by users under the shell control
void NetworkStack::showFlows(int limit) {

       	showFlows(OutputManager::getInstance()->out(), limit);
}

void NetworkStack::showFlows(const std::string& protoname, int limit) {

       	showFlows(OutputManager::getInstance()->out(), protoname, limit);
}

void NetworkStack::showFlows(const std::string &protoname) {

        showFlows(protoname, std::numeric_limits<int>::max());
}

void NetworkStack::showFlows() {

        showFlows(std::numeric_limits<int>::max());
}


void NetworkStack::statistics() const {

	statistics(OutputManager::getInstance()->out());
}

void NetworkStack::statistics(std::basic_ostream<char> &out) const { 

	out << *this; 
}

void NetworkStack::setDomainNameManager(const SharedPointer<DomainNameManager> &dnm, const std::string &name) {

	setDomainNameManager(dnm, name, true);
}

void NetworkStack::setDomainNameManager(const SharedPointer<DomainNameManager> &dnm, const std::string &name, bool allow) {

        ProtocolPtr pp = get_protocol(name);
        if (pp) {
		if (allow) {
			pp->setDomainNameManager(dnm);
		} else {
			pp->setDomainNameBanManager(dnm);
		}	
        }
}
#if defined(RUBY_BINDING) || defined(LUA_BINDING) || defined(JAVA_BINDING) || defined(GO_BINDING)

void NetworkStack::setDomainNameManager(const DomainNameManager &dnm, const std::string &name) {

	auto dm = std::make_shared<DomainNameManager>(dnm);

	setDomainNameManager(dm, name);
}

void NetworkStack::setDomainNameManager(const DomainNameManager &dnm, const std::string &name, bool allow) {

	auto dm = std::make_shared<DomainNameManager>(dnm);

	setDomainNameManager(dm, name, allow);
}

#endif

void NetworkStack::enable_protocol(const ProtocolPtr &proto, const SharedPointer<FlowForwarder> &ff) {

        auto f = proto->getFlowForwarder().lock();

        if ((ff)and(f)) {
                proto->setActive(true);
                ff->insertUpFlowForwarder(f);
        }
}

void NetworkStack::disable_protocol(const ProtocolPtr &proto, const SharedPointer<FlowForwarder> &ff) {

        auto f = proto->getFlowForwarder().lock();

        if ((ff)and(f)) {
                proto->setActive(false);
                ff->removeUpFlowForwarder(f);
        }
}

#if defined(BINDING)

void NetworkStack::enableProtocol(const std::string &name) {

        ProtocolPtr proto = get_protocol(name);
        if ((proto) and (!proto->isActive())) {
                if (proto->getProtocolLayer() == IPPROTO_UDP) {
                        enable_protocol(proto, ff_udp_current_);
                } else if (proto->getProtocolLayer() == IPPROTO_TCP) {
                        enable_protocol(proto, ff_tcp_current_);
                }
        }
}

void NetworkStack::disableProtocol(const std::string &name) {

        ProtocolPtr proto = get_protocol(name);

        if ((proto) and (proto->isActive())) {
                if (proto->getProtocolLayer() == IPPROTO_UDP) {
                        disable_protocol(proto, ff_udp_current_);
                } else if (proto->getProtocolLayer() == IPPROTO_TCP) {
                        disable_protocol(proto, ff_tcp_current_);
                }
        }
}

#if defined(PYTHON_BINDING)
void NetworkStack::showCache(const std::string &name) {

        ProtocolPtr pp = get_protocol(name);

        if (pp) {
                pp->showCache(OutputManager::getInstance()->out());
        }
}

void NetworkStack::setUDPDatabaseAdaptor(boost::python::object &dbptr) {

	setUDPDatabaseAdaptor(dbptr, default_update_frequency);
}
#elif defined(RUBY_BINDING)
void NetworkStack::setUDPDatabaseAdaptor(VALUE dbptr) {

	setUDPDatabaseAdaptor(dbptr, default_update_frequency);
}
#elif defined(JAVA_BINDING) || defined(GO_BINDING) 
void NetworkStack::setUDPDatabaseAdaptor(DatabaseAdaptor *dbptr) {

	setUDPDatabaseAdaptor(dbptr, default_update_frequency);
}
#elif defined(LUA_BINDING)
void NetworkStack::setUDPDatabaseAdaptor(lua_State *L, const char *obj_name) {

	setUDPDatabaseAdaptor(L, obj_name, default_update_frequency);
}
#endif

#if defined(PYTHON_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(boost::python::object &dbptr) {

	setTCPDatabaseAdaptor(dbptr, default_update_frequency);
}
#elif defined(RUBY_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(VALUE dbptr) {

	setTCPDatabaseAdaptor(dbptr, default_update_frequency);
}
#elif defined(JAVA_BINDING) || defined(GO_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(DatabaseAdaptor *dbptr) {
	
	setTCPDatabaseAdaptor(dbptr, default_update_frequency);
}
#elif defined(LUA_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(lua_State *L, const char* obj_name) {
	
	setTCPDatabaseAdaptor(L,obj_name, default_update_frequency);
}
#endif

#if defined(PYTHON_BINDING)
void NetworkStack::setUDPDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling) {
#elif defined(RUBY_BINDING)
void NetworkStack::setUDPDatabaseAdaptor(VALUE dbptr, int packet_sampling) {
#elif defined(JAVA_BINDING) || defined(GO_BINDING) 
void NetworkStack::setUDPDatabaseAdaptor(DatabaseAdaptor *dbptr, int packet_sampling) {
#elif defined(LUA_BINDING)
void NetworkStack::setUDPDatabaseAdaptor(lua_State *L, const char *obj_name, int packet_sampling) {
#endif
        ProtocolPtr pp = get_protocol(UDPProtocol::default_name);
        if (pp) {
                UDPProtocolPtr proto = std::static_pointer_cast<UDPProtocol>(pp);
                if (proto) {
#if defined(LUA_BINDING)
                        proto->setDatabaseAdaptor(L, obj_name, packet_sampling);
#else
                        proto->setDatabaseAdaptor(dbptr, packet_sampling);
#endif
                }
        }
}

#if defined(PYTHON_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling) {
#elif defined(RUBY_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(VALUE dbptr, int packet_sampling) {
#elif defined(JAVA_BINDING) || defined(GO_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(DatabaseAdaptor *dbptr, int packet_sampling) {
#elif defined(LUA_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(lua_State *L, const char *obj_name, int packet_sampling) {
#endif
        ProtocolPtr pp = get_protocol(TCPProtocol::default_name);
        if (pp) {
                TCPProtocolPtr proto = std::static_pointer_cast<TCPProtocol>(pp);
                if (proto) {
#if defined(LUA_BINDING)
                        proto->setDatabaseAdaptor(L, obj_name, packet_sampling);
#else
                        proto->setDatabaseAdaptor(dbptr, packet_sampling);
#endif
                }
        }
}

#if defined(PYTHON_BINDING)
void NetworkStack::setAnomalyCallback(PyObject *callback, const std::string &proto_name) {
#elif defined(RUBY_BINDING)
void NetworkStack::setAnomalyCallback(VALUE callback, const std::string &proto_name) {
#elif defined(JAVA_BINDING)
void NetworkStack::setAnomalyCallback(JaiCallback *callback, const std::string &proto_name) {
#elif defined(LUA_BINDING)
void NetworkStack::setAnomalyCallback(lua_State *L, const std::string &callback, const std::string &proto_name) {
#elif defined(GO_BINDING)
void NetworkStack::setAnomalyCallback(GoaiCallback *callback, const std::string &proto_name) {
#endif
	if (anomaly_) {
#if defined(LUA_BINDING)
		anomaly_->setCallback(L, callback, proto_name);
#else
		anomaly_->setCallback(callback, proto_name);
#endif
	}
}

#endif

#if defined(PYTHON_BINDING)

boost::python::dict NetworkStack::getCounters(const std::string &name) {
	boost::python::dict counters;
        ProtocolPtr pp = get_protocol(name);
        
	if (pp) {
		CounterMap cm = pp->getCounters();
        	counters = cm.getRawCounters();
        }

        return counters;
}

boost::python::dict NetworkStack::getCache(const std::string &name) {
        boost::python::dict cache;
        ProtocolPtr pp = get_protocol(name);

        if (pp) {
                cache = pp->getCache();
        }

        return cache;
}

#elif defined(RUBY_BINDING)

VALUE NetworkStack::getCounters(const std::string &name) {
	VALUE counters = Qnil;
	ProtocolPtr pp = get_protocol(name);

	if (pp) {
		CounterMap cm = pp->getCounters();
        	counters = cm.getRawCounters();
	}
	
	return counters;
}

VALUE NetworkStack::getCache(const std::string &name) {
	VALUE cache = Qnil;
	ProtocolPtr pp = get_protocol(name);

	if (pp) {
		cache = pp->getCache();
	}

	return cache;
}

#elif defined(JAVA_BINDING) || defined(GO_BINDING)

std::map<std::string, int32_t> NetworkStack::getCounters(const std::string &name) {
	std::map<std::string, int32_t> counters;

        ProtocolPtr pp = get_protocol(name);

        if (pp) {
		CounterMap cm = pp->getCounters();
        	counters = cm.getRawCounters();
        }

	return counters;
}

#elif defined(LUA_BINDING)

std::map<std::string, int> NetworkStack::getCounters(const char *name) {
	std::map<std::string, int> counters;
	std::string sname(name);

        ProtocolPtr pp = get_protocol(sname);

        if (pp) {
		CounterMap cm = pp->getCounters();
        	counters = cm.getRawCounters();
	}
	return counters;
}

#endif

void NetworkStack::releaseCache(const std::string &name) {

	ProtocolPtr proto = get_protocol(name);

        if (proto) {
        	proto->releaseCache();
        }
}

void NetworkStack::releaseCaches() {

	std::for_each (proto_vector_.begin(), proto_vector_.end(), [&] (ProtocolPair const &pp) {
        	ProtocolPtr proto = pp.second;

                proto->releaseCache();
        });
}

void NetworkStack::enableFlowForwarders(const std::initializer_list<SharedPointer<FlowForwarder>> &ffs) {

	SharedPointer<FlowForwarder> head_ff = *(ffs.begin());

	for (auto f = ffs.begin() + 1; f != ffs.end(); ++f) {
		ProtocolPtr proto = (*f)->getProtocol();

                proto->setActive(true);
                head_ff->addUpFlowForwarder(proto->getFlowForwarder().lock());
	}
}

void NetworkStack::disableFlowForwarders(const std::initializer_list<SharedPointer<FlowForwarder>> &ffs) {

	SharedPointer<FlowForwarder> head_ff = *(ffs.begin());

	for (auto f = ffs.begin() + 1; f != ffs.end(); ++f) {
		ProtocolPtr proto = (*f)->getProtocol();

		disable_protocol(proto, head_ff);
	}
}

void NetworkStack::infoMessage(const std::string &msg) {
#ifdef HAVE_LIBLOG4CXX
        LOG4CXX_INFO(logger, msg);
#else
	aiengine::information_message(msg);
#endif
}

void NetworkStack::enableLinkLayerTagging(const std::string &type) {

	// set as unactive 
	vlan->setActive(false);
	mpls->setActive(false);
	pppoe->setActive(false);

        if (type.compare("vlan") == 0) {
                mux_eth->addUpMultiplexer(mux_vlan, ETHERTYPE_VLAN);
                mux_vlan->addDownMultiplexer(mux_eth);
                mux_vlan->addUpMultiplexer(mux_ip, mux_ip->getProtocolIdentifier());
                mux_ip->addDownMultiplexer(mux_vlan);
		link_layer_tag_name_ = type;
		vlan->setActive(true);
        } else if (type.compare("mpls") == 0) {
                mux_eth->addUpMultiplexer(mux_mpls, ETHERTYPE_MPLS);
                mux_mpls->addDownMultiplexer(mux_eth);
                mux_mpls->addUpMultiplexer(mux_ip, mux_ip->getProtocolIdentifier());
                mux_ip->addDownMultiplexer(mux_mpls);
		link_layer_tag_name_ = type;
		mpls->setActive(true);
        } else if (type.compare("pppoe") == 0) {
                mux_eth->addUpMultiplexer(mux_pppoe, ETHERTYPE_PPPOE);
                mux_pppoe->addDownMultiplexer(mux_eth);
                mux_pppoe->addUpMultiplexer(mux_ip, mux_ip->getProtocolIdentifier());
                mux_ip->addDownMultiplexer(mux_pppoe);
		link_layer_tag_name_ = type;
		pppoe->setActive(true);
        } else {
                std::ostringstream msg;
                msg << "Unknown tagging type " << type;

                infoMessage(msg.str());
		link_layer_tag_name_ = "";
        }
}

void NetworkStack::increaseAllocatedMemory(const std::string &name, int value) {

        ProtocolPtr proto = get_protocol(name);
        if (proto) {
        	std::ostringstream msg;
                msg << "Increase allocated memory in " << value << " on " << name << " protocol";

                infoMessage(msg.str());

                proto->increaseAllocatedMemory(value);
        }
}

void NetworkStack::decreaseAllocatedMemory(const std::string &name,int value) {

        ProtocolPtr proto = get_protocol(name);
        if (proto) {
        	std::ostringstream msg;
                msg << "Decrease allocated memory in " << value << " on " << name << " protocol";

                infoMessage(msg.str());

                proto->decreaseAllocatedMemory(value);
        }
}

void NetworkStack::setDynamicAllocatedMemory(const std::string &name, bool value) {
        
	ProtocolPtr proto = get_protocol(name);
        if (proto) {
		proto->setDynamicAllocatedMemory(value);
	}	
}

void NetworkStack::setDynamicAllocatedMemory(bool value) {
	
	std::for_each (proto_vector_.begin(), proto_vector_.end(), [&] (ProtocolPair const &pp) {
        	ProtocolPtr proto = pp.second;

                proto->setDynamicAllocatedMemory(value);
        });
}

#if defined(JAVA_BINDING)

void NetworkStack::setTCPRegexManager(RegexManager *sig) { 

	if (sig == nullptr) {
		tcp_regex_mng_.reset();
	} else {
		SharedPointer<RegexManager> rm(sig);

		setTCPRegexManager(rm); 
	}
}

void NetworkStack::setUDPRegexManager(RegexManager *sig) { 
	
	if (sig == nullptr) {
		udp_regex_mng_.reset();
	} else {
		SharedPointer<RegexManager> rm(sig);

		setUDPRegexManager(rm); 
	}
}

#endif

void NetworkStack::showProtocolSummary(std::basic_ostream<char> &out) const { 

	const char *header = "%-14s %-14s %-12s %-8s %-10s %-14s %-14s %-14s %-8s %-10s";
	const char *format = "%-14s %-14d %-12d %-8d %-10d %-14s %-14s %-14s %-8s %-10s";
	int64_t total_packets = 0;
	int64_t total_bytes = 0;
	int64_t total_memory = 0;
	int64_t total_used_memory = 0;
	int64_t total_map_memory = 0;
	int32_t total_cmiss = 0;
	int32_t total_events = 0;

        ProtocolPtr proto = get_protocol("EthernetProtocol");
        if (proto) {
		total_packets = proto->getTotalPackets();
		total_bytes = proto->getTotalBytes();
	}	

	out << "Protocol statistics summary" << std::endl;
	out << "\t" << boost::format(header) % "Protocol" % "Bytes" % "Packets" % "% Bytes" % "CacheMiss" % "Memory" % "UseMemory" % "CacheMemory" % "Dynamic" % "Events";
	out << std::endl;

	for (auto &&pp: proto_vector_) {
		ProtocolPtr proto = pp.second;

		if (!proto->isActive()) continue;

		std::string cad(proto->getName());
		std::string name;

		std::string::size_type i = cad.find("Protocol");
		if (i != std::string::npos)
   			name = cad.substr(0, i);	

		i = cad.find(" "); // the protocol name could have extra info
		if (i != std::string::npos)
			name = name + cad.substr(i);

		int64_t packets = proto->getTotalPackets();
		int64_t bytes = proto->getTotalBytes();
		int32_t cmiss = proto->getTotalCacheMisses();

		int64_t per = 0;
		if (total_bytes > 0) 
			per = ( bytes * 100.00) / total_bytes; 

		const char *dynamic_mem = proto->isDynamicAllocatedMemory() ? "yes": "no";

		std::string unit = "Bytes";
		std::string used_unit = "Bytes";
		std::string map_unit = "Bytes";
		int64_t memory = proto->getTotalAllocatedMemory();
		int64_t map_memory = memory - proto->getAllocatedMemory();
		int64_t used_memory = proto->getCurrentUseMemory();
		int32_t events = proto->getTotalEvents();

		total_events += events;
		total_cmiss += cmiss;
		total_memory += memory;
		total_used_memory += used_memory;
		total_map_memory += map_memory;
		
		unitConverter(memory, unit);
		unitConverter(used_memory, used_unit);
		unitConverter(map_memory, map_unit);

		std::ostringstream s_mem;
		s_mem << memory << " " << unit;	
		
		std::ostringstream s_used_mem;
		s_used_mem << used_memory << " " << used_unit;	

		std::ostringstream s_map_mem;
		s_map_mem << map_memory << " " << map_unit;	

		out << "\t" << boost::format(format) % name  % bytes % packets % per % cmiss % s_mem.str() % s_used_mem.str() % s_map_mem.str() % dynamic_mem % events;
		out << "\n";
	}
	// The Total 
	std::string unit = "Bytes";
	std::string used_unit = "Bytes";
	std::string map_unit = "Bytes";

	unitConverter(total_memory, unit);
	unitConverter(total_used_memory, used_unit);
	unitConverter(total_map_memory, map_unit);

	std::ostringstream s_mem;
	s_mem << total_memory << " " << unit;	

	std::ostringstream s_used_mem;
	s_used_mem << total_used_memory << " " << used_unit;	

	std::ostringstream s_map_mem;
	s_map_mem << total_map_memory << " " << map_unit;

	out << "\t" << boost::format(format) % "Total"  % total_bytes % total_packets % 100 % total_cmiss % s_mem.str() % s_used_mem.str() % s_map_mem.str() % "" % total_events; 
	out << "\n";
	out << std::endl;
}

} // namespace aiengine
