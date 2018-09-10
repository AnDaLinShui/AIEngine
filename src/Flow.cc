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
#include "Flow.h"
#include "Protocol.h"

namespace aiengine {

void Flow::setFiveTuple(uint32_t src_a, uint16_t src_p, uint16_t proto, uint32_t dst_a, uint16_t dst_p) {

	address_.setSourceAddress(src_a);
	address_.setDestinationAddress(dst_a);
	address_.setType(IPPROTO_IP);
	source_port_ = src_p;
	dest_port_ = dst_p;
	protocol_ = proto;
}

void Flow::setFiveTuple6(struct in6_addr *src_a, uint16_t src_p, uint16_t proto, struct in6_addr *dst_a, uint16_t dst_p) {

        address_.setSourceAddress6(src_a);
        address_.setDestinationAddress6(dst_a);
	address_.setType(IPPROTO_IPV6);
        source_port_ = src_p;
        dest_port_ = dst_p;
        protocol_ = proto;
}

void Flow::reset() {

	hash_ = 0;
	total_bytes = 0;
	total_packets = 0;
	total_packets_l7 = 0;
	address_.reset();
	source_port_ = 0;
	dest_port_ = 0;
	protocol_ = 0;
	have_tag_ = false;
	reject_ = false;
	partial_reject_ = false;
	have_evidence_ = false;
	write_matched_packet_ = false;
	tag_ = 0xFFFFFFFF;
	ipset.reset();
	forwarder.reset();

	// Reset layer4 object attach
	layer4info.reset();
	// Reset layer7 object attach
	layer7info.reset();

	// Reset frequencies objects
	frequencies.reset();
	packet_frequencies.reset();

	regex.reset();
	regex_mng.reset();
	packet = nullptr;
	frequency_engine_inspected_ = false;
	prev_direction_ = direction_ = FlowDirection::FORWARD;
	pa_ = PacketAnomalyType::NONE;
	arrive_time_ = 0;
	current_time_ = 0;
	label_.reset();
#if defined(BINDING)
        is_accept_ = true;
#endif
}

void Flow::serialize(std::ostream &stream) {

       	JsonFlow j;

#if !defined(RUBY_BINDING)
       	j.j["ip"]["src"] = address_.getSrcAddrDotNotation();
       	j.j["ip"]["dst"] = address_.getDstAddrDotNotation();
       	j.j["port"]["src"] = source_port_;
       	j.j["port"]["dst"] = dest_port_;
#else
       	std::map<std::string, json_map_t> addr;
       	std::map<std::string, json_map_t> port;

       	addr["src"] = address_.getSrcAddrDotNotation();
       	addr["dst"] = address_.getDstAddrDotNotation();
       	j.j["ip"] = addr;

       	port["src"] = source_port_;
       	port["dst"] = dest_port_;
       	j.j["port"] = port;
#endif
       	j.j["proto"] = protocol_;
       	j.j["bytes"] = total_bytes;

	if (!ipset.expired())
                j.j["ipset"] = ipset.lock()->getName();

	if (pa_ != PacketAnomalyType::NONE)
		j.j["anomaly"] = static_cast<std::int8_t>(pa_);

	j.j["layer7"] = getL7ShortProtocolName();

	if ((label_)and(label_->length() >0))
		j.j["label"] = label_->c_str();

	if (protocol_ == IPPROTO_TCP) {
		auto tinfo = getTCPInfo();
		if (tinfo)
			tinfo->serialize(j);

		if (auto hinfo = getHTTPInfo()) {
			hinfo->serialize(j);
		} else if (auto sinfo = getSSLInfo()) {
			sinfo->serialize(j);
		} else if (auto smtpinfo = getSMTPInfo()) {
			smtpinfo->serialize(j);
		} else if (auto popinfo = getPOPInfo()) {
			popinfo->serialize(j);
		} else if (auto iinfo = getIMAPInfo()) {
			iinfo->serialize(j);
		} else if (auto binfo = getBitcoinInfo()) {
			binfo->serialize(j);
		} else if (auto minfo = getMQTTInfo()) {
			minfo->serialize(j);
		} else if (auto sinfo = getSMBInfo()) {
			sinfo->serialize(j);
		} else if (auto sinfo = getSSHInfo()) {
			sinfo->serialize(j);
		} else if (auto dinfo = getDCERPCInfo()) {
			dinfo->serialize(j);
		}
	} else { // UDP
		if (auto dinfo = getDNSInfo()) {
			dinfo->serialize(j);
		} else if (auto sinfo = getSIPInfo()) {
			sinfo->serialize(j);
		} else if (auto ssdpinfo = getSSDPInfo()) {
			ssdpinfo->serialize(j);
		} else if (auto nbinfo = getNetbiosInfo()) {
			nbinfo->serialize(j);
		} else if (auto coapinfo = getCoAPInfo()) {
			coapinfo->serialize(j);
		} else if (auto dhcpinfo = getDHCPInfo()) {
			dhcpinfo->serialize(j);
		} else if (auto dhcpv6info = getDHCPv6Info()) {
			dhcpv6info->serialize(j);
		}

		auto ginfo = getGPRSInfo();
		if (ginfo)
			ginfo->serialize(j);
	}

        if (!regex.expired()) {
		j.j["matchs"] = regex.lock()->getName();
#if defined(BINDING)
		if (write_matched_packet_) {
			// If is force to write is because the current packet contains the issue
			const uint8_t *payload = packet->getPayload();
			std::vector<uint8_t> pkt;

			for (int i = 0; i < packet->getLength(); ++i)
				pkt.push_back(payload[i]);

			j.j["packet"] = pkt;

			write_matched_packet_ = false;
		}
#endif
	}
	// convert to string the json
	stream << j;
}

void Flow::showFlowInfo(std::ostream &out) const {

	if (haveTag() == true) {
        	out << " Tag:" << getTag();
        }

        if (getPacketAnomaly() != PacketAnomalyType::NONE)
		out << " Anomaly:" << getFlowAnomalyString();

        if (ipset.lock()) out << " IPset:" << ipset.lock()->getName();

	if (protocol_ == IPPROTO_TCP) {
		auto tinfo = getTCPInfo();
		if (tinfo) out << " TCP:" << *tinfo.get();

		if (auto hinfo = getHTTPInfo()) {
			out << *hinfo.get();
        	} else if (auto sinfo = getSSLInfo()) {
			out << *sinfo.get();
		} else if (auto smtpinfo = getSMTPInfo()) {
			out << *smtpinfo.get();
		} else if (auto popinfo = getPOPInfo()) {
			out << *popinfo.get();
		} else if (auto iinfo = getIMAPInfo()) {
			out << *iinfo.get();
		} else if (auto binfo = getBitcoinInfo()) {
			out << *binfo.get();
		} else if (auto minfo = getMQTTInfo()) {
			out << *minfo.get();
		} else if (auto sinfo = getSMBInfo()) {
			out << *sinfo.get();
		} else if (auto sinfo = getSSHInfo()) {
			out << *sinfo.get();
		} else if (auto dinfo = getDCERPCInfo()) {
			out << *dinfo.get();
		}
	} else {
		auto ginfo = getGPRSInfo();
		if (ginfo) {
			out << *ginfo.get();
		}

		if (auto dnsinfo = getDNSInfo()) {
			out << *dnsinfo.get();
		} else if (auto sipinfo = getSIPInfo()) {
			out << *sipinfo.get();
		} else if (auto ssdpinfo = getSSDPInfo()) {
			out << *ssdpinfo.get();
		} else if (auto nbinfo = getNetbiosInfo()) {
			out << *nbinfo.get();
		} else if (auto coapinfo = getCoAPInfo()) {
			out << *coapinfo.get();
		} else if (auto dhcpinfo = getDHCPInfo()) {
			out << *dhcpinfo.get();
		} else if (auto dhcpv6info = getDHCPv6Info()) {
			out << *dhcpv6info.get();
		}
	}

        if (!regex.expired()) out << " Regex:" << regex.lock()->getName();

	if (isPartialReject()) out << " Rejected";

	if (frequencies) {
		out << " Dispersion(" << frequencies->getDispersion() << ")";
		out << "Enthropy(" << std::setprecision(4) << frequencies->getEntropy() << ") ";
		out << boost::format("%-8s") % frequencies->getFrequenciesString();
	}
	return;
}


std::ostream& operator<< (std::ostream &out, const Flow &flow) {

	out << flow.address_.getSrcAddrDotNotation() << ":" << flow.getSourcePort() << ":" << flow.getProtocol();
        out << ":" << flow.address_.getDstAddrDotNotation() << ":" << flow.getDestinationPort();
        // out << " pkts:" << flow.total_packets << " l7pkts:" << flow.total_packets_l7 << " bytes:" << flow.total_bytes;
        return out;
}

const char* Flow::getL7ProtocolName() const {

	const char *proto_name = "None";

        if (forwarder.lock()) {
        	ProtocolPtr proto = forwarder.lock()->getProtocol();
                if (proto) proto_name = proto->getName();
	}
        return proto_name;
}

const char* Flow::getL7ShortProtocolName() const {

	const char *proto_name = "None";

        if (forwarder.lock()) {
        	ProtocolPtr proto = forwarder.lock()->getProtocol();
                if (proto) proto_name = proto->getShortName();
	}
        return proto_name;
}

#if defined(PYTHON_BINDING)
boost::python::list Flow::getPayload() const {
	const uint8_t *pkt = packet->getPayload();
	boost::python::list l;

	for (int i = 0; i < packet->getLength(); ++i)
		l.append(pkt[i]);

	return l;
}

void Flow::setRegexManager(const SharedPointer<RegexManager> &rm) {

	if (rm) {
    		regex_mng = rm;
		regex.reset(); // Remove the old Regex if present
	} else {
		// If have a regex dont remove the refence to it
		regex_mng.reset();
	}

}

#elif defined(RUBY_BINDING)
VALUE Flow::getPayload() const {
	VALUE arr = rb_ary_new2(packet->getLength());
	const uint8_t *pkt = packet->getPayload();

	for (int i = 0; i < packet->getLength(); ++i)
		rb_ary_push(arr, INT2NUM((short)pkt[i]));

	return arr;
}
#elif defined(LUA_BINDING)
RawPacket& Flow::getPacket() const {
	static RawPacket pkt(packet->getPayload(), packet->getLength());

	return pkt;
}

const char *Flow::__str__() {
    	std::ostringstream ss;
    	static char flowip[1024];

	ss << *this;
    	snprintf(flowip, 1024, "%s", ss.str().c_str());
    	return flowip;
}

#elif defined(JAVA_BINDING)
IPAbstractSet& Flow::getIPSet() const { return *ipset.lock().get();}
#endif

} // namespace aiengine
