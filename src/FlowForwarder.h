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
#ifndef SRC_FLOWFORWARDER_H_
#define SRC_FLOWFORWARDER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Flow.h"
#include "Packet.h"
#include <iostream>
#include <memory>
#include <functional>
#include <vector>
#include <algorithm>

namespace aiengine {

class Protocol;
typedef std::shared_ptr<Protocol> ProtocolPtr;

class FlowForwarder 
{
public:
    	explicit FlowForwarder(); 
    	virtual ~FlowForwarder() {}

    	void insertUpFlowForwarder(WeakPointer<FlowForwarder> ff); 
    	void addUpFlowForwarder(WeakPointer<FlowForwarder> ff);
    	void removeUpFlowForwarder(); 
    	void removeUpFlowForwarder(WeakPointer<FlowForwarder> ff); 

	void forwardFlow(Flow *flow);

        void statistics(std::basic_ostream<char>& out);
        void statistics() { statistics(std::cout); };

	void setProtocol(ProtocolPtr proto) { proto_ = proto; }
	ProtocolPtr getProtocol() { return proto_; }

	bool acceptPacket(Packet& packet) const { return check_func_(packet); }
	void addChecker(std::function <bool (Packet&)> checker) { check_func_ = checker; }
	void addFlowFunction(std::function <void (Flow*)> flow_func) { flow_func_ = flow_func; }

	int64_t getTotalForwardFlows() const { return total_forward_flows_; }
	int64_t getTotalFailFlows() const { return total_fail_flows_; }
	int64_t getTotalReceivedFlows() const { return total_received_flows_; }

	void incTotalReceivedFlows() { ++total_received_flows_; }
private:
	ProtocolPtr proto_;
	int64_t total_received_flows_;
	int64_t total_forward_flows_;
	int64_t total_fail_flows_;
	WeakPointer<FlowForwarder> muxDown_;
	uint16_t protocol_id_; // the protocol analiyzer owned by the multiplexer
    	std::vector<WeakPointer<FlowForwarder>> flowForwarderVector_;
	std::function <void (Flow*)> flow_func_;
	std::function <bool (Packet&)> check_func_;	
};

} // namespace aiengine

#endif  // SRC_FLOWFORWARDER_H_
