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
#include "ModbusProtocol.h"
#include <iomanip>

namespace aiengine {

ModbusProtocol::ModbusProtocol():
	Protocol("ModbusProtocol", "modbus", IPPROTO_TCP),
	header_(nullptr),
	total_read_coils_(0),
	total_read_discrete_inputs_(0),
	total_read_holding_registers_(0),
	total_read_input_registers_(0),
	total_write_single_coil_(0),
	total_write_single_register_(0),
	total_write_multiple_coils_(0),
	total_write_multiple_registers_(0),
        total_others_(0) {}

bool ModbusProtocol::modbusChecker(Packet &packet) {

	int length = packet.getLength();

	if (length >= header_size) {
		if ((packet.getSourcePort() == 502)||(packet.getDestinationPort() == 502)) {
			setHeader(packet.getPayload());
			++total_valid_packets_;
			return true;
		}
	}
	++total_invalid_packets_;
	return false;
}

void ModbusProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;

	++total_packets_;

	if (length > header_size) {
		setHeader(flow->packet->getPayload());	
		if (ntohs(header_->length) >= sizeof(modbus_header)) {
			const modbus_header *hdr = reinterpret_cast<const modbus_header*>(header_->data);

			if (hdr->code == MB_CODE_READ_COILS ) {
				++total_read_coils_;
			} else if (hdr->code == MB_CODE_READ_DISCRETE_INPUTS ) {
				++total_read_discrete_inputs_;
			} else if (hdr->code == MB_CODE_READ_HOLDING_REGISTERS ) {
				++total_read_holding_registers_;
			} else if (hdr->code == MB_CODE_READ_INPUT_REGISTERS ) {
				++total_read_input_registers_;
			} else if (hdr->code == MB_CODE_WRITE_SINGLE_COIL ) {
				++total_write_single_coil_;
			} else if (hdr->code == MB_CODE_WRITE_SINGLE_REGISTER ) {
				++total_write_single_register_;
			} else if (hdr->code == MB_CODE_WRITE_MULTIPLE_COILS ) {
				++total_write_multiple_coils_;
			} else if (hdr->code == MB_CODE_WRITE_MULTIPLE_REGISTERS ) {
				++total_write_multiple_registers_;
			} else {
				++total_others_;
			}
		}
	}
}

void ModbusProtocol::statistics(std::basic_ostream<char> &out, int level) { 

	if (level > 0) {
                int64_t alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory, unit);

                out << getName() << "(" << this <<") statistics" << std::dec << "\n";
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit << "\n";
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ << "\n";
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ << std::endl;
		if (level > 1) {
                        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ << "\n";
                        out << "\t" << "Total invalid packets:  " << std::setw(10) << total_invalid_packets_ << "\n";
                        if (level > 3) {
                                out << "\t" << "Total read coils:       " << std::setw(10) << total_read_coils_ << "\n";
                                out << "\t" << "Total read dis inputs:  " << std::setw(10) << total_read_discrete_inputs_ << "\n";
                                out << "\t" << "Total read hold regs:   " << std::setw(10) << total_read_holding_registers_ << "\n";
                                out << "\t" << "Total read input regs:  " << std::setw(10) << total_read_input_registers_ << "\n";
                                out << "\t" << "Total write single coil:" << std::setw(10) << total_write_single_coil_  << "\n";
                                out << "\t" << "Total write multi coils:" << std::setw(10) << total_write_multiple_coils_ << "\n";
                                out << "\t" << "Total write multi regs: " << std::setw(10) << total_write_multiple_registers_ << "\n"; 
                                out << "\t" << "Total others:           " << std::setw(10) << total_others_ << std::endl;
                        }
			if (level > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
			}
		}
	}
}

CounterMap ModbusProtocol::getCounters() const {
  	CounterMap cm;
 
        cm.addKeyValue("packets",total_packets_);
        cm.addKeyValue("bytes", total_bytes_);

	cm.addKeyValue("read coils", total_read_coils_ );
	cm.addKeyValue("read dis inputs", total_read_discrete_inputs_ );
	cm.addKeyValue("read hold regs", total_read_holding_registers_ );
	cm.addKeyValue("read input regs", total_read_input_registers_ );
	cm.addKeyValue("write single coil", total_write_single_coil_ );
	cm.addKeyValue("write multi coils", total_write_multiple_coils_ );
	cm.addKeyValue("write multi regs", total_write_multiple_registers_ );
	cm.addKeyValue("others", total_others_ );

        return cm;
}

} // namespace aiengine
