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
#ifndef SRC_PROTOCOLS_MODBUS_MODBUSPROTOCOL_H_
#define SRC_PROTOCOLS_MODBUS_MODBUSPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

struct modbus_tcp_header {
	uint16_t 	op;		/* Transaction id */
	uint16_t 	proto;		/* Protocol id */
	uint16_t 	length;		/* Transaction id */
	uint8_t 	unitid;		/* Unit id */
	uint8_t 	data[0];
} __attribute__((packed));

struct modbus_header {
        uint8_t       	code;           /* Function code */
        uint16_t       	proto;          /* Ref number */
	uint8_t 	data[0];
} __attribute__((packed));

enum modbus_type_function_code {
	MB_CODE_READ_COILS = 1,
	MB_CODE_READ_DISCRETE_INPUTS = 2,
	MB_CODE_READ_HOLDING_REGISTERS = 3,
	MB_CODE_READ_INPUT_REGISTERS = 4,
	MB_CODE_WRITE_SINGLE_COIL = 5,
	MB_CODE_WRITE_SINGLE_REGISTER = 6,
	MB_CODE_WRITE_MULTIPLE_COILS = 15,
	MB_CODE_WRITE_MULTIPLE_REGISTERS = 16
};

class ModbusProtocol: public Protocol {
public:
    	explicit ModbusProtocol();
    	virtual ~ModbusProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(modbus_tcp_header);

	int getHeaderSize() const { return header_size; }

        void processFlow(Flow *flow) override;
        bool processPacket(Packet &packet) override { return true; } 

	void statistics(std::basic_ostream<char> &out, int level) override;

	void releaseCache() override {} // No need to free cache

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = reinterpret_cast <const modbus_tcp_header*> (raw_packet);
	}

	// Condition for say that a packet is dhcp 
	bool modbusChecker(Packet &packet); 

	int64_t getCurrentUseMemory() const override { return sizeof(ModbusProtocol); }
	int64_t getAllocatedMemory() const override { return sizeof(ModbusProtocol); }
	int64_t getTotalAllocatedMemory() const override { return sizeof(ModbusProtocol); }
	int64_t getAllocatedMemory(int value) const { return sizeof(ModbusProtocol); }

        void setDynamicAllocatedMemory(bool value) override {}
        bool isDynamicAllocatedMemory() const override { return false; }	

	CounterMap getCounters() const override; 

private:
	const modbus_tcp_header *header_;

	// Some statistics 
	int32_t total_read_coils_;
	int32_t total_read_discrete_inputs_;
	int32_t total_read_holding_registers_;
	int32_t total_read_input_registers_;
	int32_t total_write_single_coil_;
	int32_t total_write_single_register_;
	int32_t total_write_multiple_coils_;
	int32_t total_write_multiple_registers_;
	int32_t total_others_;
};

typedef std::shared_ptr<ModbusProtocol> ModbusProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_MODBUS_MODBUSPROTOCOL_H_
