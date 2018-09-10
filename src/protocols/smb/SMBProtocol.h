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
#ifndef SRC_PROTOCOLS_SMB_SMBPROTOCOL_H_
#define SRC_PROTOCOLS_SMB_SMBPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "SMBInfo.h"
#include <arpa/inet.h>
#include "flow/FlowManager.h"
#include "Cache.h"

namespace aiengine {

#define SMB_VERSION 2 

struct smb_netbios_header {
	uint16_t 	nb_padd;   	/* From netbios */ 
    	uint16_t 	nb_length;    	/* From netbios */
	uint8_t 	data[0];
} __attribute__((packed));

struct smb_v1_header {
	uint8_t 	token;
    	uint8_t 	data[3];     
	uint8_t 	cmd;
	uint32_t 	status;
	uint8_t 	flags; 
    	uint8_t 	pad[22];     
} __attribute__((packed)); 

struct smb_v2_header {
	uint8_t 	token;
    	uint8_t 	data[3];     
	uint16_t 	length;
	uint16_t 	credit_charge;
	uint16_t 	channel_sequence;
	uint16_t 	res;
	uint16_t 	cmd; 
	uint16_t 	credit_request;
	uint32_t 	flags;	
	uint32_t 	chain_offset;	
    	uint8_t 	msg_id[8];   
	uint32_t 	process_id; 
	uint32_t 	tree_id; 
    	uint8_t 	session_id[8];   
    	uint8_t 	signature[16];   
} __attribute__((packed));
 
struct smb_v2_create_file_request {
	uint8_t 	struct_size[3];
	uint8_t 	lock;
	uint32_t 	impersonation;
	uint8_t 	flags[16];
	uint32_t 	access_mask;
	uint32_t 	file_attributes;
	uint32_t 	share_access;
	uint32_t 	disposition;
	uint32_t 	create_options;
	uint16_t 	filename_offset;
	uint16_t 	filename_length;
	uint8_t 	data[0];
} __attribute__((packed)); 

struct smb_v1_create_file_request {
        uint8_t 	word_count;
	uint16_t 	file_attributes;
	uint32_t 	timestamp;
	uint16_t 	byte_count;
	uint8_t 	buffer_format;
        uint8_t 	data[0];
} __attribute__((packed)); 

struct smb_v1_create_directory_request {
        uint8_t 	word_count;
        uint16_t 	byte_count;
        uint8_t 	buffer_format;
        uint8_t 	data[0];
} __attribute__((packed)); 

struct smb_v1_open_and_request {
	uint8_t 	word_count;
	uint8_t 	xcmd;
	uint8_t 	res1;
	uint16_t 	offset;
	uint16_t 	flags;
	uint16_t 	access;
	uint16_t 	sattrib;
	uint16_t 	fattrib;
	uint32_t 	timestamp;
	uint16_t 	openfunc;
	uint32_t 	alloc_size;
	uint32_t 	timeout;
	uint32_t 	res2;
	uint16_t 	byte_count;
	uint8_t 	data[0];
} __attribute__((packed)); 

// http://www.timothydevans.me.uk/nbf2cifs/smb-smbcommandcode.html
enum smb1_commands {
        SMB_CMD_CREATE_DIR = 	0x00,
        SMB_CMD_DELETE_DIR = 	0x01,
        SMB_CMD_OPEN_FILE = 	0x02,
        SMB_CMD_CREATE_FILE = 	0x03,
        SMB_CMD_CLOSE_FILE = 	0x04,
        SMB_CMD_FLUSH_FILES = 	0x05,
        SMB_CMD_DELETE_FILE = 	0x06,
        SMB_CMD_RENAME_FILE = 	0x07,
        SMB_CMD_GET_FILE_ATTR = 0x08,
        SMB_CMD_SET_FILE_ATTR = 0x09,

	SMB_CMD_TRANS = 	0x25,
	SMB_CMD_OPEN_ANDX =	0x2D,
	SMB_CMD_READ =		0x2E,
	SMB_CMD_WRITE_ANDX =	0x2F,
	SMB_CMD_TRANS2 =	0x32,

        SMB_CMD_TREE_DISC =	0x71,
	SMB_CMD_NEGO_PROTO =	0x72,
	SMB_CMD_SESSION_SETUP =	0x73,
        SMB_CMD_LOGOFF =  	0x74,
	SMB_CMD_TREE_CONNECT =	0x75,

	SMB_CMD_NT_CREATE =	0xA2
};

enum smb2_commands {
	SMB2_CMD_TREE_CONNECT =	0x03,
	SMB2_CMD_CREATE_FILE = 	0x05,
	SMB2_CMD_CLOSE_FILE = 	0x06,
	SMB2_CMD_READ_FILE = 	0x08,
	SMB2_CMD_WRITE_FILE = 	0x09,
	SMB2_CMD_GET_INFO =	0x10
};

class SMBProtocol: public Protocol {
public:
    	explicit SMBProtocol();
    	virtual ~SMBProtocol();

	static const uint16_t id = 0;	
	static constexpr int header_size = 8;

	int getHeaderSize() const { return header_size;}

        void processFlow(Flow *flow) override;
        bool processPacket(Packet& packet) override { return true; } 

	void statistics(std::basic_ostream<char>& out, int level) override;

	void releaseCache() override; 

	void setHeader(const uint8_t *raw_packet) override { 

		header_ = raw_packet;
	}

	// Condition for say that a packet is rtp
	bool smbChecker(Packet &packet); 

        void increaseAllocatedMemory(int value) override;
        void decreaseAllocatedMemory(int value) override;

        void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }
	
	int64_t getCurrentUseMemory() const override; 
	int64_t getAllocatedMemory() const override;
	int64_t getTotalAllocatedMemory() const override;

        void setDynamicAllocatedMemory(bool value) override;
        bool isDynamicAllocatedMemory() const override; 

        int32_t getTotalCacheMisses() const override;
        int32_t getTotalEvents() const override { return total_events_; }

	void releaseFlowInfo(Flow *flow) override;

	CounterMap getCounters() const override; 

        void setAnomalyManager(SharedPointer<AnomalyManager> amng) override { anomaly_ = amng; }

	Flow *getCurrentFlow() const { return current_flow_; }

#if defined(PYTHON_BINDING)
        boost::python::dict getCache() const override;
        void showCache(std::basic_ostream<char> &out) const override;
#elif defined(RUBY_BINDING)
        VALUE getCache() const;
#endif

private:
	void update_command_type_v1(uint16_t cmd);
	void update_command_type_v2(uint16_t cmd);
	void create_request_file_v2(SMBInfo *info, const uint8_t *payload, int length);
	void create_request_file_v1(SMBInfo *info, const uint8_t *payload, int length);
	void create_request_directory_v1(SMBInfo *info, const uint8_t *payload, int length);
	void open_and_request_v1(SMBInfo *info, const uint8_t *payload, int length);

        void attach_filename(SMBInfo *info, const boost::string_ref &name);
        int32_t release_smb_info(SMBInfo *info);
        int64_t compute_memory_used_by_maps() const;
	bool is_minimal_smb_header(const uint8_t *hdr);

	const uint8_t *header_;

	// Some statistics 
	int32_t total_create_dirs_;
	int32_t total_delete_dirs_;
	int32_t total_open_files_;
	int32_t total_create_files_;
	int32_t total_close_files_;
	int32_t total_commit_files_;
	int32_t total_delete_files_;
	int32_t total_rename_files_;
	int32_t total_get_file_attribs_;
	int32_t total_set_file_attribs_;
	int32_t total_tree_disconnects_;
	int32_t total_negotiate_protocol_;
	int32_t total_session_setups_;
	int32_t total_logoff_and_request_;
	int32_t total_tree_connects_;
	int32_t total_trans_;
	int32_t total_reads_;
	int32_t total_writes_;
	int32_t total_nt_creates_;
	int32_t total_others_;
	int32_t total_events_;

	Cache<SMBInfo>::CachePtr info_cache_;
        Cache<StringCache>::CachePtr filename_cache_;

        GenericMapType filename_map_;

        Flow *current_flow_;
	FlowManagerPtrWeak flow_mng_;
        SharedPointer<AnomalyManager> anomaly_;
#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<SMBProtocol> SMBProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SMB_SMBPROTOCOL_H_
