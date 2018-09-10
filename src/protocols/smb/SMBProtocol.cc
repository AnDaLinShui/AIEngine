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
#include "SMBProtocol.h"
#include <iomanip>

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr SMBProtocol::logger(log4cxx::Logger::getLogger("aiengine.smb"));
#endif

SMBProtocol::SMBProtocol():
	Protocol("SMBProtocol", "smb", IPPROTO_TCP),
	header_(nullptr),
        total_create_dirs_(0),
        total_delete_dirs_(0),
        total_open_files_(0),
        total_create_files_(0),
        total_close_files_(0),
        total_commit_files_(0),
        total_delete_files_(0),
        total_rename_files_(0),
        total_get_file_attribs_(0),
        total_set_file_attribs_(0),
	total_tree_disconnects_(0),
        total_negotiate_protocol_(0),
        total_session_setups_(0),
	total_logoff_and_request_(0),
        total_tree_connects_(0),
        total_trans_(0),
        total_reads_(0),
        total_writes_(0),
        total_nt_creates_(0),
        total_others_(0),
        total_events_(0),
	info_cache_(new Cache<SMBInfo>("SMB Info cache")),
	filename_cache_(new Cache<StringCache>("Filename cache")),
	filename_map_(),
        current_flow_(nullptr),
        flow_mng_(),
        anomaly_() {}

SMBProtocol::~SMBProtocol() {

	anomaly_.reset();
}

bool SMBProtocol::is_minimal_smb_header(const uint8_t *hdr) {

	if ((hdr[0] == 0x00)and(hdr[1] == 0x00)) {
		if ((hdr[5] == 'S')and(hdr[6] == 'M')and(hdr[7] == 'B')) {
			return true;
		}
	}
	return false;
}

bool SMBProtocol::smbChecker(Packet &packet) {

	int length = packet.getLength();

	if (length >= 8) {
		setHeader(packet.getPayload());

		if (is_minimal_smb_header(header_)) {	
			++total_valid_packets_;
			return true;
		}
	}
	++total_invalid_packets_;
	return false;
}

void SMBProtocol::setDynamicAllocatedMemory(bool value) {

        info_cache_->setDynamicAllocatedMemory(value);
        filename_cache_->setDynamicAllocatedMemory(value);
}

bool SMBProtocol::isDynamicAllocatedMemory() const {

        return info_cache_->isDynamicAllocatedMemory();
}

int64_t SMBProtocol::getCurrentUseMemory() const {

        int64_t mem = sizeof(SMBProtocol);

        mem += info_cache_->getCurrentUseMemory();
        mem += filename_cache_->getCurrentUseMemory();

        return mem;
}

int64_t SMBProtocol::getAllocatedMemory() const {

        int64_t mem = sizeof(SMBProtocol);

        mem += info_cache_->getAllocatedMemory();
        mem += filename_cache_->getAllocatedMemory();

        return mem;
}

int64_t SMBProtocol::getTotalAllocatedMemory() const {

        int64_t mem = getAllocatedMemory();

	mem += compute_memory_used_by_maps();

        return mem;
}

int64_t SMBProtocol::compute_memory_used_by_maps() const {

        int64_t bytes = filename_map_.size() * sizeof(StringCacheHits);

        std::for_each (filename_map_.begin(), filename_map_.end(), [&bytes] (PairStringCacheHits const &f) {
                bytes += f.first.size();
        });
        return bytes;
}

void SMBProtocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
        filename_cache_->create(value);
}

void SMBProtocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
        filename_cache_->destroy(value);
}

int32_t SMBProtocol::release_smb_info(SMBInfo *info) {

        int32_t bytes_released = 0;

        bytes_released = releaseStringToCache(filename_cache_, info->filename);

        return bytes_released;
}

void SMBProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

                int64_t total_bytes_released = compute_memory_used_by_maps();
                int64_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;
		int32_t release_filename = filename_map_.size();

                for (auto &flow: ft) {
                        SharedPointer<SMBInfo> info = flow->getSMBInfo();
                        if (info) {
                                total_bytes_released_by_flows = release_smb_info(info.get());
                                total_bytes_released_by_flows += sizeof(info);        

                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(info);
                        }
                }
		filename_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released * 100) / total_bytes_released_by_flows);
                }

                msg.str("");
		msg << "Release " << release_filename << " file names, " << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}

void SMBProtocol::releaseFlowInfo(Flow *flow) {

	auto info = flow->getSMBInfo();
	if (info) {
		info_cache_->release(info);
	}
}

void SMBProtocol::attach_filename(SMBInfo *info, const boost::string_ref &name) {

	GenericMapType::iterator it = filename_map_.find(name);
	if (it == filename_map_.end()) {
		SharedPointer<StringCache> name_ptr = filename_cache_->acquire();
		if (name_ptr) {
			name_ptr->setName(name.data(), name.length());
			info->filename = name_ptr;
			filename_map_.insert(std::make_pair(name_ptr->getName(), name_ptr));
		}
	} else {
		++ (it->second).hits;
		info->filename = (it->second).sc;
        }
}

void SMBProtocol::create_request_directory_v1(SMBInfo *info, const uint8_t *payload, int length) {

        if (length >= sizeof(smb_v1_create_file_request)) {
                const smb_v1_create_directory_request *hdr = reinterpret_cast<const smb_v1_create_directory_request*>(payload);
                int len = hdr->byte_count - 1;

                if (len <= (length - sizeof(smb_v1_create_directory_request) + 1)) {
                        std::string filename;
                        const uint8_t *filename_payload = &hdr->data[0];

                        for (int i = 0; i < len; ++i) {
                                if (filename_payload[i] != 0x00) {
                                        filename += (char)filename_payload[i];
                                }
                        }
                        if (filename.length() > 0) { // Something to attach
                                boost::string_ref file(filename.c_str(), filename.length());
                                attach_filename(info, file);
                        }
                }
        }
}

void SMBProtocol::create_request_file_v1(SMBInfo *info, const uint8_t *payload, int length) {

	if (length >= sizeof(smb_v1_create_file_request)) {
		const smb_v1_create_file_request *hdr = reinterpret_cast<const smb_v1_create_file_request*>(payload);
		int len = hdr->byte_count - 1;

		if (len <= (length - sizeof(smb_v1_create_file_request) + 1)) {
			std::string filename;
			const uint8_t *filename_payload = &hdr->data[0];

			for (int i = 0; i < len; ++i) {
				if (filename_payload[i] != 0x00) {
					filename += (char)filename_payload[i];
				}	
			}
			if (filename.length() > 0) { // Something to attach
				boost::string_ref file(filename.c_str(), filename.length());
				attach_filename(info, file);
			}
		} 
	}
}

void SMBProtocol::create_request_file_v2(SMBInfo *info, const uint8_t *payload, int length) {

	if (length >= sizeof(smb_v2_create_file_request)) {
		const smb_v2_create_file_request *hdr = reinterpret_cast<const smb_v2_create_file_request*>(payload);
		int offset = hdr->filename_offset - (sizeof(smb_v2_header));
		if (offset < length) { 
			std::string filename;
			const uint8_t *filename_payload = &payload[offset];
			for (int i = 0; i < hdr->filename_length; ++i) {
				if (filename_payload[i] != 0x00) {
					filename += (char)filename_payload[i];
				}	
			}
			if (filename.length() > 0) { // Something to attach
				boost::string_ref file(filename.c_str(), filename.length());
				attach_filename(info, file);
			}
		}
	}
}

void SMBProtocol::open_and_request_v1(SMBInfo *info, const uint8_t *payload, int length) {

        if (length >= sizeof(smb_v1_open_and_request)) {
        	const smb_v1_open_and_request *hdr = reinterpret_cast<const smb_v1_open_and_request*>(payload);
	
		if (hdr->byte_count + sizeof(smb_v1_open_and_request) <= length) {
			if (hdr->byte_count > 0) {
				char *filename_payload = (char*)hdr->data;

				boost::string_ref file(filename_payload, hdr->byte_count);
				attach_filename(info, file);	
			}
                }
        }
}

void SMBProtocol::update_command_type_v1(uint16_t cmd) {

	if ((cmd == SMB_CMD_OPEN_FILE)or(cmd == SMB_CMD_OPEN_ANDX))
		++total_open_files_;
	else if (cmd == SMB_CMD_CREATE_DIR) 
		++total_create_dirs_;
	else if (cmd == SMB_CMD_DELETE_DIR)
		++total_delete_dirs_;
	else if (cmd == SMB_CMD_CREATE_FILE) 
		++total_create_files_;
	else if (cmd == SMB_CMD_CLOSE_FILE)
		++total_close_files_;
	else if (cmd == SMB_CMD_FLUSH_FILES)
		++total_commit_files_;
	else if (cmd == SMB_CMD_DELETE_FILE) 
		++total_delete_files_;
	else if (cmd == SMB_CMD_RENAME_FILE)
		++total_rename_files_;
	else if (cmd == SMB_CMD_GET_FILE_ATTR)
		++total_get_file_attribs_;
	else if (cmd == SMB_CMD_SET_FILE_ATTR)
		++total_set_file_attribs_;
        else if (cmd == SMB_CMD_TREE_DISC) 
                ++total_tree_disconnects_;
        else if (cmd == SMB_CMD_NEGO_PROTO)
                ++total_negotiate_protocol_;
        else if (cmd == SMB_CMD_SESSION_SETUP) 
                ++total_session_setups_;
        else if (cmd == SMB_CMD_LOGOFF) 
                ++total_logoff_and_request_;
        else if (cmd == SMB_CMD_TREE_CONNECT)
                ++total_tree_connects_;
        else if ((cmd == SMB_CMD_TRANS)or(cmd == SMB_CMD_TRANS2))
                ++total_trans_;
        else if (cmd == SMB_CMD_READ)
                ++total_reads_;
        else if (cmd == SMB_CMD_NT_CREATE)
                ++total_nt_creates_;
        else if (cmd == SMB_CMD_WRITE_ANDX)
                ++total_writes_;
        else {
                ++total_others_;
	}
}

void SMBProtocol::update_command_type_v2(uint16_t cmd) {

	if (cmd == SMB2_CMD_CREATE_FILE)
		++total_create_files_;
	else if (cmd == SMB2_CMD_CLOSE_FILE)
		++total_close_files_;
	else if (cmd == SMB2_CMD_GET_INFO)
		++total_get_file_attribs_;
        else if (cmd == SMB2_CMD_TREE_CONNECT)
                ++total_tree_connects_;
        else if (cmd == SMB2_CMD_READ_FILE)
                ++total_reads_;
        else if (cmd == SMB2_CMD_WRITE_FILE)
                ++total_writes_;
        else {
                ++total_others_;
	}
}


void SMBProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;
	++flow->total_packets_l7;

	current_flow_ = flow;

	if (length >= header_size) {
       		SharedPointer<SMBInfo> info = flow->getSMBInfo();
       		if (!info) {
               		info = info_cache_->acquire();
               		if (!info) {
#ifdef HAVE_LIBLOG4CXX
	        		LOG4CXX_WARN (logger, "No memory on '" << info_cache_->getName() << "' for flow:" << *flow);
#endif
				return;
       			}	
               		flow->layer7info = info;
       		}
			
		const uint8_t *payload = flow->packet->getPayload();
	
		if (is_minimal_smb_header(payload)) {	
			uint8_t smb_version = payload[4];
			uint16_t cmd = 0;

			if (smb_version == 0xFF) { // Version 1
				const smb_v1_header *hdr = reinterpret_cast<const smb_v1_header*>(&payload[4]);
				cmd = hdr->cmd;
				int offset = 4 + sizeof(smb_v1_header);
				update_command_type_v1(hdr->cmd);
				if (cmd == SMB_CMD_OPEN_ANDX)
					open_and_request_v1(info.get(), &payload[offset], length - offset);		
				else if (cmd == SMB_CMD_CREATE_FILE)
					create_request_file_v1(info.get(), &payload[offset], length - offset);
				else if (cmd == SMB_CMD_CREATE_DIR)
					create_request_directory_v1(info.get(), &payload[offset], length - offset);
	
			} else if (smb_version == 0xFE) { // Version 2
				const smb_v2_header *hdr = reinterpret_cast<const smb_v2_header*>(&payload[4]);
				cmd = hdr->cmd;
				update_command_type_v2(cmd);
				int offset = 4 + sizeof(smb_v2_header);
				if (cmd == SMB2_CMD_CREATE_FILE)
					create_request_file_v2(info.get(), &payload[offset], length - offset);
					
			} else {
				++total_events_;
                		// Malformed header packet
                		if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        		current_flow_->setPacketAnomaly(PacketAnomalyType::SMB_BOGUS_HEADER);
                		}
                		anomaly_->incAnomaly(PacketAnomalyType::SMB_BOGUS_HEADER);
                		return;
			} 

			info->setCommand(cmd);
		} else {
			// TODO Current transfer of files , may be regex?
		}
	} else {
		++total_events_;
                // Malformed header packet
                if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                	current_flow_->setPacketAnomaly(PacketAnomalyType::SMB_BOGUS_HEADER);
                }
	}
}

int32_t SMBProtocol::getTotalCacheMisses() const {

        int32_t miss = 0;

        miss = info_cache_->getTotalFails();
        miss += filename_cache_->getTotalFails();

        return miss;
}

void SMBProtocol::statistics(std::basic_ostream<char>& out, int level) { 

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
                                out << "\t" << "Total create dirs:      " << std::setw(10) << total_create_dirs_ << "\n";
                                out << "\t" << "Total delete dirs:      " << std::setw(10) << total_delete_dirs_ << "\n";
                                out << "\t" << "Total open files:       " << std::setw(10) << total_open_files_ << "\n";
                                out << "\t" << "Total create files:     " << std::setw(10) << total_create_files_ << "\n";
                                out << "\t" << "Total close files:      " << std::setw(10) << total_close_files_ << "\n";
                                out << "\t" << "Total commit files:     " << std::setw(10) << total_commit_files_ << "\n";
                                out << "\t" << "Total delete files:     " << std::setw(10) << total_delete_files_ << "\n";
                                out << "\t" << "Total rename files:     " << std::setw(10) << total_rename_files_ << "\n";
                                out << "\t" << "Total get attr files:   " << std::setw(10) << total_get_file_attribs_ << "\n";
                                out << "\t" << "Total set attr files:   " << std::setw(10) << total_set_file_attribs_ << "\n";
                                out << "\t" << "Total tree disconnects: " << std::setw(10) << total_tree_disconnects_ << "\n";
                                out << "\t" << "Total negotiate proto:  " << std::setw(10) << total_negotiate_protocol_ << "\n";
                                out << "\t" << "Total session setups:   " << std::setw(10) << total_session_setups_ << "\n";
                                out << "\t" << "Total logoffs:          " << std::setw(10) << total_logoff_and_request_ << "\n";
                                out << "\t" << "Total tree connects:    " << std::setw(10) << total_tree_connects_ << "\n";
                                out << "\t" << "Total trans:            " << std::setw(10) << total_trans_ << "\n";
                                out << "\t" << "Total reads:            " << std::setw(10) << total_reads_ << "\n";
                                out << "\t" << "Total writes:           " << std::setw(10) << total_writes_ << "\n";
                                out << "\t" << "Total nt creates:       " << std::setw(10) << total_nt_creates_ << "\n";
                                out << "\t" << "Total others:           " << std::setw(10) << total_others_ << std::endl;
                        }
			if (level > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
                                if (level > 3) {
                                        info_cache_->statistics(out);
                                        filename_cache_->statistics(out);
                                        if (level > 4) {
                                                showCacheMap(out, "\t", filename_map_, "Filenames", "Name");
                                        }
                                }
                        }
		}
	}
}

CounterMap SMBProtocol::getCounters() const {
       	CounterMap cm;
 
        cm.addKeyValue("packets", total_packets_);
        cm.addKeyValue("bytes", total_bytes_);

	// Specific SMB counters
	cm.addKeyValue("create dirs", total_create_dirs_);
	cm.addKeyValue("delete dirs", total_delete_dirs_);
	cm.addKeyValue("open files", total_open_files_);
	cm.addKeyValue("create files", total_create_files_);
	cm.addKeyValue("close files", total_close_files_);
	cm.addKeyValue("commit files", total_commit_files_);
	cm.addKeyValue("delete files", total_delete_files_);
	cm.addKeyValue("rename files", total_rename_files_);
	cm.addKeyValue("get attr files", total_get_file_attribs_);
	cm.addKeyValue("set attr files", total_set_file_attribs_);
	cm.addKeyValue("tree disconnects", total_tree_disconnects_);
	cm.addKeyValue("negotiate proto", total_negotiate_protocol_);
	cm.addKeyValue("session setups", total_session_setups_);
	cm.addKeyValue("logoffs", total_logoff_and_request_);
	cm.addKeyValue("tree connects", total_tree_connects_);
	cm.addKeyValue("trans", total_trans_);
	cm.addKeyValue("reads", total_reads_);
	cm.addKeyValue("writes", total_writes_);
	cm.addKeyValue("nt creates", total_nt_creates_);
	cm.addKeyValue("others", total_others_);

        return cm;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
#if defined(PYTHON_BINDING)
boost::python::dict SMBProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE SMBProtocol::getCache() const {
#endif
        return addMapToHash(filename_map_);
}

#if defined(PYTHON_BINDING)
void SMBProtocol::showCache(std::basic_ostream<char> &out) const {

	showCacheMap(out, "", filename_map_, "Filenames", "Name");
}
#endif

#endif
} // namespace aiengine
