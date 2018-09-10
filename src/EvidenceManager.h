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
#ifndef SRC_EVIDENCEMANAGER_H_
#define SRC_EVIDENCEMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fcntl.h>
#include <unistd.h> // getpid
#include <iostream>
#include <boost/iostreams/device/mapped_file.hpp>
#include <pcap.h>
#include "Packet.h" 
#include "Protocol.h" // for unit converter

namespace aiengine {

typedef struct {
	int32_t t0;
	int32_t t1;
	int32_t len;
	int32_t caplen;
} pcap_header_writeable;

/* LCOV_EXCL_START */

class EvidenceManager {
public:

	explicit EvidenceManager(int32_t size);
	explicit EvidenceManager():EvidenceManager(default_size) {}
    	virtual ~EvidenceManager() { disable(); }

	// By default the system creates a mmap of 128 MBs
	// Depending on the use of this functionality may be a small
	// size of a bigger size is required.
	static constexpr int32_t default_size = 1024 * 1024 * 128;

	void statistics(std::basic_ostream<char> &out) const;

	void enable();
	void disable();
	void write(const Packet& pkt);

	friend std::ostream& operator<< (std::ostream &out, const EvidenceManager &em);

#if defined(STAND_ALONE_TEST) || defined(TESTING)
        const char* getFilename() const { return filename_.c_str(); }
#endif

private:
	boost::iostreams::mapped_file_sink evidence_file_;
	std::string filename_;
	int32_t total_size_;
	int32_t total_files_;
	int32_t total_write_packets_;
	int32_t evidence_offset_;
	int64_t total_bytes_on_disk_;
	char *evidence_data_;
};

/* LCOV_EXCL_STOP */

} // namespace aiengine

#endif  // SRC_EVIDENCEMANAGER_H_
