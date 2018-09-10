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
#ifndef SRC_PROTOCOLS_SSH_SSHINFO_H_
#define SRC_PROTOCOLS_SSH_SSHINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <algorithm>
#include "Pointer.h"
#include "FlowInfo.h"

namespace aiengine {

class SSHInfo : public FlowInfo {
public:
    	explicit SSHInfo() { reset(); }
    	virtual ~SSHInfo() {}

	void reset(); 
	void serialize(JsonFlow &j); 

	void setClientHandshake(bool value) { is_client_handshake_ = value; }
	void setServerHandshake(bool value) { is_server_handshake_ = value; }
	bool isHandshake() const { return is_client_handshake_ || is_server_handshake_; }

	void addEncryptedBytes(int32_t value) { total_encrypted_bytes_ += value; }
	int32_t getTotalEncryptedBytes() const { return total_encrypted_bytes_; }

	friend std::ostream& operator<< (std::ostream &out, const SSHInfo &info);

#if defined(STAND_ALONE_TEST) || defined(TESTING)
	bool isClientHandshake() const { return is_client_handshake_; }
	bool isServerHandshake() const { return is_server_handshake_; }
#endif

private:
	int32_t total_encrypted_bytes_;
	bool is_client_handshake_:1;	
	bool is_server_handshake_:1;	
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SSH_SSHINFO_H_
