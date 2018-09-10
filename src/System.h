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
#ifndef SRC_SYSTEM_H_
#define SRC_SYSTEM_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <fstream>
#include <iomanip> // setw
#include <unistd.h> // getpid 
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace aiengine {

class System {
public:

    	explicit System();
    	virtual ~System();

	void statistics(std::basic_ostream<char> &out);
	void statistics() { statistics(std::cout); }

	void lockMemory() { is_memory_lock_ = ( mlockall(MCL_CURRENT) == 0 ? true:false);}

	std::string getOSName() const;
	std::string getNodeName() const;
	std::string getReleaseName() const;
	std::string getVersionName() const;
	std::string getMachineName() const;

private:
	boost::posix_time::ptime start_time_;
	boost::posix_time::ptime end_time_;
	struct rusage usage_;
	struct utsname system_info_;
	bool is_memory_lock_;
};

typedef std::shared_ptr<System> SystemPtr;

} // namespace aiengine

#endif  // SRC_SYSTEM_H_
