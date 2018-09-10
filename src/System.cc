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
#include "System.h"

namespace aiengine {

std::function <void(int64_t&, std::string&)> unitConverter = [](int64_t &bytes, std::string &unit) noexcept { 
	if (bytes >1024) { bytes = bytes / 1024; unit = "KBytes"; } 
	if (bytes >1024) { bytes = bytes / 1024; unit = "MBytes"; } 
	if (bytes >1024) { bytes = bytes / 1024; unit = "GBytes"; } 
	if (bytes >1024) { bytes = bytes / 1024; unit = "TBytes"; } 
};

System::System(): 
	start_time_(boost::posix_time::microsec_clock::local_time()),
	end_time_(boost::posix_time::microsec_clock::local_time()),
	is_memory_lock_(false)
	{

	uname(&system_info_),
	getrusage(RUSAGE_SELF,&usage_);
}

System::~System() { 

	munlockall();
}

void System::statistics(std::basic_ostream<char> &out) {

	struct rusage usage;
	std::ostringstream proc_file;
	int64_t virtual_memory = 0;
	std::string unit("Bytes");

	proc_file << "/proc/" << getpid() << "/stat";

	std::vector<std::string> items;
	try {
		std::string item;
		std::ifstream fd (proc_file.str());
		while(std::getline(fd, item, ' ')) {
			items.push_back(item);	
    		}
		// The virtual memory is on the 22 index value
		virtual_memory = std::stoi(items.at(22));
	} catch ( ... ) { /* LCOV_EXCL_LINE */

	}	
	unitConverter(virtual_memory, unit);

	getrusage(RUSAGE_SELF,&usage);

	end_time_ = boost::posix_time::microsec_clock::local_time();
	boost::posix_time::time_duration duration(end_time_ - start_time_);

        out << "System process statistics" << std::dec <<  "\n";
        out << "\t" << "Elapsed time:      " << duration << "\n";
        out << "\t" << "Virtual memory size:    " << std::setw(9 - unit.length()) << virtual_memory << " " << unit << "\n"; 
        out << "\t" << "Lock memory:                 " << std::setw(5) << (is_memory_lock_ ? "yes":"no") << "\n";
        out << "\t" << "Resident memory size:      " << std::setw(7) << usage.ru_maxrss << "\n";
        out << "\t" << "Shared memory size:          " << std::setw(5) << usage.ru_ixrss << "\n";
        out << "\t" << "Unshared data size:          " << std::setw(5) << usage.ru_idrss << "\n";
        out << "\t" << "Unshared stack size:         " << std::setw(5) << usage.ru_isrss << "\n";
        out << "\t" << "Page reclaims:             " << std::setw(7) << usage.ru_minflt << "\n";
        out << "\t" << "Page faults:                 " << std::setw(5) << usage.ru_majflt << "\n";
        out << "\t" << "Swaps:                       " << std::setw(5) << usage.ru_nswap << "\n";
        out << "\t" << "Block input operations: " << std::setw(10) << usage.ru_inblock << "\n";
        out << "\t" << "Block output operations:     " << std::setw(5) << usage.ru_oublock << "\n";
        out << "\t" << "IPC messages sent:           " << std::setw(5) << usage.ru_msgsnd << "\n";
        out << "\t" << "IPC messages received:       " << std::setw(5) << usage.ru_msgrcv << "\n";
        out << "\t" << "Signal received:             " << std::setw(5) << usage.ru_nsignals << "\n";
        out << "\t" << "Voluntary context switches:" << std::setw(7) << usage.ru_nvcsw << "\n";
        out << "\t" << "Involuntary context switches:" << std::setw(5) << usage.ru_nivcsw << std::endl;
}

std::string System::getOSName() const {
	std::ostringstream os;

        os << system_info_.sysname;
	return os.str();
}

std::string System::getNodeName() const {
	std::ostringstream os;

        os << system_info_.nodename;
	return os.str();
}

std::string System::getReleaseName() const {
	std::ostringstream os;

        os << system_info_.release;
	return os.str();
}

std::string System::getVersionName() const {
	std::ostringstream os;

        os << system_info_.version;
	return os.str();
}

std::string System::getMachineName() const {
	std::ostringstream os;

        os << system_info_.machine;
	return os.str();
}

} // namespace aiengine
