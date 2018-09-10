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
#include "PacketDispatcher.h"
#include <boost/exception/diagnostic_information.hpp> 
#include <boost/exception_ptr.hpp> 

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr PacketDispatcher::logger(log4cxx::Logger::getLogger("aiengine.packetdispatcher"));
#endif

PacketDispatcher::PacketDispatcher(const std::string &source):
	status_(PacketDispatcherStatus::STOP), // Status of the PacketDispatcher
        stream_(),
	pcap_file_ready_(false),
	read_in_progress_(false),
        device_is_ready_(false),
	have_evidences_(false),
#if defined(STAND_ALONE_TEST) || defined(TESTING)
        max_packets_(std::numeric_limits<int32_t>::max()),
#endif
        total_packets_(0),total_bytes_(0),
	pcap_(nullptr),
        io_service_(),
        signals_(io_service_, SIGINT, SIGTERM),
        stats_(),
	header_(nullptr),
	pkt_data_(nullptr),
	idle_function_([&] (void) {}),
        eth_(nullptr),
	current_packet_(),
	defMux_(nullptr),
	stack_name_(),
	input_name_(source),
        pcap_filter_(),
        em_(SharedPointer<EvidenceManager>(new EvidenceManager())),
        current_network_stack_()
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)
	,tm_(SharedPointer<TimerManager>(new TimerManager(io_service_))),
        user_shell_(SharedPointer<Interpreter>(new Interpreter(io_service_))),
	rsock_()
#if defined(PYTHON_BINDING)
        ,pystack_()
#endif
#endif
	{
        signals_.async_wait(
        	boost::bind(&boost::asio::io_service::stop, &io_service_));
}


PacketDispatcher::~PacketDispatcher() { 

	io_service_.stop(); 
}

void PacketDispatcher::info_message(const std::string &msg) {
#ifdef HAVE_LIBLOG4CXX
        LOG4CXX_INFO(logger, msg);
#else
	aiengine::information_message(msg);
#endif
}

void PacketDispatcher::error_message(const std::string &msg) {
#ifdef HAVE_LIBLOG4CXX
        LOG4CXX_ERROR(logger, msg);
#else
	aiengine::error_message(msg);
#endif
}

void PacketDispatcher::statistics() {

        statistics(OutputManager::getInstance()->out());
}

void PacketDispatcher::set_stack(NetworkStack *stack) {

        current_network_stack_ = stack;
	stack_name_ = stack->getName();
        setDefaultMultiplexer(stack->getLinkLayerMultiplexer().lock());
        stack->setAsioService(io_service_);
}

void PacketDispatcher::setStack(const SharedPointer<NetworkStack> &stack) {

	set_stack(stack.get());
}

void PacketDispatcher::setDefaultMultiplexer(MultiplexerPtr mux) {

	defMux_ = mux;
	auto proto = mux->getProtocol();
	eth_ = std::dynamic_pointer_cast<EthernetProtocol>(proto);
}

int PacketDispatcher::get_mtu_of_network_device(const std::string &name) {

	struct ifreq ifr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd != -1) {
        	ifr.ifr_addr.sa_family = AF_INET;
        	strncpy(ifr.ifr_name , name.c_str() , IFNAMSIZ - 1);

		if (ioctl(fd, SIOCGIFMTU, &ifr) == 0) {
			// Use the global namespace for link with the system call close
			::close(fd);
			return ifr.ifr_mtu;
		}
		::close(fd);
	}

        std::ostringstream msg;
        msg << "Can not get MTU of device:" << input_name_.c_str();
#ifdef HAVE_LIBLOG4CXX
	LOG4CXX_ERROR(logger, msg.str());
#else
        error_message(msg.str());
#endif
	return 0;
}

void PacketDispatcher::open_device(const std::string &device) {

	char errorbuf[PCAP_ERRBUF_SIZE];
#ifdef __FREEBSD__
	int timeout = 1000; // miliseconds
#else
	int timeout = -1;
#endif

	pcap_ = pcap_open_live(device.c_str(), PACKET_RECVBUFSIZE, 0, timeout, errorbuf);
	if (pcap_ == nullptr) {
        	std::ostringstream msg;
		msg << "Device:" << device.c_str() << " error:" << errorbuf; 
#ifdef HAVE_LIBLOG4CXX
		LOG4CXX_ERROR(logger, msg.str());
#else
		error_message(msg.str());
#endif
		device_is_ready_ = false;
		return;
	}
	int ifd = pcap_get_selectable_fd(pcap_);
	if (pcap_setnonblock(pcap_, 1, errorbuf) == 1) {
		device_is_ready_ = false;
		return;
	}
	stream_ = PcapStreamPtr(new PcapStream(io_service_));
			
	stream_->assign(::dup(ifd));
	device_is_ready_ = true;
	input_name_ = device;
}

void PacketDispatcher::close_device(void) {

	if (device_is_ready_) {
		stream_->close();
		pcap_close(pcap_);
		device_is_ready_ = false;
	}
}

void PacketDispatcher::open_pcap_file(const std::string &filename) {

	char errorbuf[PCAP_ERRBUF_SIZE];

        pcap_ = pcap_open_offline(filename.c_str(), errorbuf);
        if (pcap_ == nullptr) {
		pcap_file_ready_ = false;
        	std::ostringstream msg;
		msg << "Unkown pcapfile:" << filename.c_str(); 
#ifdef HAVE_LIBLOG4CXX
		LOG4CXX_ERROR(logger, msg.str());
#else
		error_message(msg.str());
#endif
	} else {
		pcap_file_ready_ = true;
		input_name_ = filename;
	}
}

void PacketDispatcher::close_pcap_file(void) {

	if (pcap_file_ready_) {
		pcap_close(pcap_);
		pcap_file_ready_ = false;
	}
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)
void PacketDispatcher::handle_receive(boost::system::error_code error, std::size_t bytes_transferred) {

	if (!error)
    	{
        	std::string message(recv_buffer_.data(), recv_buffer_.data() + bytes_transferred);
		boost::system::error_code err;

		std::ostringstream buffer;
	
		// All the output will go to the buffer	
		OutputManager::getInstance()->setOutput(buffer);
	
		user_shell_->executeRemoteCommand(message); 

		// restore to std::cout	
		OutputManager::getInstance()->setOutput(std::cout);
			
		size_t bytes_sent = rsock_->send_to(boost::asio::buffer(buffer.str()), remote_endpoint_, 0, err);
    	}

	start_read_remote_shell();
}
#endif

void PacketDispatcher::read_network(boost::system::error_code ec) {

	int len = pcap_next_ex(pcap_, &header_, &pkt_data_);
	if (len >= 0) {
		forward_raw_packet(pkt_data_, header_->len, header_->ts.tv_sec);
	}

// This prevents a problem on the boost asio signal
// remove this if when boost will be bigger than 1.50
#ifdef PYTHON_BINDING
#if BOOST_VERSION >= 104800 && BOOST_VERSION < 105000
	if (PyErr_CheckSignals() == -1) {
        	std::ostringstream msg;
		msg << "Throwing exception from python";

		error_message(msg.str()); 
		throw std::runtime_error("Python exception\n");
       	}
#endif
#endif

	if (!ec || ec == boost::asio::error::would_block)
      		start_read_network();
	// else error but not handler
}

void PacketDispatcher::forward_raw_packet(const uint8_t *packet, int length, time_t packet_time) {

	++total_packets_;
	total_bytes_ += length;

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)
	stats_.packet_time = packet_time;
#endif
	if (defMux_) {
		current_packet_.setPayload(packet);
		current_packet_.setPayloadLength(length);
		current_packet_.setPrevHeaderSize(0);
		current_packet_.setPacketTime(packet_time);
		current_packet_.setEvidence(false);

		if (defMux_->acceptPacket(current_packet_)) {
			defMux_->setPacket(&current_packet_);
			defMux_->setNextProtocolIdentifier(eth_->getEthernetType());
			defMux_->forwardPacket(current_packet_);
			if ((have_evidences_)and(current_packet_.haveEvidence())) {
				em_->write(current_packet_);
			}
                }
	}
}

void PacketDispatcher::start_read_network(void) {

	read_in_progress_ = false;
	if (!read_in_progress_) {
		read_in_progress_ = true;

		stream_->async_read_some(boost::asio::null_buffers(),
                	boost::bind(&PacketDispatcher::read_network, this,
                                boost::asio::placeholders::error));
	}
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)
void PacketDispatcher::start_read_user_input(void) {

	user_shell_->readUserInput();
}

void PacketDispatcher::start_read_remote_shell(void) {

	if (rsock_) {
		rsock_->async_receive_from(boost::asio::buffer(recv_buffer_), remote_endpoint_,
        		boost::bind(&PacketDispatcher::handle_receive, this, 
				boost::asio::placeholders::error, 
				boost::asio::placeholders::bytes_transferred)
    		);	
	}
}

#endif

#if defined(STAND_ALONE_TEST) || defined(TESTING)
void PacketDispatcher::setMaxPackets(int packets) {

	max_packets_ = packets;
}
#endif


void PacketDispatcher::run_pcap(void) {

        std::ostringstream msg;
        msg << "Processing packets from file " << input_name_.c_str();
       	info_message(msg.str());

	if (eth_) eth_->setMaxEthernetLength(ETHER_MAX_LEN * 4); // Increase the size to a big value probably 65243 is the best

	if (current_network_stack_) {
		int64_t memory = current_network_stack_->getAllocatedMemory();
		std::string unit = "Bytes";

		unitConverter(memory,unit);
	
		msg.clear();
		msg.str("");
        	msg << "Stack '" << stack_name_ << "' using " << memory << " " << unit << " of memory";
       		info_message(msg.str());
        } else {
                msg.clear();
                msg.str("");
                msg << "No stack configured";
                warning_message(msg.str());
        }

	status_ = PacketDispatcherStatus::RUNNING;
	while (pcap_next_ex(pcap_, &header_, &pkt_data_) >= 0) {
		// Friendly remminder:
		//     header_->len contains length this packet (off wire)
		//     header_->caplen length of portion present	
		forward_raw_packet((uint8_t*)pkt_data_, header_->caplen, header_->ts.tv_sec);
#if defined(STAND_ALONE_TEST) || defined(TESTING)
     		if (total_packets_ >= max_packets_) {
			break;
		} 
#endif
	}
	status_ = PacketDispatcherStatus::STOP;
}


void PacketDispatcher::run_device(void) {

	if (device_is_ready_) {

        	std::ostringstream msg;
        	msg << "Processing packets from device " << input_name_.c_str();

        	info_message(msg.str());

        	if ((current_network_stack_)&&(eth_)) {
                	int64_t memory = current_network_stack_->getAllocatedMemory();
			eth_->setMaxEthernetLength(get_mtu_of_network_device(input_name_));
                	std::string unit = "Bytes";

                	unitConverter(memory,unit);

                	msg.clear();
                	msg.str("");
                	msg << "Stack '" << stack_name_ << "' using " << memory << " " << unit << " of memory";
                	info_message(msg.str());
        	} else {
                	msg.clear();
                	msg.str("");
                	msg << "No stack configured";
                	warning_message(msg.str());
		}

		try {
			status_ = PacketDispatcherStatus::RUNNING;
			start_read_network();
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)
			start_read_user_input();
			start_read_remote_shell();
#endif
			io_service_.run();
		} catch (const std::exception& e) {
        		std::ostringstream msg;
        		msg << ":ERROR:" << e.what() << std::endl;
			msg << boost::diagnostic_information(e);

			error_message(msg.str()); 
        	}
		status_ = PacketDispatcherStatus::STOP;
	} else {

                std::ostringstream msg;
                msg << "The device is not ready to run";

                info_message(msg.str());
	}
}

void PacketDispatcher::open(const std::string &source) {

	std::ifstream infile(source);

	device_is_ready_ = false;
	pcap_file_ready_ = false;

	if (infile.good()) { // The source is a file
		open_pcap_file(source);
	} else {
		pcap_if_t *alldevs = nullptr;
		pcap_if_t *d = nullptr;
		char errbuf[PCAP_ERRBUF_SIZE];

		/* Retrieve the device list from the local machine */
    		if (pcap_findalldevs(&alldevs, errbuf) == -1) {
                        std::ostringstream msg;
                        msg << "Can not get list of network devices";
#ifdef HAVE_LIBLOG4CXX  
                        LOG4CXX_ERROR(logger, msg.str());
#else                   
                        error_message(msg.str());
#endif
        		exit(1);
    		}
   
		bool valid = false; 
    		for(d = alldevs; d != nullptr; d = d->next) {
    	
			if (source.compare(d->name) == 0) {
				valid = true;
				break;
			}	
		}

		if (valid) {
			open_device(source);
		} else {
                	std::ostringstream msg;
                	msg << "Unknown device or file input:" << source.c_str();
#ifdef HAVE_LIBLOG4CXX
                	LOG4CXX_WARN(logger, msg.str());
#else
                	warning_message(msg.str());
#endif
		}
		pcap_freealldevs(alldevs);
	}
}

void PacketDispatcher::run(void) {

	if (device_is_ready_) {
		run_device();
	} else {
		if (pcap_file_ready_) {
			run_pcap();
		}
	}
}

void PacketDispatcher::close(void) {

        if (device_is_ready_) {
                close_device();
        } else {
                if (pcap_file_ready_) {
                        close_pcap_file();
                }
        }
}

void PacketDispatcher::setPcapFilter(const char *filter) {

	if ((device_is_ready_)or(pcap_file_ready_)) {
		struct bpf_program fp;
		char *c_filter = const_cast<char*>(filter);

		if (pcap_compile(pcap_, &fp, c_filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {

			pcap_filter_ = filter;			
			if (pcap_setfilter(pcap_,&fp) == 0) {
				std::ostringstream msg;
                		msg << "Pcap filter set:" << filter;

                		info_message(msg.str());
			}
		} else {
			std::ostringstream msg;
			msg << "Wrong pcap filter";

			error_message(msg.str()); 
		}
		pcap_freecode (&fp);
	}
}


void PacketDispatcher::setEvidences(bool value) {

        if ((!have_evidences_)and(value)) {
                have_evidences_ = true;
                em_->enable();
        } else if ((have_evidences_)and(!value)) {
                have_evidences_ = false;
                em_->disable();
        }
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 

void PacketDispatcher::setShell(bool enable) {

        user_shell_->setShell(enable);
}

bool PacketDispatcher::getShell() const {

        return user_shell_->getShell();
}

void PacketDispatcher::setLogUserCommands(bool enable) {

	user_shell_->setLogUserCommands(enable);
}

bool PacketDispatcher::getLogUserCommands() const {

	return user_shell_->getLogUserCommands();
}

#endif

#if defined(LUA_BINDING)

void PacketDispatcher::setShell(lua_State *L, bool enable) {

        user_shell_->setShell(enable);
	user_shell_->setLuaInterpreter(L);
}

bool PacketDispatcher::getShell() const {

        return user_shell_->getShell();
}

#endif

#if defined(PYTHON_BINDING)

void PacketDispatcher::setPort(int port) {

	if (port > 0) {
		rsock_.reset();
		rsock_ = SharedPointer<boost::asio::ip::udp::socket>(new boost::asio::ip::udp::socket(
			io_service_, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port)));
	} else {
		rsock_.reset();
	} 
}

int PacketDispatcher::getPort() const {

	int port = 0;

	if (rsock_) {
		port = rsock_->local_endpoint().port();
	}

	return port;
}

void PacketDispatcher::addTimer(PyObject *callback, int seconds) {

	tm_->addTimer(callback, seconds);
}
#elif defined(RUBY_BINDING)
void PacketDispatcher::addTimer(VALUE callback, int seconds) {

	tm_->addTimer(callback, seconds);
}
#elif defined(LUA_BINDING)
void PacketDispatcher::addTimer(lua_State* L, const char *callback, int seconds) {

	tm_->addTimer(L, callback, seconds);
}
#endif

#if defined(PYTHON_BINDING)

void PacketDispatcher::setStack(const boost::python::object &stack) {

	if (stack.is_none()) {
		// The user sends a Py_None 
		pystack_ = boost::python::object();
		stack_name_ = "None";
        	defMux_.reset();
		eth_ = nullptr;
		current_network_stack_ = nullptr;
	} else {
		boost::python::extract<SharedPointer<NetworkStack>> extractor(stack);

        	if (extractor.check()) {
        		SharedPointer<NetworkStack> pstack = extractor();
                	pystack_ = stack;
                
			// The NetworkStack have been extracted and now call the setStack method
                	set_stack(pstack.get());
        	} else {
			std::ostringstream msg;

			msg << "Can not extract NetworkStack from python object"; 
			error_message(msg.str()); 
		}
	}
}

PacketDispatcher& PacketDispatcher::__enter__() {

	open(input_name_);
        return *this;
}

bool PacketDispatcher::__exit__(boost::python::object type, boost::python::object val, boost::python::object traceback) {

	close();
        return type.ptr() == Py_None;
}

void PacketDispatcher::forwardPacket(const std::string &packet, int length) {

	const uint8_t *pkt = reinterpret_cast<const uint8_t *>(packet.c_str());

	// TODO: pass the time to the method forward_raw_packet from the
	// python binding
	forward_raw_packet(pkt, length, 0);
	return;
}

const char *PacketDispatcher::getStatus() const {

        if (status_ == PacketDispatcherStatus::RUNNING)
                return "running";
        else
                return "stoped";
}

#endif

std::ostream& operator<< (std::ostream &out, const PacketDispatcher &pd) {

	pd.statistics(out);
        return out;
}

void PacketDispatcher::statistics(std::basic_ostream<char> &out) const {

	out << std::setfill(' ');
	out << "PacketDispatcher(" << this <<") statistics" << "\n";
	out << "\t" << "Connected to " << stack_name_ << "\n";
	if (device_is_ready_) {
		out << "\tCapturing from:         " << std::setw(10) << input_name_.c_str() << "\n"; 
	}
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)

	out << "\tShell:                  " << std::setw(10) << (user_shell_->getShell() ? "enabled" : "disabled" ) << "\n";
 
        tm_->statistics(out);

#if defined(PYTHON_BINDING)
	if (getPort() > 0) {
                boost::asio::ip::address addr = rsock_->local_endpoint().address();
		std::stringstream addr_str;

		addr_str << addr.to_string() << ":" << getPort();
		out << "\t" << "Listening on:" << std::setw(21) << addr_str.str() << "\n";
	}
#endif
	if (device_is_ready_) {
		// Compute the number of packets per second and bytes.
		int seconds = difftime(stats_.packet_time, stats_.last_packet_time);
		int64_t packets_per_second = total_packets_ - stats_.last_total_packets_sample;
		int64_t bytes_per_second = total_bytes_ - stats_.last_total_bytes_sample;

		if (seconds > 0 ) {
			packets_per_second = packets_per_second / seconds;
			bytes_per_second = bytes_per_second / seconds;
		}

		stats_.last_packet_time = stats_.packet_time; // update the last time we make the compute
		stats_.last_total_packets_sample = total_packets_;
		stats_.last_total_bytes_sample = total_bytes_;

		out << "\t" << "Total packets/sec:      " << std::dec << std::setw(10) << packets_per_second << "\n";
		out << "\t" << "Total bytes/sec:    " << std::dec << std::setw(14) << bytes_per_second << "\n";
	}
#endif
	if (pcap_filter_.length() > 0) {
		out << "\t" << "Pcap filter:" << pcap_filter_ <<std::endl;
	}
	out << "\t" << "Total packets:          " << std::dec << std::setw(10) << total_packets_ << "\n";
	out << "\t" << "Total bytes:        " << std::dec << std::setw(14) << total_bytes_ << std::endl;

        if (have_evidences_) {
		out << std::endl;
                em_->statistics(out);
        }
}

void PacketDispatcher::status(void) {

	std::ostringstream msg;
        msg << "PacketDispatcher ";
	if (status_ == PacketDispatcherStatus::RUNNING)
		msg << "running";
	else
		msg << "stoped";
	msg << ", plug to " << stack_name_;
	msg << ", packets " << total_packets_ << ", bytes " << total_bytes_;

        info_message(msg.str());
}

void PacketDispatcher::showCurrentPayloadPacket(std::basic_ostream<char> &out) {

	if ((device_is_ready_)or(pcap_file_ready_)) {
		if (current_network_stack_) {	
			std::tuple<Flow*,Flow*> flows = current_network_stack_->getCurrentFlows();
			Flow *low_flow = std::get<0>(flows);
			Flow *high_flow = std::get<1>(flows);

			if (low_flow) out << "\tFlow:" << *low_flow << std::endl;
			if (high_flow) out << "\tFlow:" << *high_flow << std::endl;
		}
		if ((pkt_data_) and (header_))
			showPayload(out,pkt_data_,header_->caplen);
		out << std::dec;
	}
}

void PacketDispatcher::showCurrentPayloadPacket() { showCurrentPayloadPacket(OutputManager::getInstance()->out()); }


#if !defined(PYTHON_BINDING) 

void PacketDispatcher::setStack(StackLan &stack) { 

	set_stack(&stack);
}

void PacketDispatcher::setStack(StackMobile &stack) { 

	set_stack(&stack);
}

void PacketDispatcher::setStack(StackLanIPv6 &stack) { 

	set_stack(&stack);
}

void PacketDispatcher::setStack(StackVirtual &stack) { 

	set_stack(&stack);
}

void PacketDispatcher::setStack(StackOpenFlow &stack) { 

	set_stack(&stack);
}

void PacketDispatcher::setStack(StackMobileIPv6 &stack) { 

	set_stack(&stack);
}

#endif

} // namespace aiengine
