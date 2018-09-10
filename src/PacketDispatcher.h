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
#ifndef SRC_PACKETDISPATCHER_H_
#define SRC_PACKETDISPATCHER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif

#include <chrono>
#include <iomanip>
#include <pcap.h>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/bind.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/version.hpp> 
#include <exception>
#include <sys/resource.h>
#include "NetworkStack.h"
#include "Multiplexer.h"
#include "protocols/ethernet/EthernetProtocol.h"
#include "Protocol.h"
#include "StackLan.h"
#include "StackMobile.h"
#include "StackLanIPv6.h"
#include "StackVirtual.h"
#include "StackOpenFlow.h"
#include "StackMobileIPv6.h"
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)
#include "Interpreter.h"
#include "TimerManager.h"
#endif
#include "EvidenceManager.h"
#include "OutputManager.h"
#include "Message.h"

#if !defined(PCAP_NETMASK_UNKNOWN)
/*
 *  This value depending on the pcap library is defined or not 
 * 
 */
#define PCAP_NETMASK_UNKNOWN    0xFFFFFFFF
#endif

namespace aiengine {

#define PACKET_RECVBUFSIZE    4096        // receive_from buffer size for a single datagram

#define BOOST_ASIO_DISABLE_EPOLL

typedef boost::asio::posix::stream_descriptor PcapStream;
typedef std::shared_ptr<PcapStream> PcapStreamPtr;

class PacketDispatcher {
public:

	enum class PacketDispatcherStatus : short {
        	RUNNING = 0,
        	STOP
	};

	class Statistics {
	public:
		explicit Statistics() {
			last_total_packets_sample = 0;
			last_total_bytes_sample = 0;
			std::time(&packet_time); 
			std::time(&last_packet_time);
		}
		virtual ~Statistics() {}

		// The variables are mutable because we change when the user prints the packetdispatcher,
		// just to avoid compute the on the packet processing and better when the user wants the info.
		mutable std::time_t packet_time;
		mutable std::time_t last_packet_time;
		mutable int64_t last_total_packets_sample;	
		mutable int64_t last_total_bytes_sample;
	};

    	explicit PacketDispatcher(const std::string &source);
	explicit PacketDispatcher():PacketDispatcher("") {}

    	virtual ~PacketDispatcher(); 

	void open(const std::string &source);
	void run(void);
	void close(void);
    	void stop(void) { io_service_.stop(); }
	void setPcapFilter(const char *filter);
	const char *getPcapFilter() const { return pcap_filter_.c_str(); }
	void status(void);
	const char *getStackName() const { return stack_name_.c_str(); }

	void setEvidences(bool value);
	bool getEvidences() const { return have_evidences_; }

	void statistics();
	void statistics(std::basic_ostream<char>& out) const;

#if defined(STAND_ALONE_TEST) || defined(TESTING)
	// Use for the tests, limits the number of packets injected
	void setMaxPackets(int packets);
	const char *getEvidencesFilename() const { return em_->getFilename(); }
#endif

#if defined(PYTHON_BINDING)

	// For implement the 'with' statement in python needs the methods __enter__ and __exit__
	PacketDispatcher& __enter__(); 
	bool __exit__(boost::python::object type, boost::python::object val, boost::python::object traceback);

	void forwardPacket(const std::string &packet, int length);
	void addTimer(PyObject *callback, int seconds);

	void setPort(int port);
	int getPort() const;

	void setStack(const boost::python::object &stack);
	boost::python::object getStack() const { return pystack_; }

	const char *getStatus() const;

        // The flow have been marked as accept or drop (for external Firewall integration (Netfilter)) 
        bool isPacketAccepted() const { return current_packet_.isAccept(); }
#else
        void setStack(StackLan &stack);
        void setStack(StackMobile &stack);
        void setStack(StackLanIPv6 &stack);
        void setStack(StackVirtual &stack);
        void setStack(StackOpenFlow &stack);
        void setStack(StackMobileIPv6 &stack);
#endif

	int64_t getTotalBytes(void) const { return total_bytes_; }
	int64_t getTotalPackets(void) const { return total_packets_; }

	void setStack(const SharedPointer<NetworkStack> &stack);  

	void setDefaultMultiplexer(MultiplexerPtr mux); // just use for the unit tests
	void setIdleFunction(std::function <void ()> idle_function) { idle_function_ = idle_function; }
	
	friend std::ostream& operator<< (std::ostream &out, const PacketDispatcher &pd);

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
	void setShell(bool enable);
	bool getShell() const;

	void setLogUserCommands(bool enable);
	bool getLogUserCommands() const;
#endif

#if defined(LUA_BINDING)
	void setShell(lua_State *L, bool enable);
	bool getShell() const;
	void addTimer(lua_State* L, const char *callback, int seconds);
#endif 

#if defined(RUBY_BINDING)
	void addTimer(VALUE callback, int seconds);
#endif
	void showCurrentPayloadPacket(std::basic_ostream<char>& out);
	void showCurrentPayloadPacket();

private:
	void set_stack(NetworkStack *stack);
	void start_read_network(void);
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)
	void start_read_user_input(void);
	void start_read_remote_shell(void);
#endif
	void handle_receive(boost::system::error_code error, std::size_t bytes_transferred);
	void read_network(boost::system::error_code error);
	void forward_raw_packet(const uint8_t *packet, int length, time_t packet_time);
	void restart_timer(int seconds);

        void open_device(const std::string &device);
        void close_device(void);
        void open_pcap_file(const std::string &filename);
        void close_pcap_file(void);
        void run_device(void);
        void run_pcap(void);

	void info_message(const std::string &msg);
	void error_message(const std::string &msg);

	int get_mtu_of_network_device(const std::string &name);

#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
	PacketDispatcherStatus status_;
	PcapStreamPtr stream_;
	bool pcap_file_ready_;
	bool read_in_progress_;
	bool device_is_ready_;
	bool have_evidences_;
#if defined(STAND_ALONE_TEST) || defined(TESTING)
	int32_t max_packets_;
#endif
	int64_t total_packets_;	
	int64_t total_bytes_;	
    	pcap_t* pcap_;
	boost::asio::io_service io_service_;
	boost::asio::signal_set signals_;
	Statistics stats_;
	struct pcap_pkthdr *header_;
	const uint8_t *pkt_data_;
	std::function <void ()> idle_function_;

	EthernetProtocolPtr eth_;	
	Packet current_packet_;
	MultiplexerPtr defMux_;
	std::string stack_name_;
	std::string input_name_;
	std::string pcap_filter_;

	SharedPointer<EvidenceManager> em_;
	NetworkStack *current_network_stack_;
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)
	SharedPointer<TimerManager> tm_;
	SharedPointer<Interpreter> user_shell_;
	SharedPointer<boost::asio::ip::udp::socket> rsock_;
	boost::asio::ip::udp::endpoint remote_endpoint_;
	std::array<char, 20480> recv_buffer_;
#if defined(PYTHON_BINDING)
	boost::python::object pystack_;
#endif
#endif
};

typedef std::shared_ptr<PacketDispatcher> PacketDispatcherPtr;

} // namespace aiengine

#endif  // SRC_PACKETDISPATCHER_H_
