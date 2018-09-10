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
#ifndef SRC_INTERPRETER_H_
#define SRC_INTERPRETER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <chrono>
#include <fstream>

#if defined(PYTHON_BINDING)
#include <boost/python.hpp>
#include "PyGilContext.h"
#elif defined(RUBY_BINDING)
#include <ruby.h>
#elif defined(LUA_BINDING)
#include <lua.hpp>
#endif
#include "OutputManager.h"
#include "Message.h"

namespace aiengine {

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)

class Interpreter {
public:
	explicit Interpreter(boost::asio::io_service &io_service):Interpreter(io_service, STDIN_FILENO) {}
	explicit Interpreter(boost::asio::io_service &io_service, int fd);
    	virtual ~Interpreter() { user_input_.close(); }

	static const int MaxInputBuffer = 128;
#if defined(PYTHON_BINDING)
	static constexpr const char* Prompt = ">>> ";
	static constexpr const char* CodePrompt = "... ";
#elif defined(LUA_BINDING)
	static constexpr const char* Prompt = "> ";
#elif defined(RUBY_BINDING)
	static constexpr const char* Prompt = "irb(main):0> ";
#endif
	void start(); 
	void stop();
	void readUserInput();

	void setLogUserCommands(bool enable);
	bool getLogUserCommands() const { return log_file_.is_open(); }

	void setShell(bool enable);  
	bool getShell() const { return shell_enable_; }  

	void executeRemoteCommand(const std::string &cmd) { execute_command(cmd); }

#if defined(LUA_BINDING)
	void setLuaInterpreter(lua_State *L) { L_ = L; }
#endif	
private:
	void execute_user_command(const std::string& cmd);
	void execute_command(const std::string& cmd);
	void handle_read_user_input(boost::system::error_code error);

	int fd_;
	boost::asio::posix::stream_descriptor user_input_;
	boost::asio::streambuf user_input_buffer_;
	bool shell_enable_;
	bool want_exit_;
	bool in_code_block_;
	char *current_prompt_;
	std::string cmd_;
	std::ofstream log_file_;
#if defined(LUA_BINDING)
	lua_State *L_;
#endif
};

#endif // PYTHON_BINDING || RUBY_BINDING

} // namespace aiengine

#endif  // SRC_INTERPRETER_H_
