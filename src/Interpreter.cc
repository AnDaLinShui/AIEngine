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
#include "Interpreter.h"
#include "System.h"
#include <termios.h> // tcflush()

namespace aiengine {

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)

Interpreter::Interpreter(boost::asio::io_service &io_service, int fd):
	fd_(fd),
	user_input_(io_service, ::dup(fd)),
	user_input_buffer_(MaxInputBuffer),
	shell_enable_(false),
	want_exit_(false),
	in_code_block_(false),
	current_prompt_(const_cast<char*>(Prompt)),
	cmd_(""),
	log_file_() {
#if defined(LUA_BINDING)
	L_ = nullptr;
#endif
}

void Interpreter::setShell(bool enable) {

	if (shell_enable_) {
		if (!enable) {
			stop();
		}
	} else {
		if (enable) {
			start();
		}
	}
}

void Interpreter::start() {

	shell_enable_ = true;
#if defined(PYTHON_BINDING) 
	const char *interpreter_banner = "Python " PY_VERSION;
#elif defined(RUBY_BINDING)
	const char *interpreter_banner = "Ruby";
#elif  defined(LUA_BINDING)
	const char *interpreter_banner = LUA_VERSION;
#endif
	std::ostringstream msg;
       	msg << interpreter_banner << " AIEngine " << VERSION << " shell enable on ";
       	System ss; 

       	msg << ss.getOSName() << " kernel " << ss.getReleaseName() << " " << ss.getMachineName(); 

	aiengine::information_message(msg.str());

	/* Flush the stdin descriptor, we dont want read nothing if is not enable */
	tcflush(fd_, TCIFLUSH);

	readUserInput();
}

void Interpreter::stop() {
       
	shell_enable_ = false;
        user_input_buffer_.consume(MaxInputBuffer);

	std::ostringstream msg;
	msg << "exiting AIEngine " << VERSION << " shell disable";

	aiengine::information_message(msg.str()); 

	// Cancel the asynchronoss operations
	user_input_.cancel();
}

void Interpreter::readUserInput() {

	if (shell_enable_) {
        	boost::asio::async_read_until(user_input_, user_input_buffer_, '\n',
                	boost::bind(&Interpreter::handle_read_user_input, this,
                        boost::asio::placeholders::error));
	}
}


bool has_suffix(const std::string &str, const std::string &suffix)
{
	return str.size() >= suffix.size() &&
        	str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

void Interpreter::execute_user_command(const std::string& cmd) {

#if defined(PYTHON_BINDING)

        // Verify if there is : at the end
        if (has_suffix(cmd, ":")) {
                in_code_block_ = true;
                current_prompt_ = const_cast<char*>(CodePrompt);
                cmd_ += "\n" + cmd;
                return;
        } else {
                if (in_code_block_) {
                        if (cmd.length() == 0) {
                                current_prompt_ = const_cast<char*>(Prompt);
                                in_code_block_ = false;
                        } else {
                                cmd_ += "\n" + cmd;
                                return;
                        }
                } else {
                        cmd_ = cmd;
                }
        }

	execute_command(cmd_);
	cmd_.clear();
#else
	execute_command(cmd);
#endif

}

void Interpreter::execute_command(const std::string& cmd) {

	if (cmd.empty())
		return;

#if defined(PYTHON_BINDING)

	try {
		PyGilContext gil_lock;

		// Retrieve the main module.
		boost::python::object main = boost::python::import("__main__");
  		// Retrieve the main module's namespace
  		boost::python::object global(main.attr("__dict__"));

		boost::python::exec(cmd.c_str(), global);
	} catch (boost::python::error_already_set const &) {
        	if (isatty(fileno(stdout))) {
                	Color::Modifier red(Color::FG_RED);
                	Color::Modifier def(Color::FG_DEFAULT);
                	std::cout << red;
			PyErr_Print();
                	std::cout << def;
		} else {
			PyErr_Print();
		}
	}

#elif defined(RUBY_BINDING)
	
	int state = 0;
	rb_eval_string_protect(cmd.c_str(), &state);
	if (state) {
		rb_raise(rb_eRuntimeError, "Error");
	}
#elif defined(LUA_BINDING)

	int ret = luaL_dostring(L_, cmd.c_str());
	if (ret != 0) {
		std::cout << "ERROR:" << lua_tostring(L_, -1) << std::endl; 
	}
#endif

}

void Interpreter::handle_read_user_input(boost::system::error_code error) {

	if ((!error)and(shell_enable_)) {
		std::istream user_stream(&user_input_buffer_);
                std::string cmd;

		std::getline(user_stream, cmd);

		if (want_exit_) {
			// The users type yes
			if (cmd.compare("yes") == 0) {
				stop();
				return;
			}	
			want_exit_ = false;
		} else {
			// The user wants to exist from the shell	
			if (cmd.compare("quit()") == 0) {
				std::cout << "Are you sure? (yes/no)" << std::flush;
               			user_input_buffer_.consume(MaxInputBuffer);
				want_exit_ = true;
				readUserInput();
				return;
			} else {
				std::ofstream term("/dev/tty", std::ios_base::out);				

				OutputManager::getInstance()->setOutput(term);

               			execute_user_command(cmd);

				if (log_file_.is_open()and(cmd.length() > 0)) {
        				char mbstr[100];

        				std::chrono::system_clock::time_point time_point = std::chrono::system_clock::now();
        				std::time_t now = std::chrono::system_clock::to_time_t(time_point);

        				std::strftime(mbstr, 100, "%D %X", std::localtime(&now));
        				log_file_ << "[" << mbstr << "] >>> " << cmd << std::endl;
				}
			}
		}
		user_input_buffer_.consume(MaxInputBuffer);

        	if (isatty(fileno(stdout))) {
                	Color::Modifier blue(Color::FG_BLUE);
                	Color::Modifier def(Color::FG_DEFAULT);

			std::cout << blue << current_prompt_ << def;
        	} else {
			std::cout << current_prompt_;
        	}

		std::cout.flush();
		readUserInput();
	} 
}

void Interpreter::setLogUserCommands(bool enable) {

	if ((enable)&&(!log_file_.is_open())) {
                std::time_t t = std::time(nullptr);
                std::tm tm = *std::localtime(&t);
                std::basic_stringstream<char> filename;

                filename.imbue(std::locale());
                filename << "user_commands." << getpid() << "." << std::put_time(&tm, "%Y%m%d_%H%M%S") << ".log";
		log_file_.open(filename.str().c_str(), std::ofstream::out | std::ofstream::app);
	} else if ((!enable)&&(log_file_.is_open())) {

		log_file_.close();
	}
}

#endif

} // namespace aiengine 



