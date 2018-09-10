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
#ifndef SRC_TIMERMANAGER_H_
#define SRC_TIMERMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <boost/bind.hpp>
#include "Timer.h"

#if defined(PYTHON_BINDING)
#include <boost/python.hpp>
#include "PyGilContext.h"
#endif

namespace aiengine {

class TimerManager {
public:
	explicit TimerManager(boost::asio::io_service &io_service):
		io_service_(io_service) {}

	virtual ~TimerManager() { timers_.clear(); }

#if defined(PYTHON_BINDING)
	void addTimer(PyObject *callback, int seconds);
	void statistics(std::basic_ostream<char> &out) const;
	friend std::ostream& operator<< (std::ostream &out, const TimerManager &tm);
#elif defined(LUA_BINDING)
	void addTimer(lua_State* L, const char *callback, int seconds);
	void statistics(std::basic_ostream<char> &out) const;
	friend std::ostream& operator<< (std::ostream &out, const TimerManager &tm);
#elif defined(RUBY_BINDING)
	void addTimer(VALUE callback, int seconds);
	void statistics(std::basic_ostream<char> &out) const;
	friend std::ostream& operator<< (std::ostream &out, const TimerManager &tm);
#endif

private:
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)
 	void start_timer(const SharedPointer<Timer> timer); 
 	void stop_timer(const SharedPointer<Timer> timer); 
	void scheduler_handler(boost::system::error_code error, const WeakPointer<Timer> timer); 
#endif
	boost::asio::io_service &io_service_;
	std::map<int, SharedPointer<Timer>> timers_;
};

} // namespace aiengine

#endif  // SRC_TIMERMANAGER_H_
