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
#include "TimerManager.h"

namespace aiengine {

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)

void TimerManager::start_timer(const SharedPointer<Timer> t) {

       	t->timer->expires_from_now(boost::posix_time::seconds(t->seconds));
	t->timer->async_wait(boost::bind(&TimerManager::scheduler_handler, this,
       		boost::asio::placeholders::error, WeakPointer<Timer>(t)));
}

void TimerManager::stop_timer(const SharedPointer<Timer> t) {

	// t->setCallbackWithNoArgs(nullptr);
	t->timer->cancel();
}

void TimerManager::scheduler_handler(boost::system::error_code error, const WeakPointer<Timer> wt) {

	if (wt.expired()) {
#if DEBUG
		std::cout << __FILE__ << ":" << __func__ << ":Timer have been free\n";
#endif
		return;
	}

	SharedPointer<Timer> t = wt.lock();

       	// Check if the timer have been cancel
       	if (error ==  boost::asio::error::operation_aborted) {
#if DEBUG
		std::cout << __FILE__ << ":" << __func__ << ":Timer have been cancel (" << t->seconds << ")\n";
#endif
		timers_.erase(t->seconds);
               	return;
       	}

	t->executeCallback();

	start_timer(t);

       	return;
}

#if defined(PYTHON_BINDING)
void TimerManager::addTimer(PyObject *callback, int seconds) {
#elif defined(RUBY_BINDING)
void TimerManager::addTimer(VALUE callback, int seconds) {
#elif defined(LUA_BINDING)
void TimerManager::addTimer(lua_State* L, const char *callback, int seconds) {
#endif

	// The user wants to remove the callback
#if defined(PYTHON_BINDING)
        if (callback == Py_None) {
#elif defined(RUBY_BINDING)
	if (callback == Qnil) {
#elif defined(LUA_BINDING)
	if (callback == nullptr) {
#endif
		// Find any Timer for that seconds
		auto it = timers_.find(seconds);
        	if (it != timers_.end()) {
			SharedPointer<Timer> t = (*it).second;

        		stop_timer(t);	
			timers_.erase(it);
		}
        } else {
		// Verify that the object/callback or whatever can be called
#if defined(PYTHON_BINDING)
     		if (PyCallable_Check(callback)) { 
#elif defined(RUBY_BINDING)
                if (!NIL_P(callback)) {
#elif defined(LUA_BINDING)
                lua_getglobal(L, callback);
                if (lua_isfunction(L, -1)) {
#endif
			// Find any Timer for that seconds
        		SharedPointer<Timer> t;
			auto it = timers_.find(seconds);
			if (it != timers_.end()) {
				// The timer exists, reuse
				t = (*it).second;
			} else {
				// New timer
				t = SharedPointer<Timer>(new Timer(io_service_));
				timers_.emplace(seconds, t);
			}
#if defined(LUA_BINDING)
			t->setCallbackWithNoArgs(L, callback);
#else
			t->setCallbackWithNoArgs(callback);
#endif
                        t->seconds = seconds;
                        start_timer(t);
                }
        }
}

std::ostream& operator<< (std::ostream &out, const TimerManager &tm) {

	// This output dont have a header because is part of the PacketDispatcher output
	for (auto &item: tm.timers_) {
		auto t = item.second;

		out << "\t" << "Timer:" << t->getCallbackName() << " expires every " << item.first << " secs\n";
	}
	return out;
}

void TimerManager::statistics(std::basic_ostream<char> &out) const {

        out << *this;
}

#endif

} // namespace aiengine
