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
#ifndef SRC_REGEX_REGEXMANAGER_H_
#define SRC_REGEX_REGEXMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <vector>
#include <list>
#include <sstream>
#include "Regex.h"
#include "OutputManager.h"

namespace aiengine {

class RegexManager {
public:
#if defined(PYTHON_BINDING)
	explicit RegexManager(const std::string &name, boost::python::list &regexs);
	explicit RegexManager(boost::python::list &regexs):RegexManager("Generic Regex Manager", regexs) {}
#endif
	explicit RegexManager(const std::string &name);
	explicit RegexManager():RegexManager("Generic Regex Manager") {}
        virtual ~RegexManager() = default; 

	void setName(const std::string &name) { name_ = name; }
	const char *getName() const { return name_.c_str(); }

	void setPluggedToName(const std::string &name) { plugged_to_name_ = name; }
	const char *getPluggedToName() const { return plugged_to_name_.c_str(); }

	int32_t getTotalRegexs() { return regexs_.size(); }
	int32_t getTotalMatchingRegexs() { return total_matched_regexs_; }

	void evaluate(const boost::string_ref &data, bool *result); 

#if defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING) || defined(GO_BINDING)
	void addRegex(Regex &sig) { 
		// Create a shared pointer and reset it to the object
		SharedPointer<Regex> re(new Regex());
		re.reset(&sig);

		addRegex(re); 
	}
#endif

	void addRegex(const std::string &name, const std::string &expression);
	void addRegex(const SharedPointer<Regex> &sig);
	
	void removeRegex(const std::string &name, const std::string &expression);
	void removeRegex(const SharedPointer<Regex> &sig);
	
	SharedPointer<Regex> getMatchedRegex() { return current_regex_; }

	friend std::ostream& operator<< (std::ostream &out, const RegexManager &sig);

	void statistics() const;
	void statistics(const std::string &name) const;
	void statistics(std::basic_ostream<char> &out) const;

	void resetStatistics();

#if defined(PYTHON_BINDING)
	// Methods for exposing the class to python iterable methods
	std::vector<SharedPointer<Regex>>::iterator begin() { return regexs_.begin(); }
	std::vector<SharedPointer<Regex>>::iterator end() { return regexs_.end(); }
#endif

#if defined(PYTHON_BINDING)
        void setCallback(PyObject *callback) { call.setCallback(callback); }
        PyObject *getCallback() const { return call.getCallback(); }
#elif defined(RUBY_BINDING)
        void setCallback(VALUE callback) { call.setCallback(callback); }
#elif defined(JAVA_BINDING)
        void setCallback(JaiCallback *callback) { call.setCallback(callback); }
#elif defined(LUA_BINDING)
        void setCallback(lua_State* L, const char *callback) { call.setCallback(L,callback); }
        const char *getCallback() const { return call.getCallback(); }
#elif defined(GO_BINDING)
	void setCallback(GoaiCallback *callback) { call.setCallback(callback); }
#endif

#if defined(BINDING)
	void showMatchedRegexs() const { showMatchedRegexs(OutputManager::getInstance()->out()); }
	void showMatchedRegexs(std::basic_ostream<char> &out) const;

        Callback call;
#endif

private:
	void show_regex(std::basic_ostream<char> &out, std::function<bool (const Regex&)> condition) const;

	std::string name_;
	std::string plugged_to_name_;
	SharedPointer<Regex> current_regex_;
	int32_t total_matched_regexs_;
	std::vector<SharedPointer<Regex>> regexs_;
};

typedef std::shared_ptr<RegexManager> RegexManagerPtr;
typedef std::weak_ptr<RegexManager> RegexManagerPtrWeak;

} // namespace aiengine

#endif  // SRC_REGEX_REGEXMANAGER_H_
