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
#ifndef SRC_NAMES_DOMAINNAME_H__
#define SRC_NAMES_DOMAINNAME_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <iomanip>
#include "Pointer.h"
#include "Signature.h"
#include <boost/format.hpp>
#include "protocols/http/HTTPUriSet.h"
#include "regex/RegexManager.h"

namespace aiengine {

class DomainName: public Signature {
public:
#if defined(PYTHON_BINDING)
    	explicit DomainName(const std::string &name, const std::string &expression, boost::python::object callback);
#endif
    	explicit DomainName(const std::string &name, const std::string &expression);
	explicit DomainName():DomainName("None", "") {}

    	virtual ~DomainName() {}

	friend std::ostream& operator<< (std::ostream &out, const DomainName &dom); 
       
#if defined(PYTHON_BINDING)
        void setPyHTTPUriSet(boost::python::object &obj); 
        boost::python::object getPyHTTPUriSet() { return py_uri_; }

        void setPyHTTPUriRegexManager(boost::python::object &obj); 
        boost::python::object getPyHTTPUriRegexManager() { return py_uri_regexs_; }

	void setPyHTTPRegexManager(boost::python::object &obj);
	boost::python::object getPyHTTPRegexManager() { return py_rm_; }

#elif defined(RUBY_BINDING)
       	void setHTTPUriSet(const HTTPUriSet &uset) { setHTTPUriSet(std::make_shared<HTTPUriSet>(uset)); }
#elif defined(JAVA_BINDING)
	void setHTTPUriSet(HTTPUriSet *uset); 
	void setRegexManager(RegexManager *regex_mng);
#elif defined(LUA_BINDING) || defined(GO_BINDING)
	void setHTTPUriSet(HTTPUriSet &uset); 
	void setRegexManager(RegexManager& sig);
#endif

        void setHTTPUriSet(const SharedPointer<HTTPUriSet> &uset) { uris_ = uset; }
        SharedPointer<HTTPUriSet> getHTTPUriSet() const { return uris_; }

        void setHTTPUriRegexManager(const SharedPointer<RegexManager> &rm) { uri_regexs_ = rm; }
        SharedPointer<RegexManager> getHTTPUriRegexManager() const { return uri_regexs_; }

	void setRegexManager(const SharedPointer<RegexManager> &rm); 
	SharedPointer<RegexManager> getRegexManager() const { return rm_; }

	bool haveRegexManager() const { return have_regex_manager_; }

	// The rest from the base class
private:
	SharedPointer<HTTPUriSet> uris_;
	SharedPointer<RegexManager> rm_;
	SharedPointer<RegexManager> uri_regexs_;
	bool have_regex_manager_;
#if defined(PYTHON_BINDING)
	boost::python::object py_uri_;
	boost::python::object py_rm_;
	boost::python::object py_uri_regexs_;
#endif
};

typedef std::shared_ptr<DomainName> DomainNamePtr;
typedef std::weak_ptr<DomainName> DomainNamePtrWeak;

} // namespace aiengine

#endif  // SRC_NAMES_DOMAINNAME_H_
