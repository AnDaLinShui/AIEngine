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
#include "DomainName.h"

namespace aiengine {

DomainName::DomainName(const std::string &name, const std::string &expression):
	Signature(name, expression),
	uris_(),
	rm_(),
	uri_regexs_(),
	have_regex_manager_(false)
#if defined(PYTHON_BINDING)
	,py_uri_()
	,py_rm_()
	,py_uri_regexs_()
#endif
	{}

#if defined(PYTHON_BINDING)

DomainName::DomainName(const std::string &name, const std::string &expression, boost::python::object callback):
        DomainName(name, expression) {

        if (!callback.is_none()) {
                // Take the PyObject from the boost::python::object
                PyObject *obj = callback.ptr();

                setCallback(obj);
        }
}

#endif

std::ostream& operator<< (std::ostream &out, const DomainName &dom) {
       
	out <<  boost::format("Name:%-25s Domain:%-30s Matchs:%-10d") % dom.getName() % dom.getExpression() % dom.getMatchs();
	if (dom.uris_) out << " plug to:" << dom.uris_->getName();
#if defined(BINDING)
        if (dom.call.haveCallback())
                out << " Callback:" << dom.call.getCallbackName();
#endif
	out << std::endl; 
       	return out;
}

void DomainName::setRegexManager(const SharedPointer<RegexManager> &rm) { 

	if (rm_) {
		rm_->setPluggedToName("");
	}
	if (rm) {
		rm_ = rm;
		rm_->setPluggedToName(getName());
		have_regex_manager_ = true;
	} else {
		rm_.reset();
		have_regex_manager_ = false;
	}
}

#if defined(PYTHON_BINDING)

void DomainName::setPyHTTPUriRegexManager(boost::python::object &obj) { 

        if (obj.is_none()) {
                // The user sends a Py_None
                uri_regexs_.reset();
		py_uri_regexs_ = boost::python::object();
        } else {
                boost::python::extract<SharedPointer<RegexManager>> extractor(obj);

                if (extractor.check()) {
                        SharedPointer<RegexManager> rm = extractor();
                        uri_regexs_ = rm;
			py_uri_regexs_ = obj;
                }
        }
}

void DomainName::setPyHTTPUriSet(boost::python::object &obj) { 

        if (obj.is_none()) {
                // The user sends a Py_None
                uris_.reset();
		py_uri_ = boost::python::object();
        } else {
                boost::python::extract<SharedPointer<HTTPUriSet>> extractor(obj);

                if (extractor.check()) {
                        SharedPointer<HTTPUriSet> uset = extractor();
                        uris_ = uset;
			py_uri_ = obj;
                }
        }
}

void DomainName::setPyHTTPRegexManager(boost::python::object &obj) {

        if (obj.is_none()) {
                // The user sends a Py_None
                rm_.reset();
                py_rm_ = boost::python::object();
		have_regex_manager_ = false;
        } else {
                boost::python::extract<SharedPointer<RegexManager>> extractor(obj);

                if (extractor.check()) {
                        SharedPointer<RegexManager> r = extractor();

			setRegexManager(r);
                        py_rm_ = obj;
                }
        }
}

#elif defined(JAVA_BINDING)

void DomainName::setHTTPUriSet(HTTPUriSet *uset) {

	SharedPointer<HTTPUriSet> us;

	if (uset != nullptr) {
		us.reset(uset);
	}
	setHTTPUriSet(us);
}

void DomainName::setRegexManager(RegexManager *regex_mng) {
	SharedPointer<RegexManager> rm;

	if (regex_mng != nullptr) {
		rm.reset(regex_mng);
	}
	setRegexManager(rm);
}

#elif defined(LUA_BINDING) || defined(GO_BINDING)

void DomainName::setRegexManager(RegexManager &sig) {

	SharedPointer<RegexManager> rm = SharedPointer<RegexManager>(new RegexManager());

	rm.reset(&sig);
	
	setRegexManager(rm);
}

void DomainName::setHTTPUriSet(HTTPUriSet &uset) {
	SharedPointer<HTTPUriSet> hset(new HTTPUriSet());

	hset.reset(&uset);

	setHTTPUriSet(hset);
}

#endif

} // namespace aiengine

