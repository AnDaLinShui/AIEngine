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
#include "Regex.h"
#include "RegexManager.h"

namespace aiengine {

int Regex::ovecount_[32] = {0};
char Regex::extract_buffer_[256] = {0};

Regex::Regex(const std::string &name, const std::string &exp, const SharedPointer<Regex> &re):
	Signature(name,exp),
        next_regex_(re),
        is_terminal_(true),
        have_jit_(false),
        show_match_(false),
        show_packet_(false),
        write_packet_(false),
        have_evidence_(false),
        continue_(false),
        rm_(nullptr) {

	study_exp_ = NULL;
        const char *errorstr;
        int erroffset;
        const char *buffer = const_cast<const char*>(exp.c_str());
        exp_ = pcre_compile(buffer, PCRE_DOTALL, &errorstr, &erroffset, 0);
        if (exp_ == NULL) 
        	throw errorstr;

	if (re) is_terminal_ = false; 

#if defined(PCRE_HAVE_JIT) 
	study_exp_ = pcre_study(exp_, PCRE_STUDY_JIT_COMPILE, &errorstr);
        if (study_exp_ != NULL) {
        	int jit = 0;
                int ret = pcre_fullinfo(exp_, study_exp_, PCRE_INFO_JIT, &jit);
		if ((ret == 0)or(jit == 1)) {
                        have_jit_ = true;
                }
	}
#else
	study_exp_ = pcre_study(exp_, 0, &errorstr);
#endif
}

Regex::Regex(const std::string &name, const std::string &exp):
	Regex(name, exp, nullptr) {}

Regex::~Regex() {

	next_regex_.reset();
	rm_.reset();

        pcre_free_study(study_exp_);
        pcre_free(exp_);
}

#if defined(PYTHON_BINDING)

Regex::Regex(const std::string &name, const std::string &exp, boost::python::object callback):
	Regex(name,exp) {

	if (!callback.is_none()) {
		// Check if is a SharedPointer<Regex>
		boost::python::extract<SharedPointer<Regex>> extractor(callback);
		if (extractor.check()) {
			SharedPointer<Regex> re = extractor();

			setNextRegex(re);
		} else {
			// Take the PyObject from the boost::python::object
			PyObject *obj = callback.ptr();
			
			setCallback(obj);
		}
	}
}

Regex::Regex(const std::string &name, const std::string &exp, boost::python::object callback, const SharedPointer<Regex> &re):
	Regex(name, exp, re) {

	setCallback(callback.ptr());
}

#endif

void Regex::setNextRegex(const SharedPointer<Regex> &re) { 

	next_regex_ = re;
	is_terminal_ = false;
	rm_.reset(); // Remove the reference to the RegexManager if exists
}

void Regex::setNextRegexManager(const SharedPointer<RegexManager> &rm) { 

	rm_ = rm; 
	is_terminal_ = false; 
	next_regex_.reset(); // Remove the reference 
}

bool Regex::evaluate(const boost::string_ref &data) {

       	++total_evaluates_;

        int ret = pcre_exec(exp_, NULL, data.data(), data.length(), 0, 0, NULL, 0);
        if (ret == 0) {
		++total_matchs_;
		return true;
	}
       	return false;
}

bool Regex::matchAndExtract(const boost::string_ref &data) {

        bool result = false;

        int ret = pcre_exec(exp_, NULL, data.data(), data.length(), 0, 0, ovecount_, 32);
        if (ret == 1)
                result = true;

        ret = pcre_copy_substring(data.data(), ovecount_, ret, 0, extract_buffer_, 256);

        if (result)
                ++total_matchs_;
        ++total_evaluates_;
        return result;
}

std::ostream& operator<< (std::ostream &out, const Regex &sig) {

	out << boost::format("Name:%-25s Matchs:%-10d Evaluates:%-10d") % sig.getName() % sig.getMatchs() % sig.total_evaluates_;
#if defined(BINDING)
        if (sig.call.haveCallback())
        	out << " Callback:" << sig.call.getCallbackName();
#endif
	out << std::endl;
	return out;
}

#if defined(JAVA_BINDING)

void Regex::setNextRegexManager(RegexManager *rm) {
	SharedPointer<RegexManager> s_rm;

        if (rm != nullptr) {
        	s_rm.reset(rm);
        }
        setNextRegexManager(s_rm);
}

void Regex::setNextRegex(Regex *regex) {
	SharedPointer<Regex> r;

        if (regex != nullptr) {
        	r.reset(regex);
        }
	setNextRegex(r);
}

#endif

} // namespace aiengine
