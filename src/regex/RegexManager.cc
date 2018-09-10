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
#include <iostream>
#include "RegexManager.h"

namespace aiengine {

RegexManager::RegexManager(const std::string &name):
#if defined(BINDING)
        call(),
#endif
	name_(name),
	plugged_to_name_(""),
	current_regex_(),
        total_matched_regexs_(0),
        regexs_() {} 

#if defined(PYTHON_BINDING) 
RegexManager::RegexManager(const std::string &name, boost::python::list &regexs):
	RegexManager(name) {

	for (int i = 0; i < len(regexs); ++i) {
                // Check if is a SharedPointer<Regex>
		boost::python::extract<SharedPointer<Regex>> extractor(regexs[i]);
		if (extractor.check()) {
			auto re = extractor();
			
			addRegex(re);
		}
	}
}
#endif

void RegexManager::removeRegex(const std::string &name,const std::string &expression) {

	for (auto it = regexs_.begin(); it != regexs_.end();) {
                auto ssig = (*it);

		if ((name.compare(ssig->getName()) == 0)and(expression.compare(ssig->getExpression()) == 0)) {
			// Erase the item
			it = regexs_.erase(it);
		} else {
			++it;	
		}
	}
}

void RegexManager::removeRegex(const SharedPointer<Regex> &sig) {

	for (auto it = regexs_.begin(); it != regexs_.end();) {
                auto ssig = (*it);

		if (ssig == sig) {
			// Erase the item
			it = regexs_.erase(it);
		} else {
			++it;
		}
	}
}

void RegexManager::addRegex(const std::string &name, const std::string &expression) {

        SharedPointer<Regex> sig = SharedPointer<Regex>(new Regex(name, expression));

        addRegex(sig);
}

void RegexManager::addRegex(const SharedPointer<Regex>& sig) {

        regexs_.push_back(sig);
}

void RegexManager::evaluate(const boost::string_ref &data, bool *result) {

	current_regex_.reset();

        for (auto &re: regexs_) {

                if (re->evaluate(data)) {
                        ++total_matched_regexs_;
                        current_regex_ = re;
                        (*result) = true;
                        return;
                }
        }
        return;
}

void RegexManager::show_regex(std::basic_ostream<char> &out, std::function<bool (const Regex&)> condition) const {

        out << "RegexManager (" << name_ << ")";

        if (plugged_to_name_.length() > 0) {
                out << " Plugged on " << plugged_to_name_;
        }

#if defined(BINDING)
	if (call.haveCallback()) out << " Callback:" << call.getCallbackName(); 
#endif
	out << std::endl;

        for (auto &it : regexs_ ) {
                SharedPointer<Regex> re = it;
                std::ostringstream tabs;

                bool no_more_regex = false;

                while (no_more_regex == false) {
                        tabs << "\t";

			if (condition(*re.get())) {
        			out << tabs.str() <<  *re.get();
                        }
                        if (re->isTerminal() == false) {

                                if (re->getNextRegexManager())
                                        break;

                                no_more_regex = false;
                                SharedPointer<Regex> raux = re->getNextRegex();
                                if (raux)
                                        re = raux;
                        } else {
                                no_more_regex = true;
                        }
                }
        }
}

void RegexManager::statistics() const { 

	statistics(OutputManager::getInstance()->out());
}

void RegexManager::statistics(std::basic_ostream<char> &out) const {

	show_regex(out, [&] (const Regex& f) { return true; });
}

void RegexManager::statistics(const std::string &name) const {

	show_regex(OutputManager::getInstance()->out(), [&] (const Regex &f) 
	{ 
		if (name.compare(f.getName()) == 0) 
			return true;
		else
			return false; 
	});
}

std::ostream& operator<< (std::ostream& out, const RegexManager &sig) {

	sig.statistics(out);
	return out;
}

void RegexManager::resetStatistics() {

        for (auto &it : regexs_ ) {
                SharedPointer<Regex> re = it;
               	re->total_matchs_ = 0; 
		re->total_evaluates_ = 0;

                while (!re->isTerminal()and(!re->getNextRegexManager())) {

                        SharedPointer<Regex> raux = re->getNextRegex();
                        if (raux) {
                        	re = raux;
               			re->total_matchs_ = 0; 
				re->total_evaluates_ = 0;
			}
                }
        }
}

#if defined(BINDING)

void RegexManager::showMatchedRegexs(std::basic_ostream<char> &out) const {

        std::vector<SharedPointer<Regex>> matched_regexs;

        for (auto &r : regexs_ ) {
		if (r->getMatchs() > 0)
			matched_regexs.push_back(r);
	}

        // Sort by using lambdas

        std::sort(
                matched_regexs.begin(),
                matched_regexs.end(),
                [] (const SharedPointer<Regex> &r1, const SharedPointer<Regex> &r2 )
                {
                        return r1->getMatchs() > r2->getMatchs();
        });

        out << "RegexManager (" << name_ << ")";

        if (plugged_to_name_.length() > 0) {
                out << " Plugged on " << plugged_to_name_;
        }

        out << "\n";

        for (auto &item: matched_regexs)
                out << "\t" << *item;

	out.flush();
}
#endif

} // namespace aiengine
