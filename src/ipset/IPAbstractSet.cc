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
#include "IPAbstractSet.h"

namespace aiengine {

IPAbstractSet::IPAbstractSet(const std::string &name):
	total_ips_(0),
	total_ips_not_on_set_(0),
	total_ips_on_set_(0),
#if defined(BINDING)
	call(),
#endif
	name_(name),
	rm_(),
	have_regex_mng_(false)
	{}

void IPAbstractSet::setRegexManager(const SharedPointer<RegexManager> &rm) {

	if (rm) {
		rm_ = rm; 
		have_regex_mng_ = true; 
	} else {
		rm_.reset();
		have_regex_mng_ = false;
	}
}

#if defined(RUBY_BINDING) 

void IPAbstractSet::setRegexManager(RegexManager &rm) {

        SharedPointer<RegexManager> rm_new = SharedPointer<RegexManager>(new RegexManager());
        rm_new.reset(&rm);

        setRegexManager(rm_new);
}

#elif defined(JAVA_BINDING)
void IPAbstractSet::setRegexManager(RegexManager *rm) {

	if (rm != nullptr) {
        	SharedPointer<RegexManager> rm_new(rm); 
			
		setRegexManager(rm_new);
	} else {
		rm_.reset();
		have_regex_mng_ = false;		
	}
}
 
#endif

} // namespace aiengine

