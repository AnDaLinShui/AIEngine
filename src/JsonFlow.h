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
#ifndef SRC_JSONFLOW_H_
#define SRC_JSONFLOW_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ostream>
#include <boost/variant.hpp>
#include <vector>
#include <map>

// Issue with ruby.h with isfinite state redefinition

#if !defined(RUBY_BINDING)
#include "json.hpp"
#endif

namespace aiengine {

// God save recursive_variant!
using json_map_t = boost::make_recursive_variant<
	std::string,
	int32_t,
	std::vector<uint8_t>,
	std::vector<std::string>,
	std::map<std::string, boost::recursive_variant_> 
>::type ;

#if defined(RUBY_BINDING)

static std::ostream& operator<<(std::ostream &out, const json_map_t &map)
{
    	struct visit : boost::static_visitor<void>
    	{
        	visit(std::ostream& os):os_(os) {}

        	void operator()(const std::map<std::string, json_map_t> &m) const {
            		os_ << "{";
            		int i = 0;
            		for(auto& item : m) {
                		os_ << "\"" << item.first << "\":";
                		boost::apply_visitor(visit(os_), item.second);
                		if ((i + 1) != m.size())
                        		os_ << ",";
                		++i;
            		}
            		os_ << "}";
        	}

        	void operator()(const std::string &str) const {
            		os_ << "\"" << str << "\"";
        	}

        	void operator()(const int32_t &a) const {
            		os_ << a;
        	}

        	void operator()(const std::vector<uint8_t> &a) const {
                        int i = 0;

                        for (auto &item: a) {
                                os_ <<  "\"" << (int)item << "\"";
                                if ((i + 1) != a.size())
                                        os_ << ",";
                                ++i;
                        }
        	}

        	void operator()(const std::vector<std::string> &a) const {
			int i = 0;

			for (auto &item: a) {
				os_ <<  "\"" << item << "\"";
				if ((i + 1) != a.size())
					os_ << ",";
				++i;
			}
        	}

    	private:
        	std::ostream& os_;
    	};

    	boost::apply_visitor(visit(out), map);
    	return out;
}
#endif

class JsonFlow {
public:
	JsonFlow():j() {}
    	virtual ~JsonFlow() {}

#if !defined(RUBY_BINDING)
        nlohmann::json j;
#else
	std::map<std::string, json_map_t> j;	
#endif
	friend std::ostream& operator<< (std::ostream &out, const JsonFlow &js) {

		out << js.j;
		return out;
	}
};

} // namespace aiengine 

#endif  // SRC_JSONFLOW_H_
