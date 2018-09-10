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
#include "DomainNameManager.h"

namespace aiengine {

DomainNameManager::DomainNameManager(const std::string &name):
	name_(name),
	plugged_to_name_(""),
	root_(SharedPointer<DomainNode>(new DomainNode("root"))),
	total_domains_(0),
	total_bytes_(0),
	key_() 
	{}

#if defined(PYTHON_BINDING) 
DomainNameManager::DomainNameManager(const std::string &name, boost::python::list &doms):
        DomainNameManager(name) {

        for (int i = 0; i < len(doms); ++i) {
		// Check if is a SharedPointer<DomainName>
		boost::python::extract<SharedPointer<DomainName>> extractor(doms[i]);
		if (extractor.check()) {
			auto d = extractor();

			addDomainName(d);
		}
	}
}
#endif

SharedPointer<DomainNode> DomainNameManager::find_domain_name_node(const SharedPointer<DomainName> &domain) {

        std::string exp(domain->getExpression());
        std::vector<std::string> tokens;
        boost::split(tokens, exp, boost::is_any_of("."));
        auto curr_node = root_;

        for(auto it = tokens.rbegin(); it != tokens.rend(); ++it) {
                std::string token(*it);

                if (token.length() > 0) {
			boost::string_ref key(token);
                        auto node = curr_node->haveKey(key);
                        if (node) {
				curr_node = node; 
                        }
                }
        }

	return curr_node;
}

void DomainNameManager::removeDomainName(const SharedPointer<DomainName> &domain) {

	SharedPointer<DomainNode> node;
	std::string exp(domain->getExpression());

	if (exp.compare("*") == 0) 
		node = root_;
	else
		node = find_domain_name_node(domain);

	if ((node)and(node != root_)) {
		node->setDomainName(nullptr);
		-- total_domains_;
	} else if (node == root_) { 
		/* Remove the * operator from the tree */
		root_->setDomainName(nullptr);
		root_->removeKey(root_);
		-- total_domains_;	
	}
}

void DomainNameManager::removeDomainNameByName(const std::string &name) {

	remove_domain_name_by_name(root_, name);
}

void DomainNameManager::addDomainName(const std::string &name, const std::string &expression) {

	SharedPointer<DomainName> dom = SharedPointer<DomainName>(new DomainName(name, expression));

	addDomainName(dom);
}

void DomainNameManager::addDomainName(const SharedPointer<DomainName> &domain) {

	std::string exp(domain->getExpression());

	/* The user wants to matchs all the domains */
	if (exp.compare("*") == 0) {
		root_->setDomainName(domain);
		root_->addKey(SharedPointer<DomainNode>(new DomainNode("*")));
		++total_domains_;
		return;
	}

	std::vector<std::string> tokens;
	boost::split(tokens, exp, boost::is_any_of("."));
	auto curr_node = root_;

	for(auto it = tokens.rbegin(); it != tokens.rend(); ++it) {
		std::string token(*it);

		if (token.length() > 0) {
			boost::string_ref key(token);
			auto node = curr_node->haveKey(key);
			if (!node) {
				auto new_node = SharedPointer<DomainNode>(new DomainNode(token));

				total_bytes_ += token.length() + sizeof(DomainNode);
				curr_node->addKey(new_node);
				curr_node = new_node;
			} else {
				curr_node = node;
			}
		}
	}
	
	// Just update if there is no other domain
	if (curr_node->getDomainName() == nullptr) {
		curr_node->setDomainName(domain);
		++total_domains_;
	}
}

SharedPointer<DomainName> DomainNameManager::getDomainName(const char *name) {

	boost::string_ref sname(name);

	return getDomainName(sname);
}

// TODO This function could be more optimal.
SharedPointer<DomainName> DomainNameManager::getDomainName(const boost::string_ref &name) {

	int start = 0;
	if (name.starts_with('.')) {
		start = 1;
	} 

	int pad = 0;
	int off = 0;	
        int prev_idx = name.length() - 1;
        int offset = prev_idx;
        auto curr_node = root_;
        SharedPointer<DomainName> domain_candidate(nullptr), domain_alt(nullptr);
	bool have_token = false;

        for (offset = prev_idx ; offset >= start ; --offset) {
                if (name.at(offset) == '.') {
			have_token = true;
			off = 1; pad = 0;
		} else if (offset == start){
			have_token = true;
			off = 0; pad = 1;
		} 
		if (have_token) {
			int length = prev_idx - offset + pad;
                        key_ = name.substr(offset + off, length);

                        auto node = curr_node->haveKey(key_);
                        if (node) {
                                curr_node = node;
				if (domain_candidate) domain_alt = domain_candidate;
                                domain_candidate = node->getDomainName();
                        } else {
                                if (domain_candidate) {
                                        domain_candidate->incrementMatchs();
					return domain_candidate;
				} else if (root_->getDomainName()) {
					auto dom = root_->getDomainName();
					dom->incrementMatchs();
					return dom;
				}	
                                return domain_candidate;
                        }
                        prev_idx = offset - 1;
			have_token = false;
		}
        }

	if (domain_candidate) {
		domain_candidate->incrementMatchs();
		return domain_candidate;
	} else if (domain_alt) {
		domain_alt->incrementMatchs();
		return domain_alt;
	} else if (root_->getDomainName()) {
		auto dom = root_->getDomainName();
		dom->incrementMatchs();
		return dom;
	}	
	return domain_candidate;
}

void DomainNameManager::transverse(const SharedPointer<DomainNode> node,
	std::function<void(const SharedPointer<DomainNode>&, const SharedPointer<DomainName>&)> condition) const {

	for (auto &it: *node) {
		auto nod = it.second;
		auto dname = nod->getDomainName();
		if (nod->getTotalKeys() > 0 ) {
			transverse(nod, condition);
		}
		if (dname) condition(nod, dname);
	}
}

void DomainNameManager::statistics(const std::string &name) {

        std::cout << "DomainNameManager (" << name_ <<")[" << name << "]"; 

	if (plugged_to_name_.length() > 0) {
		std::cout << " Plugged on " << plugged_to_name_;
	}

	std::cout << std::endl;

	transverse(root_, [&] (const SharedPointer<DomainNode> &n ,const SharedPointer<DomainName> &d) {
		if (name.compare(d->getName()) == 0) {
			std::cout << *d;		
		}
	});
}

void DomainNameManager::statistics(std::ostream &out) {

	out << *this;
}

void DomainNameManager::remove_domain_name_by_name(const SharedPointer<DomainNode> node, const std::string &name) {

	// Check if want to delete the root node *
	auto d = root_->getDomainName();
	if (d) {
        	std::string exp(d->getName());
	
		if (exp.compare(name) == 0) {
			root_->setDomainName(nullptr);
			root_->removeKey(root_);
			--total_domains_;
			return;
		}	
	}

        transverse(root_, [this, &name] (const SharedPointer<DomainNode> &n, const SharedPointer<DomainName> &d) {
                if (name.compare(d->getName()) == 0) {
                        n->setDomainName(nullptr);
			--total_domains_;
                }
        });
}

std::ostream& operator<< (std::ostream &out, const DomainNameManager &domain) {

        out << "DomainNameManager (" << domain.name_ <<")"; 
	
	if (domain.plugged_to_name_.length() > 0) {
		out << " Plugged on " << domain.plugged_to_name_;
	}
	out << std::endl;

	auto d = domain.root_->getDomainName();
	if (d) {
        	out << "\t" << *d;	
	}

        domain.transverse(domain.root_, [&domain, &out] (const SharedPointer<DomainNode> &n ,const SharedPointer<DomainName> &d) {
                out << "\t" << *d;
        });
       	return out;
}

void DomainNameManager::resetStatistics() {

	auto d = root_->getDomainName();
	if (d) {        
		d->total_matchs_ = 0;
		d->total_evaluates_ = 0;
        }

        transverse(root_, [&] (const SharedPointer<DomainNode> &n ,const SharedPointer<DomainName> &d) {
		d->total_matchs_ = 0;
		d->total_evaluates_ = 0;
        });
}

#if defined(BINDING)

void DomainNameManager::showMatchedDomains(std::basic_ostream<char> &out) const {

	std::vector<SharedPointer<DomainName>> matched_domains;

	auto d = root_->getDomainName();
	if (d) {        
		if (d->getMatchs() > 0)
			matched_domains.push_back(d);
	}

        transverse(root_, [&] (const SharedPointer<DomainNode> &n ,const SharedPointer<DomainName> &d) {
		if (d->getMatchs() > 0)
			matched_domains.push_back(d);
        });

        // Sort by using lambdas

        std::sort(
                matched_domains.begin(),
                matched_domains.end(),
                [] (const SharedPointer<DomainName> &d1, const SharedPointer<DomainName> &d2 )
                {
                        return d1->getMatchs() > d2->getMatchs();
        });

        out << "DomainNameManager (" << name_ <<")";

        if (plugged_to_name_.length() > 0) {
                out << " Plugged on " << plugged_to_name_;
        }
        out << "\n";
        
	for (auto &item: matched_domains) 
		out << "\t" << *item;

	out.flush();
}
#endif

} // namespace aiengine
