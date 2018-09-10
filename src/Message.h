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
#ifndef SRC_MESSAGE_H_
#define SRC_MESSAGE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <fstream>
#include <chrono>
#include "Color.h"

namespace aiengine {

static std::function <void(const std::string&, const Color::Modifier&)> 
	generic_message = [] (const std::string &msg, const Color::Modifier &color) noexcept {

        char mbstr[100];

        std::chrono::system_clock::time_point time_point = std::chrono::system_clock::now();
        std::time_t now = std::chrono::system_clock::to_time_t(time_point);

        std::strftime(mbstr, 100, "%D %X", std::localtime(&now));

        if (isatty(fileno(stdout))) {
                Color::Modifier green(Color::FG_GREEN);
                Color::Modifier def(Color::FG_DEFAULT);
                std::cout << green << "[" << mbstr << "] " << color << msg << def << std::endl;
        } else {
                std::cout << "[" << mbstr << "] " << msg << std::endl;
        }
};

// Generic function for pretty print information messages
static std::function <void(const std::string&)> information_message = [] (const std::string &msg) noexcept {

	generic_message(msg, Color::Modifier(Color::FG_DEFAULT));
};


// Generic function for pretty print error messages
static std::function <void(const std::string&)> error_message = [] (const std::string &msg) noexcept {
	
	generic_message(msg, Color::Modifier(Color::FG_RED));
};

// Generic function for pretty print warning messages
static std::function <void(const std::string&)> warning_message = [] (const std::string &msg) noexcept {
	
	generic_message(msg, Color::Modifier(Color::FG_BLUE));
};

} // namespace aiengine  

#endif  // SRC_MESSAGE_H_
