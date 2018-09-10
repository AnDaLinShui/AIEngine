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

#ifndef SRC_COLOR_H_
#define SRC_COLOR_H_

// Idea from https://stackoverflow.com/questions/2616906/how-do-i-output-coloured-text-to-a-linux-terminal

namespace Color {

enum Code {
	FG_RED      = 31,
        FG_GREEN    = 32,
        FG_BLUE     = 34,
        FG_DEFAULT  = 39,
        BG_RED      = 41,
        BG_GREEN    = 42,
        BG_BLUE     = 44,
        BG_DEFAULT  = 49
};

class Modifier {
public:
        Modifier(Code pCode) : code_(pCode) {}

        friend std::ostream& operator<<(std::ostream& os, const Modifier& mod) {
        	return os << "\033[" << mod.code_ << "m";
        }
private:
	Code code_;
};

} // namespace Color

#endif  // SRC_COLOR_H_
