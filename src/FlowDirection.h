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
//#pragma once
#ifndef SRC_FLOWDIRECTION_H_
#define SRC_FLOWDIRECTION_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <cstdint>

namespace aiengine {

enum class FlowDirection: int8_t {
	FORWARD = 0, 
	BACKWARD = 1,
	NONE = 2 
};

} // namespace aiengine 

#endif  // SRC_FLOWDIRECTION_H_
