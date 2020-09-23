/*
   Copyright (C) 2020 by Sarat Kumar Behera <beherasaratkumar@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _STRINGF_H_
#define _STRINGF_H_

#include <sstream>
#include <iostream>
#include <string.h>
#include <string>
#include <stdlib.h>
#include <cinttypes>

std::string stringf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
std::string stringnf(size_t n, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

std::string vstringf(const char *fmt, va_list args);
std::string vstringnf(size_t n, const char *fmt, va_list args);

#endif /* _STRINGF_H_ */
