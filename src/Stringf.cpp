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

#include "Stringf.h"
#include <stdarg.h>

using namespace std;

string stringf(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  string s = vstringf(fmt, args);
  va_end(args);
  return s;
}

string stringnf(size_t n, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  string s = vstringnf(n, fmt, args);
  va_end(args);
  return s;
}

string vstringf(const char *fmt, va_list args)
{
  char *buf = NULL;
  int r = vasprintf(&buf, fmt, args);
  if (r < 0)
    return string("<stringf ERROR>");
  string s(buf);
  free(buf);
  return s;
}

string vstringnf(size_t n, const char *fmt, va_list args)
{
  char buf[n];
  int r = vsnprintf(buf, n, fmt, args);
  if (r < 0)
    return string("<stringnf ERROR>");
  string s(buf);
  return s;
}
