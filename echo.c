/*
 * echo.c
 * 
 * Copyright 2015 BK <renbaoke@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */

#include "echo.h"

//echo off的意思是关闭命令行的回显
int echo_off(void)
{
    //tcgetattr用来获取终端的相关参数，tcsetattr 用来设置终端的相关参数
	struct termios flags;
    //fileno 获取文件流所使用的文件描述词
	if (tcgetattr(fileno(stdin), &flags) == -1) {
		fprintf(stderr, "Failed to echo_off: %s", strerror(errno));
		return -1;
	}


	flags.c_lflag &= ~ECHO;

	if (tcsetattr(fileno(stdin), TCSANOW, &flags) == -1) {
		fprintf(stderr, "Failed to echo_off: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int echo_on(void) {
	struct termios flags;
	if (tcgetattr(fileno(stdin), &flags) == -1) {
		fprintf(stderr, "Failed to echo_on: %s", strerror(errno));
		return -1;
	}

	flags.c_lflag |= ECHO;

	if (tcsetattr(fileno(stdin), TCSANOW, &flags) == -1) {
		fprintf(stderr, "Failed to echo_on: %s", strerror(errno));
		return -1;
	}

	return 0;
}


