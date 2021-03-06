/*
 * main.c
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

//https://github.com/renbaoke/h3c

#include <signal.h>
#include "echo.h"
#include "h3c.h"
#include "handler.h"

void usage(FILE *stream);

int main(int argc, char **argv)
{
    int ch;
    char *interface = NULL;
    char *username = NULL;
    char *password = NULL;
    int alloc_pw = 0;  //局部变量

    /*
    * int getopt(int argc,char * const argv[],const char *opstring)
    * opstring是选项字母组成的字符串，如果该字母后面有冒号，那么这个选项就要求有选项参数
    * getopt()返回第一个选项，并设置一些全局变量，使用相同的参数再次调用该函数，它将返回
    * 一个选项，并设置相应的全局变量，如果不再有可识别的选项，将返回-1，此任务相同
    * "i:u:p:h" 表示i,u,p,h 是选项字符，后面有冒号表示选项元素后面一定有一个参数，且参数保存在optarg中
    */
    while ((ch = getopt(argc, argv, "i:u:p:h")) != -1)
    {
        switch (ch)
        {
            case 'i':
                interface = optarg;
                break;
            case 'u':
                username = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'h':
                usage(stdout);
                exit(0);
            default:
                usage(stderr);
                exit(-1);
        }
    }

    /* must run as root  需要以root身份运行*/
    if (geteuid() != 0)
    {
        fprintf(stderr, "Run as root, please!\n");
        exit(-1);
    }

    /*interface表示网卡，其中eth0,eth1 表示网卡1; 网卡2 lo表示127.0.0.1 即localhost*/
    if (interface == NULL || username == NULL)
    {
        usage(stderr);
        exit(-1);
    }

    /*设置用户名*/
    if (h3c_set_username(username) != SUCCESS)
    {
        fprintf(stderr, "Failed to set username.\n");
        exit(-1);
    }

    /*如果用户在输入用户名的时候没有输入密码，则提示再一次输入密码*/
    if (password == NULL)
    {
        /*输入之前先分配空间，以便用户输入密码，因为password是局部变量*/
        if ((password = (char *) malloc(PWD_LEN)) == NULL)
        {
            fprintf(stderr, "Failed to malloc: %s\n", strerror(errno));
            exit(-1);
        }
        /*给passwd 分配的空间成功，这里的password是局部变量，它的作用域已经将那个静态变量覆盖*/
        alloc_pw = 1;
        printf("Password for %s:", username);

        /*SIGINT 中断信号，通常由用户生成*/
        signal(SIGINT, exit_with_echo_on);
        /*SIGTERM 发送给本程序的终止请求信号，如果有，则正常退出程序*/
        signal(SIGTERM, exit_with_echo_on);

        //输入密码的时候先关闭回显功能
        echo_off();

        /*fegets将换行符'/n'也算作是该行字符，因此后面需要去除'\n'*/
        fgets(password, PWD_LEN - 1, stdin);
        //密码输入完后开启回显功能
        echo_on();

        /*将输入密码多保存的的'\n'改为'\0'，表示字符终结*/
        password[strlen(password) - 1] = '\0';
        putchar('\n');
    }

    if (h3c_set_password(password) != SUCCESS)
    {
        fprintf(stderr, "Failed to set password.\n");
        if (alloc_pw)
            free(password); /*释放在堆区申请的空间，以免造成内存泄漏*/
        exit(-1);
    }
    /*密码输入时分配的空间及时释放，以免造成内存泄漏（路由器的内存有限）*/
    if (alloc_pw)
        free(password);

    if (h3c_init(interface) != SUCCESS)
    {
        fprintf(stderr, "Failed to initialize: %s\n", strerror(errno));
        exit(-1);
    }

    if (h3c_start() != SUCCESS)
    {
        fprintf(stderr, "Failed to start: %s\n", strerror(errno));
        exit(-1);
    }

    /*在输入完密码之后，如果用户想要退出，则输出*/
    signal(SIGINT, exit_handler);
    signal(SIGTERM, exit_handler);

    while (1)
    {
        if (h3c_response(success_handler, failure_handler, unkown_eapol_handler,
                         unkown_eap_handler, got_response_handler) != SUCCESS)
        {
            fprintf(stderr, "Failed to response: %s\n", strerror(errno));
            exit(-1); //异常退出
        }
    }

    return 0;
}

void usage(FILE *stream)
{
    fprintf(stream, "Usage: h3c [OPTION]...\n");
    fprintf(stream, "  -i <interface>\tspecify interface, required\n");
    fprintf(stream, "  -u <username>\t\tspecify username, required\n");
    fprintf(stream, "  -p <password>\t\tspecify password, optional\n");
    fprintf(stream, "  -h\t\t\tshow this message\n");
}

