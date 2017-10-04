/*
 * h3c.h
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

#ifndef H3C_H_
#define H3C_H_

#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#ifdef AF_LINK
/* BSD */
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/bpf.h>
#include <net/if_types.h>
#include <fcntl.h>



#ifdef __NetBSD__
#include <net/if_ether.h>
#elif __FreeBSD__
#include <net/ethernet.h>
#elif __OpenBSD__
#include <netinet/if_ether.h>
//#else
//#error 'UNKOWN UNIX PLATFORM'
#endif

#else
/* Linux */
#include <netpacket/packet.h>
#include <net/ethernet.h>
#endif /* AF_LINK */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EAPOL_VERSION 1

#define EAPOL_EAPPACKET 0
#define EAPOL_START 1
#define EAPOL_LOGOFF 2
#define EAPOL_KEY 3
#define EAPOL_ASF 4

#define EAP_TYPE_ID 1
#define EAP_TYPE_MD5 4
#define EAP_TYPE_H3C 7

#define EAP_REQUEST 1
#define EAP_RESPONSE 2
#define EAP_SUCCESS 3
#define EAP_FAILURE 4

#define BUF_LEN 256
#define MSG_LEN 32
#define MD5_LEN 16
#define USR_LEN 16
#define PWD_LEN 16
#define TYPE_LEN 1
#define MD5_LEN_LEN 1
#define H3C_LEN_LEN 1

#ifndef ETH_P_PAE
#define ETH_P_PAE 0x888E
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

/* Function Status */
#define SUCCESS 0
#define USR_TOO_LONG 1
#define PWD_TOO_LONG 2
#define BPF_OPEN_ERR 3
#define BPF_SET_BUF_LEN_ERR 4
#define BPF_SET_IF_ERR 5
#define BPF_SET_FILTER_ERR 6
#define BPF_SET_IMMEDIATE_ERR 7
#define BPF_SET_DIRECTION_ERR 8
#define SOCKET_OPEN_ERR 9
#define SOCKET_SET_IF_ERR 10
#define SOCKET_GET_HWADDR_ERR 11
#define SEND_ERR 12
#define RECV_ERR 13
#define EAPOL_UNHANDLED 14
#define EAP_UNHANDLED 15
#define SUCCESS_UNHANDLED 16
#define FAILURE_UNHANDLED 17
#define RESPONSE_UNHANDLED 18

//__attribute__ 可以设置函数属性，变量属性，类型属性，放在声明的尾部； 之前
// packed 主要目的是让编译器更紧凑的使用内存，当作用与变量时，告诉编译应该尽可能小的对齐，也就是1字节对齐
//作用于结构体时，相当于给每个成员加上了packed属性，这时结构体应该尽可能少的占用内存
struct eapol {
	unsigned char version; //版本
	unsigned char type;    //类型
	unsigned short length; //长度
}__attribute__ ((packed)) eapol;

struct eap {
	unsigned char code;
	unsigned char id;
	unsigned short length;
}__attribute__ ((packed)) eap;


/*
* EAP协议用于PPP等点对点的网络中的认证，可支持多种认证机制，在802.1X中，对EAP协议进行了简单的修改形成了
* EAPOL（EAP overLAN）协议，使其能在广播式的以太网中使用，EAP工作在OSI的第二层（数据链路层），不需要用户
* 事先获取IP地址，简单易实现，主要用于客户端和认证者之间的认证信息交互
* */

/*
* struct ether_header{
* u_int8 ether_dhost[ETH_ALEN]; // destination ether addr,6个字节
* u_int8 ether_shost[ETH_ALEN]; //source ether addr，8个字节
* u_int16_t ether_type; //packet type ID field
* */
struct packet {
	struct ether_header eth_header;
	struct eapol eapol_header;
	struct eap eap_header;
}__attribute__ ((packed)) packet;

const static char PAE_GROUP_ADDR[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };/* broadcast mac address */

const static char VERSION_INFO[] = { 0x06, 0x07, 'b', 'j', 'Q', '7', 'S', 'E',
		'8', 'B', 'Z', '3', 'M', 'q', 'H', 'h', 's', '3', 'c', 'l', 'M', 'r',
		'e', 'g', 'c', 'D', 'Y', '3', 'Y', '=', 0x20, 0x20 };/* learned from yah3c */

/*
 * param _interface: ethernet device name, e.g. eth0
 * Use ifconfig to find ethernet device name.
 */
int h3c_init(char *_interface);

int h3c_start();
int h3c_logoff();

int h3c_response(int (*success_callback)(void), int (*failure_callback)(void),
		int (*unkown_eapol_callback)(void), int (*unkown_eap_callback)(void),
		int (*got_response_callback)(void));

int h3c_set_username(char *_username);
int h3c_set_password(char *_password);

void h3c_clean();

#endif /* H3C_H_ */
