/*
 * h3c.c
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

#include "h3c.h"
#include "md5/md5.h"

//send_buf是发送的缓冲区
#define send_pkt ((struct packet *)send_buf)

#ifdef AF_LINK
#define sdl(p) ((struct sockaddr_dl *)(p))
#define recv_pkt ((struct packet *)(recv_buf + \
        ((struct bpf_hdr *)recv_buf)->bh_hdrlen))
#else
#define recv_pkt ((struct packet *)recv_buf)
#endif

#define eap_type(p) ((unsigned char *)(p) + sizeof(struct packet))
#define eap_data(p) (eap_type(p) + TYPE_LEN)

#define eap_id_info(p) eap_data(p)
#define eap_id_username(p) ((eap_id_info(p)) + sizeof(VERSION_INFO))

#define eap_md5_length(p) eap_data(p)
#define eap_md5_data(p) ((eap_md5_length(p)) + MD5_LEN_LEN)
#define eap_md5_username(p) ((eap_md5_data(p)) + MD5_LEN)

#define eap_h3c_length(p) eap_data(p)
#define eap_h3c_password(p) ((eap_h3c_length(p)) + H3C_LEN_LEN)
#define eap_h3c_username(p) (eap_h3c_password(p) + password_length)

static int sockfd;

//USR_LEN和PWD_LEN的长度均为16
static char username[USR_LEN];
static char password[PWD_LEN];

//BUF_LEN的长度为256
/* 发送缓冲区 */
static unsigned char send_buf[BUF_LEN];
/* 接收缓冲区 */
static unsigned char recv_buf[BUF_LEN];


/*
*  BPF 提供了以下的方便数组初始化
*  BPF_STMT(opcode,prand)
*  BPF_JUMP(opcode,operand,true_offset,false_offset)
* */

#ifdef AF_LINK
static struct bpf_insn insns[] =
        {
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_PAE, 0, 1),
                BPF_STMT(BPF_RET + BPF_K, (u_int) -1),
                BPF_STMT(BPF_RET + BPF_K, 0)
        };

/*
* 指令数组长度
* 指令数组
* */
static struct bpf_program filter =
        {
                sizeof(insns) / sizeof(insns[0]),
                insns
        };
#else
static struct sockaddr_ll addr;
#endif /* AF_LINK */

static inline void set_eapol_header(unsigned char type, unsigned short length)
{
    //eapol 数据包的头包括协议类型，
    //协议版本表示EAPOL帧发送方所支持的协议版本号
    //type 表示EAPOL数据帧的类型，EAP-packet值为0x00认证信息帧，用于承载认信息，该帧在设备端重新封装并承载于
    //RADIUS协议上，便于穿越复杂的网络到达认证服务器
    send_pkt->eapol_header.version = EAPOL_VERSION; //EAPOL_VERSION 的值为1
    send_pkt->eapol_header.type = type;
    send_pkt->eapol_header.length = length;
}

static inline void set_eap_header(unsigned char code, unsigned char id, unsigned short length)
{
    send_pkt->eap_header.code = code;
    send_pkt->eap_header.id = id;
    send_pkt->eap_header.length = length;
}

static int sendout(int length)
{
#ifdef AF_LINK
    /* 将send_buf 里的内容的内容写入到打开的设备文件中*/
    if (write(sockfd, send_buf, length) == -1)
        return SEND_ERR;
    else
        return SUCCESS;
#else
    if (sendto(sockfd, send_buf, length, 0, (struct sockaddr*) &addr,
            sizeof(addr)) == -1)
        return SEND_ERR;
    else
        return SUCCESS;
#endif /* AF_LINK */
}

static int recvin(int length)
{
#ifdef AF_LINK
    if (read(sockfd, recv_buf, length) == -1)
        return RECV_ERR;
    else
        return SUCCESS;

#else
    socklen_t len;
    len = sizeof(addr);

    if (recvfrom(sockfd, recv_buf, length, 0, (struct sockaddr *) &addr, &len)
            == -1)
        return RECV_ERR;
    else
        return SUCCESS;
#endif /* AF_LINK */
}

static int send_id(unsigned char packet_id)
{
    int username_length = (int) strlen(username);
    unsigned short len = htons(sizeof(struct eap) + TYPE_LEN + sizeof(VERSION_INFO) + username_length);

    set_eapol_header(EAPOL_EAPPACKET, len);
    set_eap_header(EAP_RESPONSE, packet_id, len);
    *eap_type(send_pkt) = EAP_TYPE_ID;

    memcpy(eap_id_info(send_pkt), VERSION_INFO, sizeof(VERSION_INFO));
    memcpy(eap_id_username(send_pkt), username, username_length);

    return sendout(sizeof(struct packet) + TYPE_LEN + sizeof(VERSION_INFO) + username_length);
}

/* 注意packid 也传进来了*/
static void get_md5_digest(unsigned char *digest, unsigned char packet_id, char *passwd, unsigned char *md5data)
{
    unsigned char msgbuf[128]; // msgbuf = packet_id + passwd + md5data
    unsigned short msglen;
    unsigned short passlen;
    passlen = (unsigned short) strlen(passwd);
    msglen = (unsigned short) (1 + passlen + 16);
    msgbuf[0] = packet_id;
    memcpy(msgbuf + 1, passwd, passlen);
    memcpy(msgbuf + 1 + passlen, md5data, 16);


    // calculate MD5 digest，计算MD5摘要
    md5_state_t state;
    md5_init(&state);
    md5_append(&state, (const md5_byte_t *) msgbuf, msglen);
    md5_finish(&state, digest);
}

static int send_md5(unsigned char packet_id, unsigned char *md5data)
{
    int username_length = (int) strlen(username);
    /*生成的密文为128位*/
    unsigned char md5[MD5_LEN];
    unsigned short len = htons(sizeof(struct eap) + TYPE_LEN +
                               MD5_LEN_LEN + MD5_LEN + username_length);

    /* pack_id 指明是报文的id*/
    memset(md5, 0, MD5_LEN);
    get_md5_digest(md5, packet_id, password, md5data);

    set_eapol_header(EAPOL_EAPPACKET, len);
    set_eap_header(EAP_RESPONSE, packet_id, len);
    *eap_type(send_pkt) = EAP_TYPE_MD5;

    *eap_md5_length(send_pkt) = MD5_LEN;
    memcpy(eap_md5_data(send_pkt), md5, MD5_LEN);
    memcpy(eap_md5_username(send_pkt), username, username_length);

    return sendout(sizeof(struct packet) + TYPE_LEN + MD5_LEN_LEN +
                   MD5_LEN + username_length);
}

static int send_h3c(unsigned char packet_id)
{
    int username_length = (int) (strlen(username));
    int password_length = (int) (strlen(password));
    unsigned short len = htons(
            sizeof(struct eap) + 1 + 1 + password_length + username_length);

    /*
    *  发送认证请求信息,所以帧是EAP-PACKET 类型
    *  EAPOL的Length 计数时不包括头部的长度
    *  EAP的Length 的字段包含头部的长度
    */
    set_eapol_header(EAPOL_EAPPACKET, len);
    set_eap_header(EAP_RESPONSE, packet_id, len);
    *eap_type(send_pkt) = EAP_TYPE_H3C;

    *eap_h3c_length(send_pkt) = (unsigned char) password_length;
    memcpy(eap_h3c_password(send_pkt), password, password_length);
    memcpy(eap_h3c_username(send_pkt), username, username_length);

    return sendout(
            sizeof(struct packet) + TYPE_LEN + H3C_LEN_LEN + password_length
            + username_length);
}

int h3c_init(char *_interface)
{
    /*  初始化信息包括组播mac地址，协议类型888E，以及接口名字*/
    struct ifreq ifr; //ifreq用来保存接口信息

    /* Set destination mac address. */
    // 目的组播mac地址为0x0180c2000003,mac地址长度为6个字节，所以拷贝6个字节的长度
    memcpy(send_pkt->eth_header.ether_dhost, PAE_GROUP_ADDR, ETH_ALEN);

    /* Set ethernet type. */
    //htons(x) 将主机的字节序转为网络字节序，网络字节序是TCP、IP 规定的好的一种数据表示格式
    //它与具体的CPU类型，操作系统无关，采用大端(big endian)的排序方式
    //ETH_P_PAE 0x888E 表示的是协议类型，802.1x分配的协议类型为888E
    send_pkt->eth_header.ether_type = htons(ETH_P_PAE);

    strcpy(ifr.ifr_name, _interface); //保存接口名字

    /*#if 的含义是如果#if后面的表达式为true，则编译它控制的代码
     #ifdef 表示如果有定义
     AF_LINK链路地址协议*/
#ifdef AF_LINK
    struct ifaddrs *ifhead, *ifa;
    /*
    * BPF 是类unix上数据链路层的一种原始接口，提供原始的数据链路层封装包的收发
    * BSD 分组过滤程序(BPF)是一种软件设备，用于过滤网络接口的数据流，即给网络接口加上开关
    * 应用程序打开/dev/bpf0, /dev/bpf1等等设备
    *
    * BPF的工作步骤如下：当一个数据包到达网络接口时，数据链路层的驱动会把它向系统的协议栈传送。
    * 但如果 BPF 监听接口，驱动首先调用 BPF。BPF 首先进行过滤操作，然后把数据包存放在过滤器相关的缓冲区中，
    * 最后设备驱动再次获得控制，但是请注意BPF是先对数据包过滤再缓冲
    * 通过若干ioctl命令，可以配置BPF设备，把它与每个网络接口相关联，并安装过滤程序，
    * 从而能够选择性的接收输入的分组，BPF设备打开后，应用进程通过读写设备来接收分组，或将分组放入到网络接口队列中
    *
    * http://www.gsp.com/cgi-bin/man.cgi?topic=bpf
    * 使用wireshark抓包工具
    * */
    char device[] = "/dev/bpf0";
    int n = 0;

    do
    {
        /*以读写方式打开BPF接口*/
        sockfd = open(device, O_RDWR);
        /*如果当前设备文件正在使用中，则打开失败，并将errno设置为EBUSY，因此轮询打开下一个设备设备文件*/
    } while ((sockfd == -1) && (errno == EBUSY) && (device[8]++ != '9'));


    if (sockfd == -1)
        return BPF_OPEN_ERR;

    n = BUF_LEN;
    /*设置BPF读取的缓冲区的长度,必须先设置缓冲区长度*/
    if (ioctl(sockfd, BIOCSBLEN, &n) == -1)
        return BPF_SET_BUF_LEN_ERR;

    /*
    * 打开BPF设备后，文件描述符必须绑定到特定网络接口，这里是eth0
    * 必须在读取任何数据包之前打开该命令，网络接口由ifreq中的ifr_name指定
    * */
    if (ioctl(sockfd, BIOCSETIF, &ifr) == -1)
        return BPF_SET_IF_ERR;

    /*设置BPF的过滤程序来丢弃不感兴趣的包*/
    if (ioctl(sockfd, BIOCSETF, &filter) == -1)
        return BPF_SET_FILTER_ERR;

    n = 1;
    /*
    * 根据参数的值来确定启用或者禁用"立即模式"，当立即模式启用时，数据包接收后立即读取，否则将
    * 阻塞，直到内核缓冲区变满或发生超时，猜测1应该是立即读取模式。
    * */
    if (ioctl(sockfd, BIOCIMMEDIATE, &n) == -1)
        return BPF_SET_IMMEDIATE_ERR;

#ifdef __NetBSD__
    n = 0;
    if (ioctl(sockfd, BIOCSSEESENT, &n) == -1)
        return BPF_SET_DIRECTION_ERR;
#elif __FreeBSD__
    n = BPF_D_IN;
    if (ioctl(sockfd, BIOCSDIRECTION, &n) == -1)
        return BPF_SET_DIRECTION_ERR;
#elif __OpenBSD__
    n = BPF_DIRECTION_OUT;
    if (ioctl(sockfd, BIOCSDIRFILT, &n) == -1)
        return BPF_SET_DIRECTION_ERR;
#endif

#else
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_PAE))) == -1)
        return SOCKET_OPEN_ERR;

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1)
        return SOCKET_SET_IF_ERR;
    else
        addr.sll_ifindex = ifr.ifr_ifindex;

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
        return SOCKET_GET_HWADDR_ERR;

    /* Set source mac address. */
    memcpy(send_pkt->eth_header.ether_shost, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
#endif /* AF_LINK */

    return SUCCESS;
}

int h3c_set_username(char *_username)
{
    int username_length = (int) strlen(_username);
    //用户名最长为15字符
    if (username_length > USR_LEN - 1)
        return USR_TOO_LONG;

    //username 是静态变量，用来存储用户名
    strcpy(username, _username);
    return SUCCESS; //SUCCESS 的值为0
}

int h3c_set_password(char *_password)
{
    int password_length = (int) strlen(_password);

    /*PWD_LEN==16，密码最长为15个字符*/
    if (password_length > PWD_LEN - 1)
        return PWD_TOO_LONG;

    /*password 是静态变量，用来存储用户名*/
    strcpy(password, _password);
    return SUCCESS;

}

/*把组播地址，本机mac地址，以及上一层的协议类型
* 本机支持的eapol客户端版本，帧类型为认证发起帧，长度为0
* */
int h3c_start()
{
    //设置eapol报头的数据帧类型是EAPOL_START，其值为1，表示是认证发起帧
    set_eapol_header(EAPOL_START, 0);  //EAPOL协议是局域网的扩展认证协议，POL是一个普遍的认证机制

    //以太网的报头（目的地址，源地址，以及上一层的协议类型）
    // 和eapol协议报头（这里只有3个域，分别协议版本其默认值为1，数据帧类型是认证发起，以及长度为0）
    return sendout(sizeof(struct ether_header) + sizeof(struct eapol));
}

int h3c_logoff()
{
    /*设置eapol帧为退出请求帧*/
    set_eapol_header(EAPOL_LOGOFF, 0);
    return sendout(sizeof(struct ether_header) + sizeof(struct eapol));
}

/*
* 传入的参数为：
* success_handler, failure_handler, unkown_eapol_handler,
* unkown_eap_handler, got_response_handler)
* */
int h3c_response(int (*success_callback)(void), int (*failure_callback)(void),
                 int (*unkown_eapol_callback)(void), int (*unkown_eap_callback)(void),
                 int (*got_response_callback)(void))
{
    if (recvin(BUF_LEN) == RECV_ERR)
        return RECV_ERR;

    // EAPOL_EAPPACKET 表示认证信息帧，用于承载认证信息,如果读出来的是这个就
    if (recv_pkt->eapol_header.type != EAPOL_EAPPACKET)
    {
        /* Got unknown eapol type. */
        if (unkown_eapol_callback != NULL)
            return unkown_eapol_callback();
        else
            return EAPOL_UNHANDLED;
    }

    /*认证成功*/
    if (recv_pkt->eap_header.code == EAP_SUCCESS)
    {
        /* Got success. */
        if (success_callback != NULL)
            return success_callback();
        else
            return SUCCESS_UNHANDLED;

        /* 认证失败*/
    } else if (recv_pkt->eap_header.code == EAP_FAILURE)
    {
        /* Got failure. */
        if (failure_callback != NULL)
            return failure_callback();
        else
            return FAILURE_UNHANDLED;
    } else if (recv_pkt->eap_header.code == EAP_REQUEST)
        /*
         * Got request.
         * Response according to request type.
         * EAP_TYPE_ID ==1 也就是type==1--identifier 用来询问对端的身份
         * EAP_TYPE_MD5 == 5 也就是type==5--MD5-Challenge (类似于CHAP中的MD5-challange,使用MD5算法)
         * eap_header.id 用于应答报文和请求报文之间的匹配
         *
         */
        if (*eap_type(recv_pkt) == EAP_TYPE_ID)
            return send_id(recv_pkt->eap_header.id);
        else if (*eap_type(recv_pkt) == EAP_TYPE_MD5)
            return send_md5(recv_pkt->eap_header.id, eap_md5_data(recv_pkt));
        else if (*eap_type(recv_pkt) == EAP_TYPE_H3C)
            return send_h3c(recv_pkt->eap_header.id);
        else
            return SUCCESS;
    else if (recv_pkt->eap_header.code == EAP_RESPONSE)
    {
        /* Got response. */
        if (got_response_callback != NULL)
            return got_response_callback();
        else
            return RESPONSE_UNHANDLED;
    } else
    {
        /* Got unkown eap type. */
        if (unkown_eap_callback != NULL)
            return unkown_eap_callback();
        else
            return EAP_UNHANDLED;
    }
}

void h3c_clean()
{
    /*close将描述字的访问计数-1，只有在此计数为0时关闭套接字，而shutdown是不管访问计数的，直接关闭*/
    close(sockfd);
}
