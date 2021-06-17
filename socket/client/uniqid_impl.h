#ifndef __SOCKET_CLIENT_H__
#define __SOCKET_CLIENT_H__

#ifdef __cplusplus
extern "C"{
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <fcntl.h>
#include <time.h> 

/* 通过name获取uniqid函数 */
int name_uniqid_impl(const char* pname,char* puniqid);

/* name_uniqid_impl 函数返回值 */
#define SERVER_INPUT_ERR        -1
#define SERVER_FOPENFILE_ERR   -2
#define SERVER_FINDNAME_ERR    -3
#define REQUEST_HEAD_ERR        -4
#define OPEN_MESSAGEFILE_ERR   -5
#define INPUT_PNAME_ERR         -6
#define SOCKET_ERR              -7
#define CONNECT_ERR             -8
#define FCNTL_ERR               -9
#define SEND_ERR                -10
#define RECV_ERR                -11
#define OTHER_QUIT              -12




#ifdef __cplusplus
}
#endif

#endif


