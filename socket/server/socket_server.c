#include <sys/types.h> 
#include <sys/socket.h> 
#include <stdio.h> 
#include <netinet/in.h> 
#include <sys/time.h> 
#include <sys/ioctl.h> 
#include <unistd.h> 
#include <stdlib.h>
#include <string.h> 
#include "rsfile.h"

#define SERVER_ADDRESS_SADDR "127.0.0.1"
#define SERVER_ADDRESS_PORT 8866

#define LISTEN_NUM 5
#define RECMAXBUFF 1024


int name_uniqid_impl_server(void)
{ 
    int server_sockfd = 0;
    int client_sockfd = 0;
    int server_len = 0;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    int retval = 0;
    int ret = 0;
    int retget = 0;
    fd_set readfds;
    fd_set testfds;
    int maxfd = -1;
    socklen_t len = 0;
    char err_msg[1024] = { 0 };
    struct timeval tv;
    char uniqid[256] = {0};
    char uniqidtmp[256] = {0};
    char uniqidret[4][10] = {"-1","-1","-2","-3"};
    char chartemp[256] = {0};
    char revbuff[RECMAXBUFF] = {0};
    char* temp = NULL;
    
    if((server_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)//建立服务器端socket
    {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"socket error. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
        system(err_msg);
        return -1;
    }
    
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(SERVER_ADDRESS_SADDR); 
    server_address.sin_port = htons(SERVER_ADDRESS_PORT);
    server_len = sizeof(server_address);
    
    if(bind(server_sockfd, (struct sockaddr *)&server_address, server_len) == -1)
    {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"bind error. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
        system(err_msg);
        ret = -2;
        goto out;
    }

    //监听队列最多容纳5个 
    if(listen(server_sockfd, LISTEN_NUM) == -1)
    {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"listen error. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
        system(err_msg);
        ret = -3;
        goto out;
    }

    while(1)
    {
        len = sizeof(struct sockaddr);
        if((client_sockfd = accept(server_sockfd,(struct sockaddr*)&client_address,&len)) == -1)
        {
            memset(err_msg, 0, sizeof(err_msg));
            snprintf(err_msg,sizeof(err_msg),"echo \"accept error,continue. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
            system(err_msg);
            continue;
        }

        while(1)
        {
            FD_ZERO(&readfds);
            FD_SET(client_sockfd, &readfds);
            maxfd = client_sockfd;
            tv.tv_sec = 5; //阻塞等待时间为5s
            tv.tv_usec = 0;
            retval = select(maxfd + 1,&readfds,NULL,NULL,&tv); //多路复用
            if(retval == -1) //函数执行出错
            {
                memset(err_msg, 0, sizeof(err_msg));
                snprintf(err_msg,sizeof(err_msg),"echo \"select error. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
                system(err_msg);
                continue;
            }
            else if(retval == 0) //若超时返回
            {
                memset(err_msg, 0, sizeof(err_msg));
                snprintf(err_msg,sizeof(err_msg),"echo \"select timeout. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
                system(err_msg);
                continue;
            }
            else
            {
                if(FD_ISSET(client_sockfd,&readfds))
                {
                    bzero(revbuff,RECMAXBUFF + 1);
                    len = recv(client_sockfd,revbuff,RECMAXBUFF,0);
                    //printf("recv:len:%d,senbuff:%s\n",len,revbuff);
                    if(len > 0)
                    {
                        if(temp = strstr(revbuff,"httc"))
                        {
                            memset(chartemp,0,256);
                            memset(uniqid,0,256);
                            memcpy(chartemp,temp + 5,len - 5);
                            retget = name_uniqid_get_impl(chartemp,uniqid);
                            //printf("name_uniqid_get_impl:retget:%d,uniqid:%s\n",retget,uniqid);
                            if(retget == 0)
                            {
                                memset(uniqidtmp,0,256);
                                sprintf(uniqidtmp,"httc:%s",uniqid);
                                //printf("send normal:len:%d,uniqid:%s\n",sizeof(uniqidtmp),uniqidtmp);
                                if(send(client_sockfd,uniqidtmp,sizeof(uniqidtmp),0) == -1)
                                {
                                    memset(err_msg, 0, sizeof(err_msg));
                                    snprintf(err_msg,sizeof(err_msg),"echo \"send normal data failed. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
                                    system(err_msg);
                                }
                            }
                            else if((retget >= 1) && (retget <= 3))
                            {
                                memset(uniqidtmp,0,256);
                                memcpy(uniqidtmp,uniqidret[retget],sizeof(uniqidtmp));
                                //printf("send name warning:len:%d,uniqid:%s\n",sizeof(uniqidtmp),uniqidtmp);
                                if(send(client_sockfd,uniqidtmp,sizeof(uniqidtmp),0) == -1)
                                {
                                    memset(err_msg, 0, sizeof(err_msg));
                                    snprintf(err_msg,sizeof(err_msg),"echo \"send name warning failed. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
                                    system(err_msg);
                                }
                            }
                        }
                        else
                        {
                            memset(uniqidtmp,0,256);
                            memcpy(uniqidtmp,"-4",sizeof(uniqidtmp));
                            //printf("send head warning:len:%d,uniqid:%s\n",sizeof(uniqidtmp),uniqidtmp);
                            if(send(client_sockfd,uniqidtmp,sizeof(uniqidtmp),0) == -1)
                            {
                                memset(err_msg, 0, sizeof(err_msg));
                                snprintf(err_msg,sizeof(err_msg),"echo \"send head warning failed. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
                                system(err_msg);
                            }
                        }
                    }
                    else if(len < 0)
                    {
                        memset(err_msg, 0, sizeof(err_msg));
                        snprintf(err_msg,sizeof(err_msg),"echo \"recv failed. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
                        system(err_msg);
                    }
                    else
                    {
                        memset(err_msg, 0, sizeof(err_msg));
                        snprintf(err_msg,sizeof(err_msg),"echo \"the other quit,quit. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
                        system(err_msg);
                    }
                }
                else
                {
                    memset(err_msg, 0, sizeof(err_msg));
                    snprintf(err_msg,sizeof(err_msg),"echo \" Not FD_ISSET Para. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
                    system(err_msg);
                }
                break;
            }
        }

        close(client_sockfd);
    }

out:
    close(server_sockfd);
    return ret;
}

void name_uniqid_server(void)
{
    int ret = 0;
    
    for(;;)
    {
        ret = name_uniqid_impl_server();
        if(ret != 0 )
        {
            continue;
        }
    }
    return;
}

int main() 
{ 
    int ret = 0;

    name_uniqid_mutex_init();

    name_uniqid_server();

    name_uniqid_mutex_destroy();
    
    return ret;
}

