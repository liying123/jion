#include "uniqid_impl.h"

#define SERVER_ADDRESS_SADDR "127.0.0.1"
#define SERVER_ADDRESS_PORT 8866
#define SENDMAXBUF 1024
#define MESSAGEFILE "/var/log/messages"

int name_uniqid_impl(const char* pname,char* puniqid)
{ 
    FILE *fps = NULL;
    int client_sockfd = 0; 
    struct sockaddr_in dest; //服务器端网络地址结构体 
    char buffer[SENDMAXBUF] = { 0 };
    char senbuff[SENDMAXBUF] = { 0 };
    char err_msg[1024] = { 0 };
    int ret = 0;
    int len = 0;
    int i = 0;
    char messagetime[48] = {0};
    time_t timep;
    char chartemp[256] = {0};
    char* temp = NULL;

    time(&timep);
    memcpy(messagetime,ctime(&timep),strlen(ctime(&timep))-1);
    fps = fopen(MESSAGEFILE, "a");
	if(fps == NULL){
        ret = OPEN_MESSAGEFILE_ERR;
        goto out;
	}
	    
    if ((NULL == pname) || (NULL == puniqid)){
        memset(err_msg, 0, sizeof(err_msg));
        sprintf(err_msg, "%s %s[%d]:input pname err.\n",messagetime,__func__, __LINE__);
        fputs(err_msg,fps);
        ret = INPUT_PNAME_ERR;
        goto out;
    }

    if((client_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)//建立客户端socket 
    {
        memset(err_msg, 0, sizeof(err_msg));
        sprintf(err_msg, "%s %s[%d]:socket err.\n",messagetime,__func__, __LINE__);
        fputs(err_msg,fps);
        ret = SOCKET_ERR;
        goto out;
    }
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET; 
    dest.sin_addr.s_addr = inet_addr(SERVER_ADDRESS_SADDR);
    dest.sin_port = htons(SERVER_ADDRESS_PORT);
    len = sizeof(dest);
    if(connect(client_sockfd,(struct sockaddr *)&dest,len) != 0)
    {
        memset(err_msg, 0, sizeof(err_msg));
        sprintf(err_msg, "%s %s[%d]:connect err.\n",messagetime,__func__, __LINE__);
        fputs(err_msg,fps);
        ret = CONNECT_ERR;
        goto out;
    }

    if(fcntl(client_sockfd,F_SETFL,O_NONBLOCK) == -1) //设置socket非阻塞
    {
        memset(err_msg, 0, sizeof(err_msg));
        sprintf(err_msg, "%s %s[%d]:fcntl err.\n",messagetime,__func__, __LINE__);
        fputs(err_msg,fps);
        ret = FCNTL_ERR;
        goto out;
    }

    //发送数据
    for(i = 0;i < 5;i++)
    {
        sprintf(senbuff,"httc:%s",pname);
        //printf("send:len:%d,senbuff:%s\n",sizeof(senbuff),senbuff);
        if(send(client_sockfd,senbuff,sizeof(senbuff),0) == -1)
        {
            if(i == 4)
            {
                memset(err_msg, 0, sizeof(err_msg));
                sprintf(err_msg, "%s %s[%d]:send err.\n",messagetime,__func__, __LINE__);
                fputs(err_msg,fps);
                ret = SEND_ERR;
                goto out;
            }
        }
        else
        {
            break;
        }
    }
    
    for(i = 0;i < 5;i++)
    {
        //接收数据
        bzero(buffer,SENDMAXBUF + 1);
        len = recv(client_sockfd,buffer,SENDMAXBUF,0);
        //printf("recv:len:%d,senbuff:%s\n",len,buffer);
        if(len > 0)
        {
            if(temp = strstr(buffer,"httc"))
            {
                memset(chartemp,0,256);
                memcpy(chartemp,temp + 5,len - 5);
                strcpy(puniqid,chartemp);
            }
            else
            {
                ret = atoi(buffer);
            }
            break;
        }
        else
        {   sleep(1);
            if(i == 4)
            {
                if(len < 0)
                {
                    memset(err_msg, 0, sizeof(err_msg));
                    sprintf(err_msg, "%s %s[%d]:recv err.\n",messagetime,__func__, __LINE__);
                    fputs(err_msg,fps);
                    ret = RECV_ERR;
                    goto out;
                 }
                else
                {
                    memset(err_msg, 0, sizeof(err_msg));
                    sprintf(err_msg, "%s %s[%d]:the other quit,quit.\n",messagetime,__func__, __LINE__);
                    fputs(err_msg,fps);
                    ret = OTHER_QUIT;
                    goto out;
                }
            }
        }
    }
     
out:
    if (fps) fclose(fps);
    close(client_sockfd); 
    return ret; 
}

