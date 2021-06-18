#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <zlib.h>

#define rport  "6666"
int socktrfd;

struct type_content{
	int	type;
	int	length;
	char	buff[199*1024];
};

int
tcp_socket_server(void)
{
	int socktrfd, connfd, reuse=1;
	struct sockaddr_in serveraddr, clientaddr;
	socklen_t peerlen;

	if((socktrfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "Could not create server socket");
	printf("tcp ser receive sockfd is: %d\n",socktrfd);
	
	bzero(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = inet_addr("192.168.123.100");//htonl(INADDR_ANY);
	serveraddr.sin_port = htons(atoi("10608"));
	//if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
	//	err(1, "setsockopt SO_REUSEADDR");
	if (bind(socktrfd, (struct sockaddr *)(&serveraddr), sizeof(struct sockaddr)) < 0)
		err(1, "bind failed");
	printf("bind success!\n");
	if (listen(socktrfd, 10) == -1)
		err(1, "socktrfd listening failed");
	printf("Listening...\n");
	peerlen = sizeof(struct sockaddr_in);
	if((connfd = accept(socktrfd, (struct sockaddr *)&clientaddr, &peerlen)) == -1)
		err(1,"accept failed");
	printf("Server get connection from : %s\n\n", inet_ntoa(clientaddr.sin_addr));

	return connfd;
}

int
main()
{
	int len;

	char buff[] = "Tcp Welcome to1 server!";
	char buffer[200*1024];
	memset(buffer, 0, sizeof(buffer));
	socktrfd = tcp_socket_server();

	while(1)
        {
		bzero(buffer, sizeof(buffer));
		len = recv(socktrfd, buffer, 200*1024, 0);
		struct type_content* t_content = (struct type_content* )buffer;
		printf("Tcp receive len:%d, type:%d, length:%d, content:\n%s\n", len, t_content->type, t_content->length, t_content->buff);

		int lens = send(socktrfd, buff, strlen(buff), MSG_NOSIGNAL);
		printf("Tcp send lens:%d, buff:%s\n", lens, buff);
	}
	close(socktrfd);
	return 0;

}


