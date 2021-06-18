#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <zlib.h>


static FILE* CF1 = NULL;
static FILE* CF2 = NULL;

struct sockaddr_in userveraddr;
int sockurfd, sockusfd, socktsfd;

int line1 = 0, sum1 = 0, time1 = 30;
int line2 = 0, sum2 = 0, time2 = 30;

struct timeval t_time1;
struct timeval t_time2;
struct timeval t_time3;
struct timeval t_time4;
struct timeval t_time5;
struct timeval t_time6;
struct timeval t_time7;

//int type_0 = 1000;
int type_3 = 1003;
int type_4 = 1004;
int type_5 = 1005;
int type_6 = 1006;
int type_7 = 1007;

//char test0[]="   ----tcp connect keeping detection heartbeat!!\n";
/* ==========================================================================================*/
/*store data types1-2*/
struct type_content1 {
	int	type;
	int	length;
	char	buff[150*1024];
};

/*store data types3-6*/
struct type_content2 {
	int	type;
	int	length;
	char	buff[2*1024];
};

/*store data type7*/
struct type_content3 {
	int	type;
	int	length;
	char	buff[1024];
};

char *
trim(char *str);

/* ==========================================================================================*/
/*struct mac list */
typedef struct Node
{
	char macstr[18];
	struct Node *next;
}Node;

Node *pList = NULL;

/* Init list */
void initlist(Node **pList)
{
	*pList = NULL;
}

/*create list*/
Node *createlist(Node *pList, char *mac)
{
	Node *p1;

	p1= (Node*)malloc(sizeof(Node));
	if(p1 == NULL){
		printf("Memory allocate Failure!\n");
	}
	memset(p1, 0, sizeof(Node));

	strcpy(p1->macstr, mac);
	p1->next = NULL;

	if(strlen(p1->macstr) != NULL)
	{
		if(pList == NULL)
		{
			pList = p1;
		}
	}
	return pList;
}

/*print list*/
void printlist(Node *pList)
{
	if(NULL == pList)
	{
		printf("print list is NULL\n");
	}
	else
	{
		while(NULL != pList)
		{
			printf("%s\n",pList->macstr);
			pList = pList->next;
		}
	}
	printf("\n");
}

/*clear list*/
Node *clearlist(Node **pList)
{
	Node *pNext = *pList;
	Node *pLast = NULL;

	while(pNext != NULL)
	{
		pLast = pNext->next;
		free(pNext);
		pNext = pLast;
	}
	*pList = NULL;
	return pList;
}

/*list size*/
void sizelist(Node *pList)
{
	int size = 0;
	while(pList != NULL)
	{
		size++;
		pList = pList->next;
	}
	printf("size list len:%d\n", size);
}

/*judge whether list is empty*/
int isemptylist(Node *pList)
{
	if (pList == NULL)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

/*judge whether the list contains mac*/
int listcontains(Node *pList, char *mac)
{
	if(NULL == pList)
	{
		printf("contains list is NULL\n");
	}
	if(strlen(mac) == NULL)
	{
		printf("mac value null ");
	}
	while(pList != NULL)
	{
		if (strcmp(pList->macstr, mac) == 0)
		{
			return 0;
		}
		pList = pList->next;
	}
	return 1;
}

/*insert mac in the list last*/
Node *insertlastlist(Node **pList, char *mac)
{
	if (*pList == NULL)
		printf("list is NULL\n");
	if(strlen(mac) == 0)
		printf("mac value is NULL\n");

	Node *pLast, *pTemp;
	pTemp = *pList;

	pLast = (Node *)malloc(sizeof(Node));
	memset(pLast, 0, sizeof(Node));

	strcpy(pLast->macstr, mac);
	pLast->next = NULL;

	while(pTemp->next !=NULL)
	{
		pTemp = pTemp->next;
	}
	pTemp->next = pLast;
	return pList;
}


/* UDP server socket for receive data from horst*/
int 
udp_socket_server(void)
{
	int sockurfd;
	struct sockaddr_in hostaddr;

	if ((sockurfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "Could not create local socket");
//	printf("Udp server sockurfd received from horst is : %d\n",sockurfd);

	bzero(&hostaddr, sizeof(struct sockaddr_in));
	hostaddr.sin_family = AF_INET;
	hostaddr.sin_addr.s_addr = htonl(INADDR_ANY);//inet_addr("192.168.1.1");
	hostaddr.sin_port = htons(atoi("4444"));
	if (bind(sockurfd, (struct sockaddr *)&hostaddr, sizeof(hostaddr)) < 0)
		err(1, "bind failed");
	return sockurfd;
}

/* UDP client socket for send equipment_state_info(type7) to server*/
int
udp_socket_client(void)
{
	int sockusfd, len1;

	if ((sockusfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "Could not create local socket");
	//printf("Udp client sockusfd send to server is: %d\n",sockusfd);

	bzero(&userveraddr, sizeof(userveraddr));
	userveraddr.sin_family = AF_INET;
	userveraddr.sin_addr.s_addr = inet_addr("121.41.57.242");
	userveraddr.sin_port = htons(atoi("10708"));

	if(connect(sockusfd, (struct sockaddr *)&userveraddr, sizeof(userveraddr)) < 0)
	{
		err(1,"connect failed");
	}
	return sockusfd;
}

/* TCP client socket for send type1-6 data to server*/
int
tcp_socket_client(void)
{
	int socktsfd;
	struct sockaddr_in tserveraddr;
	static char buf[256], *pbuf, *ppbuf;
	memset(buf, 0, sizeof(buf));

	static unsigned char ip[15];
	memset(ip, 0, sizeof(ip));
	int port, len;

	FILE *fp = fopen("/etc/config/statictype", "r");
	if (fp == NULL) {
		printf("Open send_server failed\n");
	}
	while(fgets(buf, sizeof(buf), fp)) {
		pbuf = buf;
		if(NULL != strstr(buf, "server_ip")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			len = strlen(ppbuf);
			strncpy(ip, ppbuf, len);
		}

		if(NULL != strstr(buf, "server_port")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			port = atoi(ppbuf);
		}
		bzero(buf, sizeof(buf));
	}
	fclose(fp);

	if ((socktsfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		err(1,"Could not open server socket");
	//printf("Tcp client sendto server socktsfd is: %d\n", socktsfd);

	memset(&tserveraddr, 0, sizeof(struct sockaddr_in));
	tserveraddr.sin_family = AF_INET;
	tserveraddr.sin_addr.s_addr = inet_addr(ip); //htonl(INADDR_ANY);
	tserveraddr.sin_port = htons(port);
	if (connect(socktsfd, (struct sockaddr *)&tserveraddr, sizeof(tserveraddr)) == -1) {
		printf("Tcp client connect failed!\n");
	}
	return socktsfd;
}

/* TCP send type1-2 data to server*/
int
tcpsend1(int socktsfd, struct type_content1 t_content)
{
	int len1;
	static unsigned char buf[150*1024];
	static unsigned char dstbuf[150*1024];
	memset(buf, 0, sizeof(buf));
	memset(dstbuf, 0, sizeof(dstbuf));
	unsigned long buflen = sizeof(buf);
	unsigned long dstlen = sizeof(dstbuf);
	int sendlen;

	//sendlen = 8 + t_content.length;	/*the sendlen of before compress*/

	compress(buf, &buflen, t_content.buff, t_content.length);
	bzero(t_content.buff, sizeof(t_content.buff));
	memcpy(t_content.buff, buf, buflen);
	t_content.length = buflen;
	sendlen = 8 + buflen;			/*the sendlen of after compress*/

	//uncompress(dstbuf, &dstlen, buf, buflen);

	len1 = send(socktsfd, &t_content, sendlen, MSG_NOSIGNAL);
	if (len1 == -1)
	{
		printf(" %d %s\n", errno, strerror(errno));
	}
	else
	{
	//	printf("Tcp send---len1:%d, type:%d, length:%d,content:\n%s\n", len1, t_content.type, t_content.length, t_content.buff);
	}
}

/* ---Type1---*/
void*
write_read_send1(struct type_content1* t_content, struct timeval s_time1)
{
	static char buf[256], *pbuf, *ppbuf;
	memset(buf, 0, sizeof(buf));

	fwrite(t_content->buff, strlen(t_content->buff), 1, CF1);
	sum1 = sum1 + (int)strlen(t_content->buff);
	line1++;

	if (line1 == 900 || s_time1.tv_sec - t_time1.tv_sec >= time1) {

		FILE *fp = fopen("/etc/config/statictype", "r");
		if (fp == NULL) {
			printf("Open send_interval1 failed\n");
		}
		while(fgets(buf, sizeof(buf), fp)) {
			pbuf = buf;
			if(NULL != strstr(buf, "type1_time")) {
				strsep(&pbuf, "'");
				ppbuf = strsep(&pbuf, "'");
				time1 = atoi(ppbuf);
			}
			bzero(buf, sizeof(buf));
		}
		fclose(fp);

		line1 = 0;
		gettimeofday(&t_time1, NULL);
		fclose(CF1);
		CF1 = fopen("test_terminal", "r");
		if (CF1 == NULL) {
			printf("Terminal open r1 fail:%s\n", strerror(errno));
		}

		struct type_content1 t_content1;
		memset(&t_content1, 0, sizeof(struct type_content1));
		if (fread(t_content1.buff, sum1, 1, CF1) > 0) {
			fflush(CF1);
			t_content1.type = t_content->type;
			t_content1.length = sum1;
		//	printf("type:%d, length:%d, content:\n%s\n", t_content1.type, t_content1.length, t_content1.buff);

			tcpsend1(socktsfd, t_content1);
			sum1 = 0;

			if (CF1 != NULL) {
				fclose(CF1);
				CF1 = NULL;
			}

			CF1 = fopen("test_terminal", "w");
			if (CF1 == NULL) {
				printf("Terminal open w1 fail:%s\n", strerror(errno));
			}
		}
	}
}

/* ---Type2---*/
void*
write_read_send2(struct type_content1* t_content, struct timeval s_time2) 
{
	static char buf[256], *pbuf, *ppbuf;
	memset(buf, 0, sizeof(buf));
	int sum = 0;

	fwrite(t_content->buff, strlen(t_content->buff), 1, CF2);
	sum2 = sum2 + (int)strlen(t_content->buff);
	line2++;

	if (line2 == 900 || s_time2.tv_sec - t_time2.tv_sec >= time2) {

		FILE *fp = fopen("/etc/config/statictype", "r");
		if (fp == NULL) {
			printf("Open send_interval2 failed\n");
		}
		while(fgets(buf, sizeof(buf), fp)) {
			pbuf = buf;
			if(NULL != strstr(buf, "type2_time")) {
				strsep(&pbuf, "'");
				ppbuf = strsep(&pbuf, "'");
				time2 = atoi(ppbuf);
			}
			bzero(buf, sizeof(buf));
		}
		fclose(fp);

		line2 = 0;
		gettimeofday(&t_time2, NULL);
		fclose(CF2);

		CF2 = fopen("test_ap", "r");
		if (CF2 == NULL) {
			printf("Ap open r2 fail:%s\n", strerror(errno));
		}

		sum = (int)strlen(t_content->buff);
		sum2 = sum2 - sum;
		struct type_content1 t_content2;
		memset(&t_content2, 0, sizeof(struct type_content1));
		if (fread(t_content2.buff, sum2, 1, CF2) > 0) {
			fflush(CF2);
			t_content2.type = t_content->type;
			t_content2.length = sum2;
		//	printf("type:%d, length:%d, content:\n%s\n", t_content2.type, t_content2.length, t_content2.buff);

			tcpsend1(socktsfd, t_content2);
			sum2 = 0;

			if (CF2 != NULL) {
				fclose(CF2);
				CF2 = NULL;
			}

			CF2 = fopen("test_ap", "w");
			if (CF2 == NULL) {
				printf("Ap open w2 fail:%s\n", strerror(errno));
			}

			clearlist(&pList);
		}
	}
}


/* TCP send type3-6  data to server*/
void
tcpsend2(int socktsfd, struct type_content2 t_content)
{
	int len2;
	static unsigned char buf[2*1024];
	static unsigned char dstbuf[2*1024];
	memset(buf, 0, sizeof(buf));
	memset(dstbuf, 0, sizeof(dstbuf));
	unsigned long buflen = sizeof(buf);
	unsigned long dstlen = sizeof(dstbuf);
	int sendlen;

	//sendlen = 8 + t_content.length;	/*the sendlen of before compress*/

	compress(buf, &buflen, t_content.buff, t_content.length);
	bzero(t_content.buff, sizeof(t_content.buff));
	memcpy(t_content.buff, buf, buflen);
	t_content.length = buflen;
	sendlen = 8 + buflen;			/*the sendlen of after compress*/

	//uncompress(dstbuf, &dstlen, buf, buflen);

	len2 = send(socktsfd, &t_content, sendlen, MSG_NOSIGNAL);
	if (len2 < 0)
	{
		printf("Data type %d failed to send!\n", t_content.type);
	}
	else
	{
	//	printf("Tcp send-len2:%d, type:%d, length:%d,content:\n%s\n", len2, t_content.type, t_content.length, t_content.buff);
	}
}

/* The trim function removes leading and trailing Spaces */
char *
trim(char *str)
{
	char *head, *tail, *rs;
	char *st = "Noinput";

	if (str == NULL)
	{
		return st;
	}
	for (head = str; *head == ' ' || *head == '\t' || *head == '\r' || *head == '\n';  head++);
	for (tail = str + strlen(str) - 1; (*tail == ' ' || *tail == '\t' || *tail == '\r' || *tail == '\n') && tail >= head; tail--);

	rs = str;
	while (head <= tail)
	{
		*str++ = *head++;
	}

	*str = 0;
	return rs;
}

/* ---Type3---*/
void
mobile_terminal_info(void)
{
	char COLLECTION_EQUIPMENT_ID3[21];		/*1采集设备编号*/
	char NETBAR_WACODE3[14];			/*2场所编号*/
	char COLLECTION_EQUIPMENT_LONGITUDE3[10];	/*3采集设备经度*/
	char COLLECTION_EQUIPMENT_LATITUDE3[10];	/*4采集设备纬度*/

	struct timeval s_time3;
	char buf[256], *pbuf, *ppbuf;
	memset(buf, 0, sizeof(buf));
	char buf3[2*1024];
	memset(buf3, 0, sizeof(buf3));

	FILE *fp = fopen("/etc/config/statictype", "r");
	if (fp == NULL) {
		printf("Open type3 failed\n");
	}

	while(fgets(buf, sizeof(buf), fp)) {
		pbuf = buf;
		if(NULL != strstr(buf, "COLLECTION_EQUIPMENT_ID3")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(COLLECTION_EQUIPMENT_ID3, ppbuf, 21);
		}
		if(NULL != strstr(buf, "NETBAR_WACODE3")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(NETBAR_WACODE3, ppbuf, 14);
		}
		if(NULL != strstr(buf, "COLLECTION_EQUIPMENT_LONGITUDE3")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(COLLECTION_EQUIPMENT_LONGITUDE3, ppbuf, 10);
		}
		if(NULL != strstr(buf, "COLLECTION_EQUIPMENT_LATITUDE3")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(COLLECTION_EQUIPMENT_LATITUDE3, ppbuf, 10);
		}
		bzero(buf, sizeof(buf));
	}
	fclose(fp);

	gettimeofday(&s_time3, NULL);
	
	sprintf(buf3, "%s\t%s\t%s\t%s\t%d\r\n", COLLECTION_EQUIPMENT_ID3, NETBAR_WACODE3, 
			COLLECTION_EQUIPMENT_LONGITUDE3, COLLECTION_EQUIPMENT_LATITUDE3, s_time3.tv_sec);

	struct type_content2 t_content3;
	memset(&t_content3, 0, sizeof(struct type_content2));
	t_content3.type = type_3;
	t_content3.length = strlen(buf3);
	strncpy(t_content3.buff, buf3, strlen(buf3));

	if (s_time3.tv_sec - t_time3.tv_sec >= 10*60) {
		tcpsend2(socktsfd, t_content3);
		gettimeofday(&t_time3, NULL);
	}
}

/* ---Type4---*/
void
terminal_info(void)
{
	char NETBAR_WACODE4[14];			/*1场所编号*/
	char COLLECTION_EQUIPMENT_ID4[21];		/*2采集设备编号*/
	char COLLECTION_EQUIPMENT_NAME4[128];		/*3采集设备名称:设备名称*/
	char COLLECTION_EQUIPMENT_ADRESS4[256];		/*4设备地址:地址信息*/
	int  COLLECTION_EQUIPMENT_TYPE4;		/*5采集设备类型*/
	char SECURITY_SOFTWARE_ORGCODE4[9];		/*6安全厂商组织机构代码:组织机构代码*/
	char COLLECTION_EQUIPMENT_LONGITUDE4[10];	/*7采集设备经度*/
	char COLLECTION_EQUIPMENT_LATITUDE4[10];	/*8采集设备纬度*/
	int UPLOAD_TIME_INTERVAL4;			/*9上传数据间隔时间:数据上传采集间隔,单位秒(s)*/
	int COLLECTION_RADIUS4;				/*10采集半径:单位米(m)*/
	char VEHICLE_CODE4[64];				/*11车牌号码*/
	char SUBWAY_LINE_INFO4[256];			/*12地铁线路信息*/
	char SUBWAY_VEHICLE_INFO4[256];			/*13地铁车辆信息*/
	char SUBWAY_COMPARTMENT_NUMBER4[256];		/*14地铁车厢编号*/

	struct timeval s_time4;
	char buf[256], *pbuf, *ppbuf;
	memset(buf, 0, sizeof(buf));
	char buf4[2*1024];
	memset(buf4, 0, sizeof(buf4));

	FILE *fp = fopen("/etc/config/statictype", "r");
	if (fp == NULL) {
		printf("Open type4 failed\n");
	}

	while(fgets(buf, sizeof(buf), fp)) {
		pbuf = buf;
		if(NULL != strstr(buf, "NETBAR_WACODE4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(NETBAR_WACODE4, ppbuf, 14);
		}
		if(NULL != strstr(buf, "COLLECTION_EQUIPMENT_ID4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(COLLECTION_EQUIPMENT_ID4, ppbuf, 21);
		}
		if(NULL != strstr(buf, "COLLECTION_EQUIPMENT_NAME4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(COLLECTION_EQUIPMENT_NAME4, ppbuf, 128);
		}
		if(NULL != strstr(buf, "COLLECTION_EQUIPMENT_ADRESS4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(COLLECTION_EQUIPMENT_ADRESS4, ppbuf, 256);
		}
		if(NULL != strstr(buf, "COLLECTION_EQUIPMENT_TYPE4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			COLLECTION_EQUIPMENT_TYPE4 = atoi(ppbuf);
		}
		if(NULL != strstr(buf, "SECURITY_SOFTWARE_ORGCODE4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(SECURITY_SOFTWARE_ORGCODE4, ppbuf, 9);
		}
		if(NULL != strstr(buf, "COLLECTION_EQUIPMENT_LONGITUDE4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(COLLECTION_EQUIPMENT_LONGITUDE4, ppbuf, 10);
		}
		if(NULL != strstr(buf, "COLLECTION_EQUIPMENT_LATITUDE4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(COLLECTION_EQUIPMENT_LATITUDE4, ppbuf, 10);
		}
		if(NULL != strstr(buf, "UPLOAD_TIME_INTERVAL4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			UPLOAD_TIME_INTERVAL4 = atoi(ppbuf);
		}
		if(NULL != strstr(buf, "COLLECTION_RADIUS4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			COLLECTION_RADIUS4 = atoi(ppbuf);
		}
		if(NULL != strstr(buf, "VEHICLE_CODE4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(VEHICLE_CODE4, ppbuf, 64);
		}
		if(NULL != strstr(buf, "SUBWAY_LINE_INFO4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(SUBWAY_LINE_INFO4, ppbuf, 256);
		}
		if(NULL != strstr(buf, "SUBWAY_VEHICLE_INFO4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(SUBWAY_VEHICLE_INFO4, ppbuf, 256);
		}
		if(NULL != strstr(buf, "SUBWAY_COMPARTMENT_NUMBER4")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(SUBWAY_COMPARTMENT_NUMBER4, ppbuf, 256);
		}
		bzero(buf, sizeof(buf));
	}
	fclose(fp);

	gettimeofday(&s_time4, NULL);
	
	sprintf(buf4, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\r\n", NETBAR_WACODE4, 
			COLLECTION_EQUIPMENT_ID4, COLLECTION_EQUIPMENT_NAME4, COLLECTION_EQUIPMENT_ADRESS4, 
			COLLECTION_EQUIPMENT_TYPE4, SECURITY_SOFTWARE_ORGCODE4, COLLECTION_EQUIPMENT_LONGITUDE4, 
			COLLECTION_EQUIPMENT_LATITUDE4, UPLOAD_TIME_INTERVAL4, COLLECTION_RADIUS4, VEHICLE_CODE4, 
			SUBWAY_LINE_INFO4, SUBWAY_VEHICLE_INFO4, SUBWAY_COMPARTMENT_NUMBER4);

	struct type_content2 t_content4;
	memset(&t_content4, 0, sizeof(struct type_content2));
	t_content4.type = type_4;
	t_content4.length = strlen(buf4);
	strncpy(t_content4.buff, buf4, strlen(buf4));

	if (s_time4.tv_sec - t_time4.tv_sec >= 24*60*60) {
		tcpsend2(socktsfd, t_content4);
		gettimeofday(&t_time4, NULL);
	}
}

/* ---Type5---*/
void
site_info(void)
{
	char NETBAR_WACODE5[14];			/*1上网服务场所编码*/
	char PLACE_NAME5[256];				/*2上网服务场所名称:场所名称*/
	char SITE_ADDRESS5[256];			/*3场所详细地址(包括省市区县路/弄号):地址信息*/
	char LONGITUDE5[10];				/*4场所经度*/
	char LATITUDE5[10];				/*5场所纬度*/
	char NETSITE_TYPE5[1];				/*6场所服务类型*/
	char BUSINESS_NATURE5[1];			/*7场所经营性质:0,表示经营;1.表示非经营;3,其他*/
	char LAW_PRINCIPAL_NAME5[128];			/*8场所经营法人:法人姓名*/
	char LAW_PRINCIPAL_CERTIFICATE_TYPE5[3];	/*9经营法人有效证件类型:证件类型*/
	char LAW_PRINCIPAL_CERTIFICATE_ID5[128];	/*10经营法人有效证件号码:证件号码*/
	char RELATIONSHIP_ACCOUNT5[128];		/*11联系方式:手机/座机号码*/
	char START_TIME5[5];				/*12营业开始时间:hh:mm,如:08:00*/
	char END_TIME5[5];				/*13营业结束时间:hh:mm,如:22:35*/
	char SECURITY_SOFTWARE_ORGCODE5[9];		/*14厂商组织机构代码:组织机构代码*/

	struct timeval s_time5;
	char buf[256], *pbuf, *ppbuf;
	memset(buf, 0, sizeof(buf));
	char buf5[2*1024];
	memset(buf5, 0, sizeof(buf5));

	FILE *fp = fopen("/etc/config/statictype", "r");
	if (fp == NULL) {
		printf("Open type5 failed\n");
	}

	while(fgets(buf, sizeof(buf), fp)) {
		pbuf = buf;
		if(NULL != strstr(buf, "NETBAR_WACODE5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(NETBAR_WACODE5, ppbuf, 14);
		}
		if(NULL != strstr(buf, "PLACE_NAME5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(PLACE_NAME5, ppbuf, 256);
		}
		if(NULL != strstr(buf, "SITE_ADDRESS5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(SITE_ADDRESS5, ppbuf, 256);
		}
		if(NULL != strstr(buf, "LONGITUDE5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(LONGITUDE5, ppbuf, 10);
		}
		if(NULL != strstr(buf, "LATITUDE5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(LATITUDE5, ppbuf, 10);
		}
		if(NULL != strstr(buf, "NETSITE_TYPE5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(NETSITE_TYPE5, ppbuf, 1);
		}
		if(NULL != strstr(buf, "BUSINESS_NATURE5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(BUSINESS_NATURE5, ppbuf, 1);
		}
		if(NULL != strstr(buf, "LAW_PRINCIPAL_NAME5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(LAW_PRINCIPAL_NAME5, ppbuf, 128);
		}
		if(NULL != strstr(buf, "LAW_PRINCIPAL_CERTIFICATE_TYPE5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(LAW_PRINCIPAL_CERTIFICATE_TYPE5, ppbuf, 3);
		}
		if(NULL != strstr(buf, "LAW_PRINCIPAL_CERTIFICATE_ID5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(LAW_PRINCIPAL_CERTIFICATE_ID5, ppbuf, 128);
		}
		if(NULL != strstr(buf, "RELATIONSHIP_ACCOUNT5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(RELATIONSHIP_ACCOUNT5, ppbuf, 128);
		}
		if(NULL != strstr(buf, "START_TIME5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(START_TIME5, ppbuf, 5);
		}
		if(NULL != strstr(buf, "END_TIME5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(END_TIME5, ppbuf, 5);
		}
		if(NULL != strstr(buf, "SECURITY_SOFTWARE_ORGCODE5")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(SECURITY_SOFTWARE_ORGCODE5, ppbuf, 9);
		}
		bzero(buf, sizeof(buf));
	}
	fclose(fp);

	gettimeofday(&s_time5, NULL);
	
	sprintf(buf5, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\r\n", NETBAR_WACODE5, PLACE_NAME5, 
			SITE_ADDRESS5, LONGITUDE5, LATITUDE5, NETSITE_TYPE5, BUSINESS_NATURE5, LAW_PRINCIPAL_NAME5, 
			LAW_PRINCIPAL_CERTIFICATE_TYPE5, LAW_PRINCIPAL_CERTIFICATE_ID5, RELATIONSHIP_ACCOUNT5, 
			START_TIME5, END_TIME5, SECURITY_SOFTWARE_ORGCODE5);

	struct type_content2 t_content5;
	memset(&t_content5, 0, sizeof(struct type_content2));
	t_content5.type = type_5;
	t_content5.length = strlen(buf5);
	strncpy(t_content5.buff, buf5, strlen(buf5));

	if (s_time5.tv_sec - t_time5.tv_sec >= 24*60*60) {
		tcpsend2(socktsfd, t_content5);
		gettimeofday(&t_time5, NULL);
	}
}

/* ---Type6---*/
void
security_vendor_info(void)
{
	char SECURITY_SOFTWARE_ORGNAME6[70];		/*1厂商名称*/
	char SECURITY_SOFTWARE_ORGCODE6[9];		/*2厂商组织机构代码:组织结构代码*/
	char SECURITY_SOFTWARE_ADDRESS6[256];		/*3厂商地址*/
	char CONTACTOR6[128];				/*4联系人:厂商联系人*/
	char CONTACTOR_TEL6[128];			/*5联系人电话:电话号码*/
	char CONTACTOR_MAIL6[32];			/*6联系人邮件:电子邮件地址*/

	struct timeval s_time6;
	char buf[256], *pbuf, *ppbuf;
	memset(buf, 0, sizeof(buf));
	char buf6[2*1024];
	memset(buf6, 0, sizeof(buf6));

	FILE *fp = fopen("/etc/config/statictype", "r");
	if (fp == NULL) {
		printf("Open type6 failed\n");
	}

	while (fgets(buf, sizeof(buf), fp))
	{
		pbuf = buf;
		if (NULL != strstr(buf, "SECURITY_SOFTWARE_ORGNAME6"))
		{
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(SECURITY_SOFTWARE_ORGNAME6, ppbuf, 70);
		}
		if (NULL != strstr(buf, "SECURITY_SOFTWARE_ORGCODE6"))
		{
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(SECURITY_SOFTWARE_ORGCODE6, ppbuf, 9);
		}
		if (NULL != strstr(buf, "SECURITY_SOFTWARE_ADDRESS6"))
		{
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(SECURITY_SOFTWARE_ADDRESS6, ppbuf, 256);
		}
		if (NULL != strstr(buf, "CONTACTOR_PEOPLE6"))
		{
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(CONTACTOR6, ppbuf, 128);
		}
		if (NULL != strstr(buf, "CONTACTOR_TEL6"))
		{
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(CONTACTOR_TEL6, ppbuf, 128);
		}
		if (NULL != strstr(buf, "CONTACTOR_MAIL6"))
		{
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(CONTACTOR_MAIL6, ppbuf, 32);
		}
		bzero(buf, sizeof(buf));
	}
	fclose(fp);

	gettimeofday(&s_time6, NULL);

	sprintf(buf6, "%s\t%s\t%s\t%s\t%s\t%s\r\n", SECURITY_SOFTWARE_ORGNAME6, SECURITY_SOFTWARE_ORGCODE6, 
			SECURITY_SOFTWARE_ADDRESS6, CONTACTOR6, CONTACTOR_TEL6, CONTACTOR_MAIL6);

	struct type_content2 t_content6;
	memset(&t_content6, 0, sizeof(struct type_content2));
	t_content6.type = type_6;
	t_content6.length = strlen(buf6);
	strncpy(t_content6.buff, buf6, strlen(buf6));

	if (s_time6.tv_sec - t_time6.tv_sec >= 24*60*60) {
		tcpsend2(socktsfd, t_content6);
		gettimeofday(&t_time6, NULL);
	}
}

/* udp send type7 data to server */
void
udpsend(int sockusfd, struct type_content3 t_content)
{
	int len, sendlen;
	sendlen = 8 + t_content.length;

	len = sendto(sockusfd, &t_content, sendlen, 0, (struct sockaddr *)&userveraddr, sizeof(userveraddr));
	printf("udp send-len:%d, type:%d, length:%d,content:%s", len, t_content.type, t_content.length, t_content.buff);
}

/* ---Type7---*/
void
equipment_state_info(void)
{
	char NETBAR_WACODE7[14];			/*场所代码*/
	char COLLECTION_EQUIPMENT_ID7[21];		/*设备代码*/
	char STATUS_CODE7[2];				/*01 在线:99 其他*/

	struct timeval s_time7;
	char buf[256], *pbuf, *ppbuf;
	memset(buf, 0, sizeof(buf));
	char buf7[40];
	memset(buf7, 0, sizeof(buf7));

	FILE *fp = fopen("/etc/config/statictype", "r");
	if (fp == NULL) {
		printf("Open type7 failed\n");
	}

	while(fgets(buf, sizeof(buf), fp)) {
		pbuf = buf;
		if(NULL != strstr(buf, "NETBAR_WACODE7")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(NETBAR_WACODE7, ppbuf, 14);
		}
		if(NULL != strstr(buf, "COLLECTION_EQUIPMENT_ID7")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(COLLECTION_EQUIPMENT_ID7, ppbuf, 21);
		}
		if(NULL != strstr(buf, "STATUS_CODE7")) {
			strsep(&pbuf, "'");
			ppbuf = strsep(&pbuf, "'");
			ppbuf = trim(ppbuf);
			strncpy(STATUS_CODE7, ppbuf, 2);
		}
		bzero(buf, sizeof(buf));
	}
	fclose(fp);

	gettimeofday(&s_time7, NULL);
	
	sprintf(buf7, "%s\t%s\t%s\r\n", NETBAR_WACODE7, COLLECTION_EQUIPMENT_ID7, STATUS_CODE7);

	struct type_content3 t_content7;
	memset(&t_content7, 0, sizeof(struct type_content3));
	t_content7.type = type_7;
	t_content7.length = strlen(buf7);
	strcpy(t_content7.buff, buf7);

	if (s_time7.tv_sec - t_time7.tv_sec >= 10*60) {
		udpsend(sockusfd, t_content7);
		gettimeofday(&t_time7, NULL);
	}
}

static void
receive_send_any(void)
{
	int len;
	struct sockaddr_in fromaddr;
	socklen_t peerlen;
	peerlen = sizeof(fromaddr);

	static char buffer[1024];
	memset(buffer, 0, sizeof(buffer));
	static char macstr[18];
	memset(macstr, 0, 18);

	fd_set rfds;
	struct timeval tv;
	int retval, maxfd = -1;

	FD_ZERO(&rfds);
	FD_SET(sockurfd, &rfds);
	maxfd = sockurfd;
	FD_SET(socktsfd, &rfds);
	if(socktsfd > maxfd)
		maxfd = socktsfd;

	tv.tv_sec = 10;
	tv.tv_usec = 0;

	retval = select(maxfd + 1, &rfds, NULL, NULL, &tv);
	if (retval == -1)
	{
		printf("exit and error!");
		return;
	}
	else if (retval == 0)
	{
		printf("\nOuttime,udp-server no data receive from horst;only send 3-6 to tcp-server,continue to wait...\n");

#if 0
		struct type_content2 t_content0;
		memset(&t_content0, 0, sizeof(struct type_content2));
		bzero(t_content0.buff, sizeof(t_content0.buff));
		t_content0.type = type_0;
		t_content0.length = strlen(test0);
		strcpy(t_content0.buff, test0);

		len = send(socktsfd, &t_content0, sizeof(struct type_content2), 0);
		if (len < 0)
		{
			printf("Connect keeping heartbeat send failed!\n");
			return;
			//break;
		}
		else
		{
			printf("Connect keeping,send heartbeat to tcp-servre len:%d,type:%d,length:%d,content:%s", len, t_content0.type, t_content0.length, t_content0.buff);
		}
		//continue;
#endif

	}
	else if (retval < 0) /* error */
		printf("select() error\n");

	if (FD_ISSET(socktsfd, &rfds))
	{
		bzero(buffer, sizeof(buffer));
		len = recv(socktsfd, buffer, 400, 0);
		if (len > 0)
		{
			printf("connect keeping,receive from tcp-server data-bytes: %s, %d\n\n", buffer, len);
		}
		else
		{
			if (len < 0)
				printf("Connect failed,from tcp-server received data failed! \n\n");
			else
				printf("Chat to terminate!\n");
			close(socktsfd);
			while(1) 
			{
				sleep(10);
				if ((socktsfd = tcp_socket_client()) != -1)
					break;
			}
		}
	}

	if (FD_ISSET(sockurfd, &rfds))
	{
		bzero(buffer, sizeof(buffer));

		if ((len = recvfrom(sockurfd, buffer, 1024, 0, (struct sockaddr*)&fromaddr, &peerlen)) > 0) {
			struct type_content1* t_content = (struct type_content1* )buffer;
			//printf("len-receive:%d, type:%d, length:%d, content:\n%s", len, t_content->type, t_content->length, t_content->buff);
			//printf("%s", t_content->buff);

			if (t_content->type == 1001) {
				struct timeval s_time1;
				gettimeofday(&s_time1, NULL);

				write_read_send1(t_content, s_time1);
			}
			else if (t_content->type == 1002) {
				struct timeval s_time2;
				gettimeofday(&s_time2, NULL);

				bzero(macstr, sizeof(macstr));
				strncpy(macstr, t_content->buff, 17);

				if (isemptylist(pList) == 0){
					pList=createlist(pList, macstr);
					write_read_send2(t_content, s_time2);
				}
				if ((isemptylist(pList) == 1 && listcontains(pList, macstr)==1)||s_time2.tv_sec - t_time2.tv_sec >= time2){
					insertlastlist(&pList, macstr);
					//printlist(pList);
					//sizelist(pList);
					write_read_send2(t_content, s_time2);
				}
			}
		}
	}
}

int
main()
{
	gettimeofday(&t_time1, NULL);
	gettimeofday(&t_time2, NULL);
	gettimeofday(&t_time3, NULL);
	gettimeofday(&t_time4, NULL);
	gettimeofday(&t_time5, NULL);
	gettimeofday(&t_time6, NULL);
	gettimeofday(&t_time7, NULL);

	/* host UDP receive */
	sockurfd = udp_socket_server();
	/* host UDP send */
	sockusfd = udp_socket_client();
	/* host tcp send */
	socktsfd = tcp_socket_client();

	if (CF1 != NULL){
		fclose(CF1);
		CF1 = NULL;
	}
	CF1 = fopen("test_terminal", "w");
	if (CF1 == NULL) {
		printf("Terminal open fail:%s\n", strerror(errno));
	}

	if (CF2 != NULL){
		fclose(CF2);
		CF2 = NULL;
	}
	CF2 = fopen("test_ap", "w");
	if (CF2 == NULL) {
		printf("Ap open fail:%s\n", strerror(errno));
	}

	initlist(&pList);

	while(1)
	{
		receive_send_any();

		mobile_terminal_info();
		terminal_info();
		site_info();
		security_vendor_info();

		//equipment_state_info();

	}
	close(sockusfd);
	close(sockurfd);
	close(socktsfd);
	fclose(CF1);
	fclose(CF2);
	return 0;

}

