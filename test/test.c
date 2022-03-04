#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include<pthread.h>

#include <fcntl.h>
#include <time.h> 
#include <errno.h>
#include <stdbool.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include<stdarg.h>






#define MAX_VALUE_LEN 256
struct config_info_st {
    char platform_name[MAX_VALUE_LEN];       
    char manager_address[MAX_VALUE_LEN];
    char software_address[MAX_VALUE_LEN];
    char audit_address[MAX_VALUE_LEN];
    int manage_center_port;
    int link;
    int active;
    int logon;
    int audit;
    unsigned int login_max_retries;
    unsigned int login_lock_time;
    unsigned int login_unlock_time;
    unsigned int login_reject_times;
    char nodeid[64];
	char userid[64];
    char version_info[64];
    char version_rel[MAX_VALUE_LEN];
    char build_time[MAX_VALUE_LEN];
    char build_os[64];
    char mac[32];
    char os_type[32];
	char ip[32];
	int install;
	int mode; /* ZhengJunpu added */
#ifdef TIP_PORTING
	int syslog_flag;
	char ipinfo[15];
	int portinfo;
	int valid_days;
	int switch_mode;// 1 close 0 open (same to server)
#endif
};

int func_fun(int n)
{
    int sum=0;
    int i;
    for(i=1; i<=n; i++)
    {
        sum+=i;
    }
    return sum;
 }

void test_fun(void)
{
    int i;
    int result = 0;
    for(i=1; i<=100; i++)
    {
        result += i;
    }

    printf("result[1-100] = %d\n", result);
    printf("result[1-250] = %d\n", func_fun(250));
    return ;

}
void test_popen();
void test_time(void);


/*==================================== 函数实现 ===================================================*/
/* struct 转换相关测试 start */
#define MAX_LOCATION_LENGTH 256
typedef void (*call_function)(void);
typedef void (*triger_event)(void);
struct httcsec_platform{

	void (*call_function)(void);
	void (*triger_event)(void);
};
#define HTTCSET_PLATFORM(platform) ((struct httcsec_platform * )platform)

struct httcsec_address{
	int address_type;
	int address_length;
	char address[0];
};

struct httcsec_ipcaddress{
	struct httcsec_address base;
	char location[MAX_LOCATION_LENGTH];
};

struct httcsec_ipcplatform{
    struct httcsec_platform base;
    struct httcsec_ipcaddress ipc_address;
};

struct httcsec_platform * test_struct_param(void)
{
	struct httcsec_ipcplatform *ipc_platform;
	
	ipc_platform = (struct httcsec_ipcplatform *)malloc(sizeof(struct httcsec_ipcplatform));
	if(!ipc_platform){
		printf("%s : malloc fail\n", __func__);
		return NULL;
	}

	memset(ipc_platform, 0, sizeof(struct httcsec_ipcplatform));
	strcpy(ipc_platform->ipc_address.location, "abbbbb");
	ipc_platform->ipc_address.base.address_length = MAX_LOCATION_LENGTH;
	ipc_platform->ipc_address.base.address_type = 1;
	
    printf("%s:location:%s,address_length:%d,address_type:%d.\n",__FUNCTION__,
                ipc_platform->ipc_address.location,
                ipc_platform->ipc_address.base.address_length,
                ipc_platform->ipc_address.base.address_type);
                
	HTTCSET_PLATFORM(ipc_platform)->call_function = test_time;
	HTTCSET_PLATFORM(ipc_platform)->triger_event = test_time;
	return (struct httcsec_platform *)ipc_platform;
	
}


void test_struct_param_get()
{
    struct httcsec_platform *plt;
	
    printf("%s.start .\n",__FUNCTION__);
    plt = test_struct_param();

    plt->call_function();
    plt->triger_event();

    printf("%s.end .\n",__FUNCTION__);
}

void test_time(void)
{
    struct tm *p = NULL;
    time_t timep;

    time(&timep);
    p = localtime(&timep);

    printf("local time:%d%02d%02d\n",1900+p->tm_year,1+p->tm_mon,p->tm_mday);

}

#define INT_SWAP(a,b) \
{                   \
    int tmp = a;    \
    a = b;          \
    b = tmp;        \
}

int test_define_swap(void)
{
    int var_a = 1;
    int var_b = 2;

    INT_SWAP(var_a, var_b);
    printf("var_a = %d, var_b = %d\n", var_a, var_b);   // var_a = 2, var_b = 1

    if (1)
        INT_SWAP(var_a, var_b);
    printf("var_a = %d, var_b = %d\n", var_a, var_b);   // var_a = 1, var_b = 2
}


#define offsetof1(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof1(type,member) );})


void define_function_test(int inde)
{

    printf("define_function_test:inde=%d\n",inde);
}


typedef struct {
    int mask;  
} policy_notify_t;

typedef struct{
    int active; //0:inactive 1:active
    int link;   //0:off      1:on
    int logon;  //0:logoff,  1:logon
    int audit;  //0:off,     1:on
} terminal_status_t;

static int notify_callback(int type, void *data)
{
    terminal_status_t *status = NULL;
    policy_notify_t *po = NULL;
    
    
    status = (terminal_status_t *)data;
    printf("notify_callback:active:%d, link:%d, logon:%d, audit:%d\n",status->active,status->link,status->logon,status->audit);
    
    po = (policy_notify_t *)data;
    printf("notify_callback:mask:%d\n",po->mask);
    
    return 0;
}

void test_notify_callback(void)
{
	policy_notify_t data;
    
    data.mask = 4;
    
    notify_callback(1,&data);
    
    return ;
}

void test_str_sub_str_len(void)
{
	unsigned int uistrlen = 0;
	unsigned char * pctmpd = "abcd";
	unsigned char * pctmps = "bbbbccdcd";
	
	uistrlen = pctmpd - pctmps;
    printf("main:uistrlen:%d\n",uistrlen);
	uistrlen = pctmps - pctmpd;
    printf("main:uistrlen:%d\n",uistrlen);
    
    return ;
}



#define AUDIT_CURVE_ROW    6
#define AUDIT_CURVE_MONTH  13
struct audit_curve_data{
    char audit_time_buff[64];
    long long start_time_sec;
    long long end_time_sec;
    int audit_curve_count[AUDIT_CURVE_ROW];
};
typedef struct audit_curve_data Saudit_curdata,*paudit_curdata;

#if 1

static void struct_cut(paudit_curdata audit_data)
{
    int i = 0;
    time_t nowtime = time(NULL);
    struct tm timefindst;
    struct tm *nowstmp = localtime(&nowtime);
    memcpy(&timefindst, nowstmp, sizeof(struct tm));
    char time_now_buff[64] = {'\0'};

    audit_data[0].end_time_sec = nowtime;
    printf("audit_data[0].end_time_sec = %lld\n", audit_data[0].end_time_sec);
    struct tm *end_time = localtime(&nowtime);

    sprintf(time_now_buff, "%04d-%02d\n", end_time->tm_year + 1900, end_time->tm_mon + 1);
    strncpy(audit_data[0].audit_time_buff, time_now_buff, sizeof(audit_data[0].audit_time_buff));
    printf("audit_data[0].audit_time_buff = %s\n", audit_data[0].audit_time_buff);

    for (i = 0; i < AUDIT_CURVE_MONTH - 1; i++) {
        if (0 == timefindst.tm_mon && 0 != i) {
            timefindst.tm_year = timefindst.tm_year - 1;
            timefindst.tm_mon = timefindst.tm_mon + 11;
        } else if (0 != i) {
            timefindst.tm_mon = timefindst.tm_mon - 1;
        } else {
            timefindst.tm_mday = 1;
            timefindst.tm_hour = 0;
            timefindst.tm_min = 0;
            timefindst.tm_sec = 0;
        }
        time_t time_month = mktime(&timefindst);
        audit_data[i].start_time_sec = time_month;
        printf("time_month = %lld\n", time_month);
        printf("audit_data[i].start_time_sec = %lld\n", audit_data[i].start_time_sec);
        
        struct tm *month_now = localtime(&time_month);
        memset(time_now_buff, 0, sizeof(time_now_buff));
        sprintf(time_now_buff, "%04d-%02d\n", month_now->tm_year + 1900, month_now->tm_mon + 1);
        strncpy(audit_data[i].audit_time_buff, time_now_buff, sizeof(audit_data[i].audit_time_buff));
        printf("time_month_buff = %s\n", time_now_buff);
    }

    for (i = 1; i < AUDIT_CURVE_MONTH - 1; i++) {
        audit_data[i].end_time_sec = audit_data[i-1].start_time_sec;
        audit_data[i].audit_curve_count[0] = 234;
        audit_data[i].audit_curve_count[1] = 567;
        printf("audit_data[i].end_time_sec = %lld\n\n", audit_data[i].end_time_sec);
    }
}
/* struct结构体变量，通过malloc申请的动态地址可以用作调用函数的参数，用于取得的被调用参数计算后的值 */
int test_mallocaddr_struct_information(void)
{
    int i = 0;
    paudit_curdata audit_data = NULL;

    audit_data = (struct audit_curve_data *) malloc(AUDIT_CURVE_MONTH * sizeof(struct audit_curve_data));
    if (NULL == audit_data) {
        printf("malloc error.\n");
        return -1;
   }
   memset(audit_data, 0, AUDIT_CURVE_MONTH * sizeof(struct audit_curve_data));

   struct_cut(audit_data);

   for (i = 0; i < AUDIT_CURVE_MONTH - 1; i++) 
   {
        printf("test_struct_information:Index=%d,audit_curve_count[0]:%d,audit_curve_count[1]:%d,audit_curve_count[2]:%d\n",
                i,audit_data[i].audit_curve_count[0],audit_data[i].audit_curve_count[1],audit_data[i].audit_curve_count[2]);
        printf("test_struct_information:Index=%d,audit_time_buff:%s,start_time_sec:%lld,end_time_sec:%lld\n\n",
                i,audit_data[i].audit_time_buff,audit_data[i].start_time_sec,audit_data[i].end_time_sec);
    }

    return 0;
}
#endif


/* 
    函数说明：字符串有效性检查
        备注：A:厂商名称缩写; B:产品名称; C:版本号
    返回值说明： 0 -- 检查正常，-10 -- 入参异常
    只子串长度检测异常的返回值：-1 -- A长度异常，-2 -- B长度异常，-3 -- C长度异常，-4 -- A、B长度异常，-5 -- A、C长度异常，-6 -- B、C长度异常，-7 -- A、B、C长度异常
    只子串检测有中文的返回值： -100 -- A有中文，-200 -- B有中文，-300 -- C有中文，-400 -- A、B有中文，-500 -- A、C有中文，-600 -- B、C有中文，-700 -- A、B、C有中文
    字符串同时子串长度异常和检测到中文时的返回值 = 子串长度检测返回值 + 子串中文检测返回值
*/
int string_valid_check_test(const char* checkstring)
{
    int ret = 0;
    char err_msg[1024] = { 0 };
    char* stringtmp = NULL;
    char stringa[50] = { 0 };
    char stringb[50] = { 0 };
    char stringc[50] = { 0 };
    int stringlen = 0;
    int stringlena = 0;
    int stringlenb = 0;
    int stringlenc = 0;
    int stringlenflag = 0;
    int stringtypeflag = 0;
    int index = 0;
    int retlenval[10] = {0,-1,-2,-4,-3,-5,-6,-7};
    int rettypeval[10] = {0,-100,-200,-400,-300,-500,-600,-700};
    int strch_num = 0;
    
    if (NULL == checkstring){
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"%ld [%s:%d] ERRROR: input invalid arg. \" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
        system(err_msg);
        return  -10;
    }


    /* string handle */
    stringlen = strlen(checkstring);    
    for(index = 0;index < stringlen; index++)
    {
        if(!strcmp(&checkstring[index],"_"))
        {
            strch_num++;
        }
    }
    
    stringtmp = strchr(checkstring,'_');
    stringlena = stringlen - strlen(stringtmp);
    memcpy(stringa,checkstring,stringlena);

    stringtmp = strrchr(checkstring,'_');
    stringlenc = strlen(stringtmp) - 1;
    memcpy(stringc,stringtmp + 1,stringlenc);

    stringtmp = strchr(checkstring,'_');
    stringlenb = stringlen - stringlena - stringlenc -2;
    memcpy(stringb,stringtmp + 1,stringlenb);
    
    /* string len check and return ret set */
    if((stringlena <= 0) || (stringlena > 12))
    {
        stringlenflag = 1;
    }
    if((stringlenb <= 0) || (stringlenb > 12))
    {
        stringlenflag += 2;
    }
    if((stringlenc <= 0) || (stringlenc > 8))
    {
        stringlenflag += 4;
    }
    ret = retlenval[stringlenflag];
    
    /* string char type check */
    for(index = 0;index < stringlena;index++)
    {
        if((stringa[index] < 0) || (stringa[index] > 127))
        {
            stringtypeflag = 1;
            break;
        }
    }
    for(index = 0;index < stringlenb;index++)
    {
        if((stringb[index] < 0) || (stringb[index] > 127))
        {
            stringtypeflag += 2;
            break;
        }
    }
    for(index = 0;index < stringlenc;index++)
    {
        if((stringc[index] < 0) || (stringc[index] > 127))
        {
            stringtypeflag += 4;
            break;
        }
    }
    ret += rettypeval[stringtypeflag];
    
    printf("checkstring=%s: stringa=%s,stringb=%s,stringc=%s.\n",checkstring,stringa,stringb,stringc);
    printf("stringlen=%d: stringlena=%d,stringlenb=%d,stringlenc=%d.\n",stringlen,stringlena,stringlenb,stringlenc);
    printf("return ret=%d: stringlenflag=%d, retlenval[stringlenflag]=%d; stringtypeflag=%d, rettypeval[stringtypeflag]=%d.\n",
            ret,stringlenflag,retlenval[stringlenflag],stringtypeflag,rettypeval[stringtypeflag]);
    return ret;
}

void rand_test()
{
    int i = 0;
    int n = 5;
    
    srand((int)time(0));
    for( i = 0 ; i < 1 ; i++ ) {
        printf("rand_test:%d\n", rand() % 256);
    }

}

void math_test()
{
    int and1=7;
    int and2=1;
    int or1=7;
    int or2=1;
    int not=7;
    int xor1=7;
    int xor2=1;

    int andresult=and1&and2;
    int orresult=or1&or2;
    int notresutl=~not;
    int xorresult=xor1^xor2;

    printf("and1&and2  andresult=%d\n",andresult);
    printf("or1&or2    orresult=%d\n",orresult);
    printf(" ~not      notresutl=%d\n",notresutl);
    printf("xor1^xor2  xorresult=%d\n",xorresult);


    int andresult2=andresult<<2;
    int notresutl2=notresutl>>2;


    printf("andresult<<2 andresult2=%d\n",andresult2);
    printf("notresutl>>2 notresutl2=%d\n",notresutl2);

    return ;
}


//将小写字母转化为大写，其余不处理
static void upper_test(char* buf)
{
    if(!buf)
        return;
    int off = 0;
    char x = 0x00;
    while( (x = *(buf + off)) != '\0')
    {
        if( x >= 0x61 && x <= 0x7A )
            *(buf + off) = x - 0x20;
        ++ off;
    }

}

static void getmac_test(char* mac, int length)
{
    if (!mac || length < 13)
    {
        printf("%s %s[ERROR]input parameters wrong!In buf=[%s], len=[%d]\n",__FILE__,__FUNCTION__, mac, length);
        return ;
    }
    int sockfd = 0;
    int if_len = 0;
    int MAXINTERFACES = 16;
    struct ifreq buf[MAXINTERFACES];
    struct ifconf ifc;
    int retry_times = 3;
    memset(mac, 0x00, length);
    const char* default_mac = "0F1E2D3C4B5A";

Retry:
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    //sockfd = -1;
    if ( sockfd < 0)
    {
        printf("%s %s[DEBUG]new socket errors [%d]times!\n",__FILE__,__FUNCTION__, 4-retry_times);
        sleep(1);
        if ( --retry_times <= 0)
        {
            printf("%s %s[DEBUG]new socket errors! Use Default!\n",__FILE__,__FUNCTION__);
            goto Default;
        }
        else
        {
            goto Retry;
        }
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = (caddr_t)buf;

    if (ioctl(sockfd, SIOCGIFCONF, (char *)&ifc) == -1)
    {
        perror("SIOCGIFCONF ioctl");
        if(retry_times < 0)
        {
            goto Default;
        }
    }

    if_len = ifc.ifc_len / sizeof(struct ifreq);
    //if_len = 0;

    while (if_len-- > 0)
    {
        if (!(ioctl(sockfd, SIOCGIFHWADDR, (char *)&buf[if_len])))
        {
            sprintf(mac, "%02x%02x%02x%02x%02x%02x",
                    (unsigned char) buf[if_len].ifr_hwaddr.sa_data[0],
                    (unsigned char) buf[if_len].ifr_hwaddr.sa_data[1],
                    (unsigned char) buf[if_len].ifr_hwaddr.sa_data[2],
                    (unsigned char) buf[if_len].ifr_hwaddr.sa_data[3],
                    (unsigned char) buf[if_len].ifr_hwaddr.sa_data[4],
                    (unsigned char) buf[if_len].ifr_hwaddr.sa_data[5]
                   );
            break;
        }
    }
    if(if_len <= 0)
    {
        goto Default;
    }
    upper_test(mac);
    if(sockfd)
    {
        close(sockfd);
    }
    return ;

Default:
    if(sockfd)
    {
        close(sockfd);
    }
    strcpy(mac, default_mac);
    return;

}

int getOsDiskId_uid_t(const char* pOsDiskSymbol, char* pOsDiskId)
{
    int retval = 0;
    FILE* pFile = NULL;
    char line[1024] = {'\0'};
    char sys_cmd[1024] = {'\0'};
    memset(sys_cmd, 0, sizeof(sys_cmd));
    snprintf(sys_cmd, sizeof(sys_cmd), "blkid -s UUID %s", pOsDiskSymbol);
    pFile = popen(sys_cmd, "r");
    if (NULL == pFile) {
        retval -3;
    }else{
        while (!feof(pFile)) {
            memset(line, 0, sizeof(line));
            if (NULL == fgets(line, sizeof(line) - 1, pFile)){
                retval -4;
                break;
            }
            printf("get line data:%s,%s,%d", line, __func__, __LINE__);
            char* ptrDiskId = strstr(line, "UUID=");
            if(NULL != ptrDiskId){
                int len = strlen(ptrDiskId);
                char* ptrDiskID = strstr(ptrDiskId, "\n");
                if(NULL != ptrDiskID){
                    strncpy(pOsDiskId, ptrDiskId+6, len-8);
                }else{
                    strncpy(pOsDiskId, ptrDiskId+6, len-7);
                }
                printf("get disk UUID:%s,%s,%d", ptrDiskId, __func__, __LINE__);
            }
        }
    }
    if(NULL != pFile)
    {
        pclose(pFile);
        pFile = NULL;
    }
    return retval;
}

int getOsDiskSymbol_uid_test(char* pOsDiskId)
{
    int retval = 0;
    FILE* pFile = NULL;
    char execmd[1024] = {'\0'};
    char linedata[1024] = {'\0'};
    char osDiskSymbol[1024] = {'\0'};
    memset(execmd, 0, sizeof(execmd));
    snprintf(execmd, sizeof(execmd), "fdisk -l | grep dev | grep \"*\" | gawk '{print $1}'");
    pFile = popen(execmd, "r");
    if (NULL == pFile) {
        retval -1;
    }else{
        while (!feof(pFile)) {
            memset(linedata, 0, sizeof(linedata));
            if (NULL == fgets(linedata, sizeof(linedata) - 1, pFile)){
                retval -2;
                break;
            }
            printf("get line data:%s,%s,%d", linedata, __func__, __LINE__);
            if (0 == strncmp(linedata, "/dev/", 5)) {
                memset(osDiskSymbol, 0, sizeof(osDiskSymbol));
                strncpy(osDiskSymbol, linedata, sizeof(osDiskSymbol));
                int results = getOsDiskId_uid_t(osDiskSymbol, pOsDiskId);
                if(results < 0){
                    retval = results;
                }
                break;
            }
        }
    }
    if(NULL != pFile)
    {
        pclose(pFile);
        pFile = NULL;
    }
    return retval;
}

//从/etc/.systeminfo取 SOCID
//且SOC ID长度严格限制在16字节, 由宏LICENSE_CHK_SOC_ID_LENGTH表示
static int getsoc_test(char* socID, int length)
{
    if(!socID || length < 17)
    {
        printf("%s %s[ERROR]input parameters wrong!In buf=[%s], len=[%d]\n",__FILE__,__FUNCTION__, socID, length);
        return -1;
    }
    //soc卡两种头
    char* mark1 = "\'ID=\'";
    char* mark2 = "\'标识码（产品唯一标识）\'";
    char* mark2_kind1 = "标识码（产品唯一标识）=";
    char* mark2_kind2 = "标识码（产品唯一标识）：";
    int len_mark1 = 0;
    int len_mark2_kind1 = 0;
    int len_mark2_kind2 = 0;
    char cmd1[256];
    char cmd2[256];
    char line[1024];
    FILE* fp;

    int tmp_no = 0;
    int left = 0;
    //const char* default_soc_ID = "DEFALUT SOC ID";

    len_mark1 = strlen("ID=");//此时不需要单引号
    len_mark2_kind1 = strlen(mark2_kind1);
    len_mark2_kind2 = strlen(mark2_kind2);
    memset(socID, 0x00, length);
    memset(cmd1, 0x00, sizeof(cmd1));
    memset(cmd2, 0x00, sizeof(cmd2));
    memset(line, 0x00, sizeof(line));

    sprintf(cmd1,  "cat /etc/.systeminfo|grep %s", mark1);
    sprintf(cmd2,  "cat /etc/.systeminfo|grep %s", mark2);

    //一种没取到，取另一种
    fp = popen(cmd1, "r");
    if(fp)
    {
        fgets(line, 1024, fp);
        if(line[0] != '\0')
        {
            tmp_no = strlen(line) - 1;//去掉最后\n
            line[tmp_no] = '\0';
            left = tmp_no - len_mark1;
            left = left < 16?left:16;

            memcpy(socID, line+ len_mark1, left);

            pclose(fp);
            return 0;

        }
    }
    memset(line, 0x00, sizeof(line));
    if(fp)
    {
        pclose(fp);
    }
    fp = 0;

    fp = popen(cmd2, "r");
    if(fp)
    {
        fgets(line, 1024, fp);
        if(line[0] == '\0')
        {
            printf("%s %d[DEBUG] SOC ID can not be obtained!\n",__FILE__,__LINE__ );
            goto Default;
        }
        else
        {
            tmp_no = strlen(line) - 1;//去掉最后\n
            line[tmp_no] = '\0';

            //长度出错时
            if( tmp_no <= len_mark2_kind1 || tmp_no <= len_mark2_kind2)
            {
                printf("%s %d[DEBUG] NO SOCID!\n",__FILE__,__LINE__ );
                goto Default;
            }

            if ( memcmp(line, mark2_kind1, len_mark2_kind1) == 0)//kind1
            {
                left = tmp_no - len_mark2_kind1;
                left = left < 16?left:16;
                strncpy(socID, line+ len_mark2_kind1, left );
            }
            else if ( memcmp(line, mark2_kind2, len_mark2_kind2) == 0)//kind2
            {
                left = tmp_no - len_mark2_kind2;
                left = left < 16?left:16;
                strncpy(socID, line+ len_mark2_kind2, left);
            }
            else
            {
                printf("%s %d[DEBUG] SOC ID HEAD errors! Please update codes!\n",__FILE__,__LINE__ );
                goto Default;
            }
        }
    }
    else
    {
        goto Default;
    }

    if(fp)
    {
        pclose(fp);
    }
    return 0;

Default:
    //strcpy(socID, default_soc_ID);
    if(fp)
    {
        pclose(fp);
    }
    return -1;
}

static void erase_char_test(char* buf, char x);

//取CPU ID，无法取到时 返回默认
static void getcpu_test(char* cpu_id, int length)
{
    if(!cpu_id || length < 17)
    {
        printf("%s %s[ERROR]input parameters wrong!In buf=[%s], len=[%d]\n",__FILE__,__FUNCTION__, cpu_id, length);
        return;
    }

    const char* default_cpu_ID="F9060000FFFB8B0F";
    char line[1024];
    FILE* fp;
    memset(line, 0x00, sizeof(line));

    //char* test_cmd = "cat abc.txt";
    char* test_cmd = "dmidecode -t processor |wc -l";
    char* cmd= "dmidecode -t processor |grep ID|sort -u|awk -F': ' '{print $2}'";

    fp = popen(test_cmd, "r");
    if(fp)
    {
        fgets( line, 1024, fp);
        //行数小于5 或空 说明无法取得
        if(line[0] == '\0')
        {
        printf("%s %d[DEBUG]CPU id can not be obtained! Use Default!\n",__FILE__,__LINE__, cpu_id, length);
            goto Default;
        }
        else
        {
            line[strlen(line)-1] = '\0';
            if ( atoi(line) < 5)
            {
                printf("%s %d[DEBUG]CPU id can not be obtained! Use Default!\n",__FILE__,__LINE__, cpu_id, length);
                goto Default;
            }
        }
    }
    else
    {
        goto Default;
    }
    if(fp)
    {
        pclose(fp);
    }
    memset(line, 0x00, sizeof(line));
    fp = 0;

    fp = popen(cmd, "r");
    if(fp)
    {
        fgets( line, 1024, fp);
        line[strlen(line)-1] = '\0';
        erase_char_test(line, ' ');
        memcpy(cpu_id, line, strlen(line));
        upper_test(cpu_id);
    }
    else
    {
        goto Default;
    }
    
    if(fp)
    {
        pclose(fp);
    }
    return;

Default:
    strcpy(cpu_id, default_cpu_ID);
    if(fp)
    {
        pclose(fp);
    }
    return ;
}


//读n个字符
static int readn_test(char* path,  char* storeline, int length)
{
    int fd = 0;
    int left = length, read_len = 0, already = 0;
    fd = open(path, O_RDONLY);
    if( fd == -1)
    {
        return -1;
    }
    //本地使用，读长度<=ACTIVE_ACT_CODE_LEN
    while(left > 0 && already <= 16)
    {
        read_len = read(fd, storeline + already, left);
        /*
        if(read_len == 0)//finish
        {
            break;
        }
        else if(read_len == -1)
        */
        if(read_len == -1)
        {
            if(errno == EINTR)
                continue;
            else
            {
                printf("error=[%d], [%s]", errno, strerror(errno));
                break;
            }
        }
        left = left - read_len;
        already += read_len;
        printf("readn_test 333:read_len=%d,left=%d,already=%d\n",read_len,left,already);
    }
    close(fd);
    return length - left;
}

//写n个字符
static int writen_test(char* path,  char* storeline, int length)
{
    int fd = 0;
    int left = length, write_len = 0, already = 0;
    
    fd = open(path, O_RDWR|O_CREAT,
         (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH));
    if( fd == -1)
    {
        return -1;
    }
    printf("writen_test:fd=%d,storeline=%s,length(left)=%d\n",fd,storeline,length);
    //本地使用，读长度<=16
    while(left > 0 && already <= 16)
    {
        printf("writen_test 111:left=%d,already=%d\n",left,already);
        write_len = write(fd, storeline + already, left);
        printf("writen_test 222:write_len=%d\n",write_len);
        if(write_len == 0)//finish
        {
            break;
        }
        else if(write_len == -1)
        {
            if(errno == EINTR)
                continue;
            else
            {
                printf("error=[%d], [%s]", errno, strerror(errno));
                break;
            }
        }
        left = left - write_len;
        already += write_len;
        printf("writen_test 333:left=%d,already=%d\n",left,already);
    }
    close(fd);
    printf("writen_test 444:length=%d,left=%d\n",length,left);
    return length - left;
}


//buf 必须以'\0'结束，x为要删除的字符
static void erase_char_test(char* buf, char x)
{
    if( !buf)
        return;
    char* p_pos = buf;//cursor
    char* p_ori = buf;//storage
    
    //printf("erase_char_test 111: buf=%s,*p_pos=%s,*p_ori=%s,x=%c\n",buf,p_pos,p_ori,x);

    while( *p_pos!= '\0')
    {
        //printf("erase_char_test 222: *p_pos=%s,x=%c\n",p_pos,x);
        if( *p_pos == x)
        {
            ++p_pos;
        }
        else
        {
            //printf("erase_char_test 333: *p_pos=%s,p_ori=%s\n",p_pos,p_ori);
            //*p_ori = *p_pos;
            //++p_ori;
            //++p_pos;
            
            *p_ori++ = *p_pos++;
        }
        //printf("erase_char_test 444: *p_pos=%s,p_ori=%s\n\n",p_pos,p_ori);

    }
    //printf("erase_char_test 555: buf=%s,*p_pos=%s,*p_ori=%s\n",buf,p_pos,p_ori);
    *p_ori = '\0';
    
    //printf("erase_char_test 666: buf=%s,*p_pos=%s,*p_ori=%s\n",buf,p_pos,p_ori);
    return;
}

int del_space(char *src)
{
    char *pTmp = src;
    unsigned int iSpace = 0;
 
    printf("del_space :iSpace=%d,pTmp=%s,src=%s\n",iSpace,pTmp,src);

    while (*src != '\0') 
    {
        if (*src != ' ') 
        {
            printf("del_space 33:iSpace=%d,pTmp=%s,src=%s\n",iSpace,pTmp,src);
            *pTmp++ = *src++;
            printf("del_space 44:iSpace=%d,pTmp=%s,src=%s\n\n",iSpace,pTmp,src);
        } 
        else 
        {
            iSpace++;
            src++;
        }
 
        //src++;
    }
 
    *pTmp = '\0';
 
    printf("del_space 55:iSpace=%d,pTmp=%s,src=%s\n",iSpace,pTmp,src);
    src--;
    printf("del_space 55:iSpace=%d,pTmp=%s,src=%s\n",iSpace,pTmp,src);
    src--;
    printf("del_space 55:iSpace=%d,pTmp=%s,src=%s\n",iSpace,pTmp,src);
    src -= 3;
    printf("del_space 55:iSpace=%d,pTmp=%s,src[src -= 3]【】=%s\n",iSpace,pTmp,src);
    return iSpace;
}

char *cpystr_test(char* dst, const char* src)
{
	char* tmp=dst;
	while(*src!='\0')
		*tmp++=*src++;
	*tmp='\0';
	
	return dst;
}
#if 0
/***************************
 * name: gen_activ_code
 * param:
 * machine_code        输入机器码
 * machine_code_length 机器码buffer长度 16
 * date                输入激活码有效期，格式：YYYYMMDD
 * date_length         date buffer长度 至少为8
 * key_path            key路径
 * key_path_length     key_path buffer 长度
 * act_code            激活码buffer指针，返回
 * act_code_length     激活码buffer总长度 返回
 * notice:-
 * return:
 *       返回值;
 ***************************/
int gen_activ_code(unsigned char* soc_code, int soc_code_length,unsigned char* uid_code, int uid_code_length,char type,
        char* date, int date_length,
        char* key_path, int key_path_length,
        unsigned char** act_code, int* act_code_length)
{
    if( !machine_code || !date || !key_path ||!act_code )
    {
        return ACT_ERROR_IPUT_PARAM_ERROR;
    }
    if ( machine_code_length < ACTIVE_MACHINE_CODE_LEN ||
        date_length < ACTIVE_DATE_LEN )
    {
        return ACT_ERROR_IPUT_PARAM_ERROR;
    }
    unsigned char storage[17];
    unsigned char local_mach_code[machine_code_length + 1];
    char rand_buf[5];
    unsigned char date_convert[5];
    int i = 0;
    int iRet = 0;
    unsigned char * p_act_hex = NULL;
    int act_hex = 0;


    memset(storage, 0x00, sizeof(storage));
    memset(rand_buf, 0x00, sizeof(rand_buf));
    memset(date_convert, 0x00, sizeof(date_convert));
    memset(local_mach_code, 0x00, sizeof(local_mach_code));
    memcpy(local_mach_code, machine_code, machine_code_length);
    
    sm3andhash(local_mach_code, storage);

    i = 0;
    //8 bytes => 4 bytes
    while(i < 4)
    {
        date_convert[i] = (get_char(date[i*2])<<4) + get_char(date[i*2 + 1]);
        //printf("storage is [%02X]\n", date_convert[i]);
        ++i;
    }
    memcpy(storage + 8, date_convert, ACTIVE_DATE_LEN/2);

    srand((int)time(0));
    storage[12] = (unsigned char)random(256);
 //   storage[13] = (unsigned char)random(256);
    storage[13] = (unsigned char)type;
    //storage[14] = (unsigned char)random(256);

    /* befor sm4
    printf("gen ", storage[i]);
    i =0;
    while( i < strlen(storage))
    {
        printf("%X ", storage[i]);
        ++i;
    }
    printf("\n");
    */

    iRet = my_encrypt(key_path, key_path_length,
            storage, strlen(storage), &p_act_hex, &act_hex);
    if( iRet != 0)
    {
        if(p_act_hex)
        {
            free(p_act_hex);
            p_act_hex = NULL;
        }
        return iRet;
    }
    //hex => char
    i = 0;
    *act_code_length = 2*act_hex;
    *act_code = (unsigned char*)malloc( *act_code_length + 1);
    memset(*act_code, 0x00, *act_code_length + 1);
    while( i < act_hex)
    {
        sprintf(*act_code + i*2, "%02X", p_act_hex[i]);
        ++i;
    }
    if(p_act_hex)
    {
        free(p_act_hex);
        p_act_hex = NULL;
    }

    return 0;
}
#endif
#define KEY_BUILD_VER          "BUILD_VER:"
#define KEY_BUILD_REL	     "BUILD_REL:"
#define KEY_BUILD_TIME	      "BUILD_TIME:"
#define KEY_BUILD_OS           "BUILD_OS:"
#define TIP_VERSION_FILE "/opt/softmanager/tipterminal/var/version.txt"

static int read_ver(struct config_info_st *cfg)
{
	FILE *fp = NULL;
	char buf[256], value[256];
	char hostname[256] = {0};
	char socid[64] = {0};
	int ret = 0;

    fp = fopen(TIP_VERSION_FILE, "r");
    if (fp == NULL) {
        printf("fopen err\n");
    }
    while (!feof(fp)) {
        if (fgets(buf, sizeof(buf), fp)) {
	    sscanf(buf, KEY_BUILD_VER" %s", cfg->version_info);
	    sscanf(buf, KEY_BUILD_REL" %s", cfg->version_rel);
	    sscanf(buf, KEY_BUILD_TIME" %s", cfg->build_time);

	    sscanf(buf, KEY_BUILD_OS" %s", cfg->build_os);
        printf("\nread_ver: cfg->version_info=%s,cfg->version_rel=%s,cfg->build_time=%s,cfg->build_os=%s \n",cfg->version_info,cfg->version_rel,cfg->build_time,cfg->build_os);
        }
    }
	printf("\nread_ver: cfg->version_info=%s,cfg->version_rel=%s,cfg->build_time=%s,cfg->build_os=%s \n",cfg->version_info,cfg->version_rel,cfg->build_time,cfg->build_os);

    return ret;
}


#if 1
#define MAX_PROCESS_NUM	512
#define MAX_PORT_NUM	256

#define LONG_MAX	((long)pow(2, 63))
#define LINE_MAX	4096
#define PROGNAME_WIDTH	32
#define PRG_HASH_SIZE	32

#define PATH_PROC	   "/proc"
#define PATH_FD_SUFF	"fd"
#define PATH_FD_SUFFl       strlen(PATH_FD_SUFF)
#define PATH_PROC_X_FD      PATH_PROC "/%s/" PATH_FD_SUFF
#define PATH_CMDLINE	"status"
#define PATH_CMDLINEl       strlen(PATH_CMDLINE)

#define PRG_SOCKET_PFX    "socket:["
#define PRG_SOCKET_PFXl (strlen(PRG_SOCKET_PFX))
#define PRG_SOCKET_PFX2   "[0000]:"
#define PRG_SOCKET_PFX2l  (strlen(PRG_SOCKET_PFX2))

#define PRG_HASHIT(x) ((x) % PRG_HASH_SIZE)
#define USR_NAME_LEN (32)

#define TIME_WAIT   (1000 * 1000)
#define TCP_LISTEN	10
#define TCP_FILE 	"/proc/net/tcp"
#define UDP_FILE 	"/proc/net/udp"



struct prg_node {
	struct prg_node *next;
	unsigned long inode;
	char name[PROGNAME_WIDTH];
};
//网络端口
struct sys_port {
	int port;
	unsigned char proto[4];
	unsigned char program[32];
};
//struct dirent {
//    unsigned char d_name[64];
//};


//#define DIR 1

#define PRG_HASHIT(x) ((x) % PRG_HASH_SIZE)

struct prg_node *prg_hash[PRG_HASH_SIZE];

void prg_cache_add(unsigned long inode, char *name)
{
    unsigned hi = PRG_HASHIT(inode);
    struct prg_node **pnp, *pn;

    for (pnp = prg_hash + hi; (pn = *pnp); pnp = &pn->next) {
        if (pn->inode == inode) {
            return;
        }
    }

    if ( !(*pnp = malloc(sizeof(**pnp))) )
        return;

    pn = *pnp;
    pn->next = NULL;
    pn->inode = inode;

    if (strlen(name) > sizeof(pn->name) - 1) {
        name[sizeof(pn->name) - 1] = '\0';
    }

    strcpy(pn->name, name);
}

const char *prg_cache_get(unsigned long inode)
{
    unsigned hi = PRG_HASHIT(inode);
    struct prg_node *pn;

    for (pn = prg_hash[hi]; pn; pn = pn->next)
        if (pn->inode == inode)
            return(pn->name);

    return("-");
}

void prg_cache_clear(void)
{
	struct prg_node **pnp,*pn;

	for (pnp=prg_hash;pnp<prg_hash+PRG_HASH_SIZE;pnp++) {
		while ((pn=*pnp)) {
			*pnp=pn->next;
			free(pn);
		}
	}
}
static int extract_type_1_socket_inode(const char lname[], unsigned long *inode_p)
{
    /* If lname is of the form "socket:[12345]", extract the "12345" as *inode_p.
       Otherwise, return -1 as *inode_p.
    */

    if (strlen(lname) < PRG_SOCKET_PFXl + 3) {
        return(-1);
    }

    if (memcmp(lname, PRG_SOCKET_PFX, PRG_SOCKET_PFXl)) {
        return(-1);
    }

    if (lname[strlen(lname) - 1] != ']') {
        return(-1);
    }

    char inode_str[strlen(lname + 1)];  /* e.g. "12345" */
    const int inode_str_len = strlen(lname) - PRG_SOCKET_PFXl - 1;
    char *serr;

    strncpy(inode_str, lname + PRG_SOCKET_PFXl, inode_str_len);
    inode_str[inode_str_len] = '\0';
    *inode_p = strtol(inode_str, &serr, 0);

    if (!serr || *serr || *inode_p < 0 || *inode_p >= LONG_MAX)
        return(-1);

    return(0);
}


static int extract_type_2_socket_inode(const char lname[], unsigned long *inode_p)
{
    /* If lname is of the form "[0000]:12345", extract the "12345" as *inode_p.
       Otherwise, return -1 as *inode_p.
    */

    if (strlen(lname) < PRG_SOCKET_PFX2l + 1) {
        return(-1);
    }

    if (memcmp(lname, PRG_SOCKET_PFX2, PRG_SOCKET_PFX2l)) {
        return(-1);
    }

    char *serr;

    *inode_p = strtol(lname + PRG_SOCKET_PFX2l, &serr, 0);
    if (!serr || *serr || *inode_p < 0 || *inode_p >= LONG_MAX)
        return(-1);

    return(0);
}

void prg_cache_load(void)
{
    char line[LINE_MAX], eacces = 0;
    int i, procfdlen, lnamelen, found = 0;
    char lname[30], cmdlbuf[32] = { 0 }, finbuf[PROGNAME_WIDTH] = {'-', '\0'};
    unsigned long inode;
    const char *cs, *cmdlp;
    int *dirproc = NULL;
    int *dirfd = NULL;
    struct dirent *direproc, *direfd;
    FILE *fp = NULL;

    if (!(dirproc = opendir(PATH_PROC)))
        return;

    while (errno = 0, direproc = readdir(dirproc)) {
        for (cs = direproc->d_name; *cs; cs++)
            if (!isdigit(*cs))
                break;

        if (*cs)
            continue;

        procfdlen = snprintf(line, sizeof(line), PATH_PROC_X_FD, direproc->d_name);
        if ( (procfdlen <= 0) || (procfdlen >= sizeof(line) - 5) )
            continue;

        errno = 0;
        dirfd = opendir(line);
        if (!dirfd) {
            if (errno == EACCES)
                eacces = 1;
            continue;
        }

        line[procfdlen] = '/';
        cmdlp = NULL;
        while ((direfd = readdir(dirfd))) {
            /* Skip . and .. */
            if (!isdigit(direfd->d_name[0]))
                continue;

            if (procfdlen + 1 + strlen(direfd->d_name) + 1 > sizeof(line))
                continue;

            memcpy(line + procfdlen - PATH_FD_SUFFl, PATH_FD_SUFF "/", PATH_FD_SUFFl + 1);
            strcpy(line + procfdlen + 1, direfd->d_name);
            lnamelen = readlink(line, lname, sizeof(lname) - 1);
            lname[lnamelen] = '\0';  /* make it a null-terminated string */

            if (extract_type_1_socket_inode(lname, &inode) < 0)
                if (extract_type_2_socket_inode(lname, &inode) < 0)
                    continue;

            if (!cmdlp) {
                if (procfdlen - PATH_FD_SUFFl + PATH_CMDLINEl >= sizeof(line) - 5)
                    continue;

                strcpy(line + procfdlen - PATH_FD_SUFFl, PATH_CMDLINE);
                fp = fopen(line, "r");
                if (fp == NULL)
                    continue;
                memset(cmdlbuf, 0, sizeof(cmdlbuf));
                if (!fgets(cmdlbuf, sizeof(cmdlbuf)-1, fp)) {
                    fclose(fp);
                    continue;
                }

                if (fclose(fp))
                    continue;

                cmdlbuf[strlen(cmdlbuf)-1] = '\0';
                if ((cmdlp = strchr(cmdlbuf, ':')))
                    cmdlp += 2;
                else
                    cmdlp = "-";
            }

            snprintf(finbuf, sizeof(finbuf), "%s", cmdlp);
            printf("prg_cache_load:finbuf=%s\n",finbuf);
            prg_cache_add(inode, finbuf);
        }
        closedir(dirfd);
        dirfd = NULL;
    }

    if (dirproc)
        closedir(dirproc);
    if (dirfd)
        closedir(dirfd);
}

int get_tcp_port_test(void)
{
    char buffer[1024] = { 0 };
    unsigned int local_port, state, i = 0;
    unsigned long inode;

    FILE *fp = fopen(TCP_FILE, "r");
    if (fp == NULL) {
        return -1;
    }

    while (!feof(fp)) {
        memset(buffer, 0, sizeof(buffer));
        if(fgets(buffer, sizeof(buffer) - 1, fp) == NULL)
            break;
        printf("get_tcp_port_test 11:len=%d,buffer[0]=%d, buffer=%s\n",strlen(buffer),buffer[0],buffer);

        
        sscanf(buffer, "%*d: %*X:%X %*X:%*X %X %*X:%*X %*d:%*X %*X %*d %*d %ld\n", &local_port, &state, &inode);
        printf("get_tcp_port_test 22: local_port=%x,state=%x,inode=%d\n",local_port,state,inode);
    }

    return 0;
}

int get_tcp_port(struct sys_port *p, int *loc)
{
    char buffer[1024] = { 0 };
    unsigned int local_port, state, i = 0;
    unsigned long inode;

    FILE *fp = fopen(TCP_FILE, "r");
    if (fp == NULL) {
        return -1;
    }

    /* ignore the first line */
    fgets(buffer, sizeof(buffer) - 1, fp);

    while (!feof(fp)) {
        memset(buffer, 0, sizeof(buffer));
        //if(fgets(buffer, sizeof(buffer) - 1, fp) == NULL)
       //     break;
        //printf("get_tcp_port 11:len=%d,buffer[0]=%d, buffer=%s\n",strlen(buffer),buffer[0],buffer);
        fgets(buffer, sizeof(buffer) - 1, fp);
        printf("get_tcp_port 11:len=%d, buffer=%s\n",strlen(buffer),buffer);
        if (buffer[0] == '\0')
            break;
        sscanf(buffer, "%*d: %*X:%X %*X:%*X %X %*X:%*X %*d:%*X %*X %*d %*d %ld\n", &local_port, &state, &inode);
        printf("get_tcp_port 22: local_port=%x,state=%x,inode=%d\n",local_port,state,inode);

#if 1
        if (state == TCP_LISTEN) {
            (p + i)->port = local_port;
            //strcpy((p + i)->program, prg_cache_get(inode));
            strcpy((p + i)->program, "httctcp");
            strcpy((p + i)->proto, "TCP");

            i++;
        }
#endif
    }
    (p + i)->port = -1;
    *loc = i;
    fclose(fp);

    return 0;
}

int get_udp_port(struct sys_port *p, int loc)
{
    char buffer[1024] = { 0 };
    unsigned int local_port, state, i = loc;
    unsigned long inode;

    FILE *fp = fopen(UDP_FILE, "r");
    if (fp == NULL) {
        return -1;
    }

    /* ignore the first line */
    fgets(buffer, sizeof(buffer) - 1, fp);

    while (!feof(fp)) {
        memset(buffer, 0, sizeof(buffer));
        fgets(buffer, sizeof(buffer) - 1, fp);
        if (buffer[0] == '\0')
            break;
        sscanf(buffer, "%*d: %*X:%X %*X:%*X %X %*X:%*X %*d:%*X %*X %*d %*d %ld\n", &local_port, &state, &inode);

        (p + i)->port = local_port;
        //strcpy((p + i)->program, prg_cache_get(inode));
        strcpy((p + i)->program, "httcudp");
        strcpy((p + i)->proto, "UDP");

        i++;
    }
    printf("get_udp_port : i=%d\n",i);
    (p + i)->port = -1;
    fclose(fp);

    return 0;
}

int do_sys_port_get(struct sys_port *p)
{
    int loc = 0, ret = 0;

    //prg_cache_load();
    printf("do_sys_port_get：debug\n");

    ret = get_tcp_port(p, &loc);
    printf("do_sys_port_get:tcp port=%d,program=%s,proto=%s\n", p->port,p->program,p->proto);
    if (ret) {
        goto out;
    }

    ret = get_udp_port(p, loc);
    printf("do_sys_port_get:udp port=%d,program=%s,proto=%s\n", p->port,p->program,p->proto);

out:
//    prg_cache_clear();

    return ret;
}
#endif


void test_popen()
{
    int ret = 0;
    int len = 0;
    FILE *fp = NULL;
    char cmds[1024] = { 0 };
    char buf[101]  = { 0 };
    char pkgname[1024] = { "agent.c" };
    char err_msg[512] = { 0 };


    //sprintf(cmds, "ps -ef |grep socket 2>/dev/null", pkgname);
    sprintf(cmds, "ps -ef |grep socket 2>/dev/null");
    printf("main:cmds:%s\n",cmds);
    fp = popen(cmds, "r");
    if (fp == NULL) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] popen error.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
        system(err_msg);

        ret = -1;
        goto out;
    }

    while (!feof(fp)) {
        len = fread(buf, 1, sizeof(buf), fp);
        printf("main111:len:%d,buf:%s\n",len,buf);
        if (len <= 0) {
            break;
        }
        printf("main222:len:%d,buf:%s\n",len,buf);

        if (strstr(buf, "acpid.socket11") != NULL) {
            ret = 0;
            printf("main333:len:%d,buf:%s\n",len,buf);
            goto out;
        } else if (strstr(buf, "daemon") != NULL) {
            ret = 0;
            printf("main444:len:%d,buf:%s\n",len,buf);
            goto out;
        }
    }

out:
    if (fp) {
        pclose(fp);
        fp = NULL;
    }

}

/*  C 库函数 long int strtol(const char *str, char **endptr, int base) 把参数 str 所指向的字符串根据给定的 base 转换为一个长整数（类型为 long int 
型），base 必须介于 2 和 36（包含）之间，或者是特殊值 0。
    long int strtol(const char *str, char **endptr, int base)
    参数: str -- 要转换为长整数的字符串。
          endptr -- 对类型为 char* 的对象的引用，其值由函数设置为 str 中数值后的下一个字符。
          base -- 基数，必须介于 2 和 36（包含）之间，或者是特殊值 0。
    返回值:该函数返回转换后的长整数，如果没有执行有效的转换，则返回一个零值。
*/
long strtol_test()
{
   char str1[30] = "This is test 1";
   char str2[30] = "203030666666 This is test2";
   char *ptr;
   long ret;

   ret = strtol(str1, &ptr, 10);
   printf("strtol_test:数字（无符号长整数）是 %ld\n", ret);
   printf("strtol_test:字符串部分是 |%s|\n", ptr);


   ret = strtol(str2, &ptr, 0);
   printf("strtol_test:数字（无符号长整数）是 %ld\n", ret);
   printf("strtol_test:字符串部分是 |%s|\n", ptr);

    /*
        strtol_test:数字（无符号长整数）是 0
        strtol_test:字符串部分是 |This is test 1|
        strtol_test:数字（无符号长整数）是 203030666666
        strtol_test:字符串部分是 | This is test2|
    */
   return ret;
}

/*  C 库函数 char *strtok(char *str, const char *delim) 分解字符串 str 为一组字符串，delim 为分隔符。
    char *strtok(char *str, const char *delim)
    str -- 要被分解成一组小字符串的字符串。
    delim -- 包含分隔符的 C 字符串。
    返回值:该函数返回被分解的第一个子字符串，如果没有可检索的字符串，则返回一个空指针。
*/
int strtok_test(void)
{
   char str[80] = "This is - www.runoob.com - website";
   const char s[2] = "-";
   char *token;
   
   /* 获取第一个子字符串 */
   token = strtok(str, s);
   
   /* 继续获取其他的子字符串 */
   while( token != NULL ) {
      printf( "%s\n", token );
    
      token = strtok(NULL, s);
   }
    /*
         This is 
         www.runoob.com 
         website
    */
   
   return(0);
}

/*  C 库函数 char *strstr(const char *haystack, const char *needle) 在字符串 haystack 中查找第一次出现字符串 needle 的位置，不包含终止符 '\0'。
    char *strstr(const char *haystack, const char *needle)
    参数: haystack -- 要被检索的 C 字符串。
          needle -- 在 haystack 字符串内要搜索的小字符串。
    返回值:该函数返回在 haystack 中第一次出现 needle 字符串的位置，如果未找到则返回 null。
*/
int strstr_test(void)
{
   const char haystack[20] = "RUNOOB:ffw";
   const char needle[10] = ":";
   char *ret = NULL;
    int len= 0;
   //len = strlen(ret);
   ret = strstr(haystack, needle);
 
   printf("子字符串是：ret=[%s],haystack=[%s]\n", ret,haystack);
    /*
        子字符串是：ret=[:ffw],haystack=[RUNOOB:ffw]
    */
   
   return(0);
}


char * get_exe_path_readlink( char * buf, int count)
{
    int i;
    int rslt = readlink("/proc/self/exe", buf, count - 1);
    if (rslt < 0 || (rslt >= count - 1))
    {
        return NULL;
    }
    printf("get_exe_path: rslt=%d, buf=%s\n", rslt, buf);
    /* get_exe_path: rslt=17, buf=/home/ly/tst/test */
    buf[rslt] = '\0';
    for (i = rslt; i >= 0; i--)
    {
        printf("get_exe_path: buf[%d] %c\n", i, buf[i]);
        if (buf[i] == '/')
        {
            buf[i + 1] = '\0';
            break;
        }
    }
    printf("get_exe_path:buf=%s\n",buf);
    /* get_exe_path:home/ly/tst/test */
    return buf;
}

int get_exe_path_test(void)
{
    char path[1024];
    printf("get_exe_path_test:%s\n", get_exe_path_readlink(path, 1024));
    /* get_exe_path_test:home/ly/tst/ */
    return 0;
}

void opendir_readdir(char dirname[])
{
	DIR *dir_ptr;
	struct dirent *direntp;
 
    printf("opendir_readdir:dirname=%s\n",dirname);
	dir_ptr = opendir(dirname);
	if(dir_ptr == NULL)
	{
		printf("opendir_readdir: can not opendir %s\n",dirname);
	}
	else 
	{
	   	direntp = readdir(dir_ptr);
		while(direntp == NULL)
		{
			printf("opendir_readdir 11:%s\n",direntp->d_name);
		}

        printf("opendir_readdir 22:%s\n",direntp->d_name);

		closedir(dir_ptr);
	}

	return;
}

void opendir_readdir_test(void)
{

	opendir_readdir("/home/ly/tst/");
	opendir_readdir("/home/ly/name_uniqid/");
	opendir_readdir("/home/ly/readdirtest/");
	opendir_readdir(".");
	/*
        opendir_readdir:dirname=/home/ly/tst/
        opendir_readdir 22:test.c
        opendir_readdir:dirname=/home/ly/name_uniqid/
        opendir_readdir 22:rsfile
        opendir_readdir:dirname=/home/ly/readdirtest/
        opendir_readdir 22:readfile
        opendir_readdir:dirname=.
        opendir_readdir 22:test.c
	*/
}

void pragma_warning_func()
{
#pragma warning(disable: 4189)
      char s;
      s = 128;
#pragma warning(default: 4189)
      char c;
      c = 128;
}

void fileno_test(void)
{
     FILE   *fp;
     int   fd;
     fp = fopen("/home/ly/test/namefile", "r");
     printf("fileno_test:fp = %s\n", fp);
     fd = fileno(fp);
     printf("fileno_test:fd = %d\n", fd);
     fclose(fp);
     /* 执行：fileno()用来取得参数stream指定的文件流所使用的文件描述词
         fileno_test:fp = $­
         fileno_test:fd = 3
     */
}
void while_test(void)
{
        int timeout = 5;
        while(timeout--){
            printf("while_test:timeout = %d\n", timeout);
            sleep(2);
            continue;
        }
}

static pthread_mutex_t g_mutex_lock_pthread;


void pthread_create_test0_chi0_chi0(void)
{
    /* 线程pthread开始运行 */
    printf("pthread_create_test0_chi0_chi0!\n");

}
void pthread_create_test0_chi0_chi1(void)
{
    /* 线程pthread开始运行 */
    printf("pthread_create_test0_chi0_chi1!\n");

}

void pthread_create_test0_chi0(void)
{
    /* 线程pthread开始运行 */
    pthread_t tidptt;
    pthread_t tidptt1;
    /* 线程pthread开始运行 */
    
    printf("pthread_create_test0_chi0 111!\n");

    /* 创建线程  */
    if ((pthread_create(&tidptt, NULL, pthread_create_test0_chi0_chi0, NULL)) == -1)
    {
        printf("create error!\n");
        return -1;
    }
    /* 创建线程  */
    if ((pthread_create(&tidptt1, NULL, pthread_create_test0_chi0_chi1, NULL)) == -1)
    {
        printf("create error!\n");
        return -1;
    }
    sleep(1);/* 等待创建的线程执行 */
    printf("pthread_create_test0_chi0 222!\n");

}

void pthread_create_test0_chi1_chi0(void)
{
    /* 线程pthread开始运行 */
    printf("pthread_create_test0_chi1_chi0!\n");

}
void pthread_create_test0_chi1_chi1(void)
{
    /* 线程pthread开始运行 */
    printf("pthread_create_test0_chi1_chi1!\n");

}

void pthread_create_test0_chi1(void)
{
    /* 线程pthread开始运行 */
    pthread_t tidptt;
    pthread_t tidptt1;
    /* 线程pthread开始运行 */
    
    printf("pthread_create_test0_chi1 111!\n");

    /* 创建线程  */
    if ((pthread_create(&tidptt, NULL, pthread_create_test0_chi1_chi0, NULL)) == -1)
    {
        printf("create error!\n");
        return -1;
    }
    /* 创建线程  */
    if ((pthread_create(&tidptt1, NULL, pthread_create_test0_chi1_chi1, NULL)) == -1)
    {
        printf("create error!\n");
        return -1;
    }
    sleep(1);/* 等待创建的线程执行 */
    printf("pthread_create_test0_chi1 222!\n");

}


int pthread_create_test0(void)
{
    pthread_t tidptt;
    pthread_t tidptt1;
    /* 线程pthread开始运行 */
    
    printf("pthread_create_test0 111!\n");

    /* 创建线程  */
    if ((pthread_create(&tidptt, NULL, pthread_create_test0_chi0, NULL)) == -1)
    {
        printf("create error!\n");
        return -1;
    }
    /* 创建线程  */
    if ((pthread_create(&tidptt1, NULL, pthread_create_test0_chi1, NULL)) == -1)
    {
        printf("create error!\n");
        return -1;
    }
    sleep(1);/* 等待创建的线程执行 */
    printf("pthread_create_test0 222!\n");
    return 0;
}

void pthread_create_test1(void)
{
    int index1 = 0;
    int index2 = 0;
    printf("pthread_create_test1!111 index1 = %d,index2 = %d\n",index1,index2);
    /* 线程pthread开始运行 */
    //pthread_mutex_lock(&g_mutex_lock_pthread);    
    #if 1
    while(1)
    {   
        index1++;
        printf("pthread_create_test1!111 index1 = %d\n",index1);
        if (index1 == 10)
        {
            break;
        }
        sleep(1);
        #if 0
        while(1)
        {
            index2++;
            if (index2 == 3)
            {
                break;
            }
            sleep(1);
            printf("pthread_create_test1!222 index2 = %d\n",index2);
            
        }
        #endif
    }
    #endif
    //pthread_mutex_unlock(&g_mutex_lock_pthread);

}

void pthread_create_test2(void)
{
    /* 线程pthread开始运行 */
    pthread_mutex_lock(&g_mutex_lock_pthread);    
    printf("pthread_create_test2!\n");
    pthread_mutex_unlock(&g_mutex_lock_pthread);

}
void pthread_create_test3(void)
{
    /* 线程pthread开始运行 */
    pthread_mutex_lock(&g_mutex_lock_pthread);    
    printf("pthread_create_test3!\n");
    pthread_mutex_unlock(&g_mutex_lock_pthread);

}

int pthread_test(void)
{
    pthread_t tidp[4];
    
    int ret = pthread_mutex_init(&g_mutex_lock_pthread, NULL);
    if (ret != 0) {
        printf("mutex init failed\n");
        return -1;
    }

    //pthread_create_test1();
    
    printf("pthread_test 111!\n");

    
    /* 创建线程 name_uniqid_thread */
    if ((pthread_create(&tidp[1], NULL, pthread_create_test1, NULL)) == -1)
    {
        printf("create error!\n");
        return -1;
    }
    
    printf("pthread_test 222!\n");
    /*  能够保证子线程运行：
        方法1：在“return 0;”之前加上一句“sleep(1);”
        方法2：在“父进程”所对应程序中加上一句“pthread_join()”
        方法3：在“父进程”所对应程序中加上一句“pthread_exit(NULL)”
    */
    /* 方法1：等待创建的线程执行:设置时间到后，子线程退出不在执行 */
    sleep(5);//设置的时间
    
    /* 方法2：等待创建的线程执行，线程一直执行除非线程自身条件触发退出 */
    //if (pthread_join(tidp[1],NULL))   
    //{
    //    printf("thread1 is not exit...111\n");
    //    return -2;
   // }
    
    /* 方法3：等待创建的线程执行，线程一直执行除非线程自身条件触发退出 */
    //pthread_exit(NULL);
        
    //pthread_cancel(tidp[1]); /* 取消此线程 */
    
#if 1

    /* 创建线程 name_uniqid_thread */
    if ((pthread_create(&tidp[0], NULL, pthread_create_test0, NULL)) == -1)
    {
        printf("create error!\n");
        return -1;
    }

    /* 等待线程name_uniqid_thread释放 */
    /* 等待线程name_uniqid_thread释放 */
    //pthread_cancel(tidp[0]);

    //sleep(1);/* 等待创建的线程执行 */

    /* 创建线程 name_uniqid_thread */
    if ((pthread_create(&tidp[2], NULL, pthread_create_test2, NULL)) == -1)
    {
        printf("create error!\n");
        return -1;
    }
    /* 创建线程 name_uniqid_thread */
    if ((pthread_create(&tidp[3], NULL, pthread_create_test3, NULL)) == -1)
    {
        printf("create error!\n");
        return -1;
    }

    /* 令线程name_uniqid_thread先运行 */
    //sleep(1);

    /* 等待线程name_uniqid_thread释放 */
    if (pthread_join(tidp[0],NULL))        
    {
        printf("thread0 is not exit...0\n");
        return -2;
    }
    /* 等待线程name_uniqid_thread释放 */
    if (pthread_join(tidp[1],NULL))        
    {
        printf("thread1 is not exit...1\n");
        return -2;
    }
    /* 等待线程name_uniqid_thread释放 */
    if (pthread_join(tidp[2],NULL))        
    {
        printf("thread2 is not exit...2\n");
        return -2;
    }
    
    /* 等待线程name_uniqid_thread释放 */
    //pthread_cancel(tidp[3]);
    if (pthread_join(tidp[3],NULL))        
    {
        printf("thread2 is not exit...3\n");
        return -2;
    }
#endif
    pthread_mutex_destroy(&g_mutex_lock_pthread);

    return 0;

}

/* 指针地址赋值 */
struct register_output {
    int result;
    char msg[128];
};

/* 通过指针入参，然后地址赋值给被调函数，调用函数得到回调参数的值 */
int addr_value_get_function(char *output)
{
    int ret = -1;
    struct register_output *reg;

    reg = (struct register_output *)output;
    reg->result = 10;
    strcpy(reg->msg, "abcdbcd");
    
    printf("addr_value_get_function:reg->result=%d,reg->msg=%s\n",reg->result,reg->msg);
    
    ret = 0;
    return ret;
}

struct httcsec_policy_unit{
	int subject_num;
	int object_num;
	int refvalue_num;
};

struct httcsec_policy_object{
	char *type;
	int value_length;
	char *value;
};
#define HTTCSEC_POLICY_UNIT_EXTERN 0x0101
#define PATH_MAX_LENGTH	512
#define DEGEST_MAX_LENGTH	512
#define OBJECTS_LENGTH		64			
#define PACK_NAME_LENGTH	64
#define DIGEST_LENGTH		64//OR  32?
#define KILO_BYTE				1024
#define MAX_IMAGELEN		1*1024*1024

typedef struct softwarepolicy_st{
	int	soft_status;
	long long pkg_size;
	int 	img_type;
	int 	soft_level;
	char	fullrpm_path[PATH_MAX_LENGTH];
	char	pkg_version[OBJECTS_LENGTH];
	char soft_id[OBJECTS_LENGTH];
	char	pkg_name[256];
	char pkg_desc[DEGEST_MAX_LENGTH];
	char img[MAX_IMAGELEN];
	char group_id[OBJECTS_LENGTH];
	char soft_property[2];//"L" or "R"
	int 	soft_type;
	char dep_list[KILO_BYTE];
	char low_list[KILO_BYTE];
}softwarepolicy_t;


/*
itoa()函数有3个参数：第一个参数是要转换的数字，第二个参数是要写入转换结果的目标字符串，第三个参数是转移数字时所用 
的基数。在上例中，转换基数为10。10：十进制；2：二进制...

itoa并不是一个标准的C函数，它是Windows特有的，如果要写跨平台的程序，请用sprintf。是Windows平台下扩展的，标准库中有sprintf，功能比�
�个更强，用法跟printf类似：

*/
int itoa(int value,char *buff, int radix)
{
	char *p;
	unsigned int a;
	int len;
	char *b;
	char temp;
	unsigned int u;

	p = buff;
	
	if(value < 0){
		*p++ = '-';
		value = 0 - value;
	}
	
	u = (unsigned int)value;
	b = p;

	do{
		a = u % radix;
		u /= radix;
		*p++ = a+'0';
	}while(u > 0);

	len = (int)(p - buff);	
	--p;

	do{
		temp = *p;
		*p = *b;
		*b = temp;
		--p;
		++b;
		
	}while(b < p);

	return len;
	
}

struct httcsec_policy_unit * httcsec_policy_unit_init(int subject_num, int object_num, int refvalue_num, struct httcsec_policy_object *objects)
{
	struct httcsec_policy_unit *item;
	int **pextern;

	if(!objects)
		return NULL;
	
	item = (struct httcsec_policy_unit *)malloc(sizeof(struct httcsec_policy_unit) + sizeof(int *) + sizeof(struct httcsec_policy_object *));
	if(!item)
		return NULL;

    printf("httcsec_policy_unit_init:sizeof(struct httcsec_policy_unit)=%d,sizeof(int *)=%d,sizeof(int)=%d,sizeof(struct httcsec_policy_object *)=%d,sizeof(struct httcsec_policy_object)=%d\n",
                    sizeof(struct httcsec_policy_unit),sizeof(int *),sizeof(int),sizeof(struct httcsec_policy_object *),sizeof(struct httcsec_policy_object));
    printf("httcsec_policy_unit_init:sizeof(char *)=%d\n",sizeof(char *));

	item->subject_num = subject_num;
	item->object_num = object_num;
	item->refvalue_num = refvalue_num;
	
	printf("httcsec_policy_unit_init:item:subject_num=%d,object_num=%d,refvalue_num=%d\n",item->subject_num,item->object_num,item->refvalue_num);

	// separator
	pextern = (int **)(item + 1);
	*pextern = (int *)HTTCSEC_POLICY_UNIT_EXTERN;
	//printf("httcsec_policy_unit_init:**pextern=%d\n",**pextern);
	
	*(struct httcsec_policy_object **)(pextern + 1) = objects;
	
	printf("httcsec_policy_unit_init:item:subject_num=%d,object_num=%d,refvalue_num=%d\n",item->subject_num,item->object_num,item->refvalue_num);

	return item;
}

void httcsec_policy_unit_init_test()
{
	struct httcsec_policy_unit* policy_unit = NULL;
	struct httcsec_policy_object objects[4]; 
	softwarepolicy_t info;
    int  software_status = 89;
	char softstatus[OBJECTS_LENGTH] = {0};

	
    objects[0].type = "null";
    objects[0].value_length = strlen("sp_key")+1;
    objects[0].value = "sp_key";   
    
    objects[1].type = "null";
    objects[1].value_length = strlen("software_name")+1;
    objects[1].value = "software_name";   
    
    objects[2].type = "null";
    objects[2].value_length = strlen("software_version")+1;
    objects[2].value = "software_version";   

	itoa(software_status,softstatus,10);
	printf("softstatus:%s\n",softstatus);
    objects[3].type = "null";
    objects[3].value_length = strlen(softstatus)+1;
    objects[3].value = softstatus;   
    
    policy_unit = httcsec_policy_unit_init(1, 3, 0, objects);
    
	printf("policy_unit:subject_num=%d,object_num=%d,refvalue_num=%d\n",policy_unit->subject_num,policy_unit->object_num,policy_unit->refvalue_num);
	
	printf("objects0:type=%s,value_length=%d,value=%s\n",objects[0].type,objects[0].value_length,objects[0].value);
	printf("objects1:type=%s,value_length=%d,value=%s\n",objects[1].type,objects[1].value_length,objects[1].value);
	printf("objects2:type=%s,value_length=%d,value=%s\n",objects[2].type,objects[2].value_length,objects[2].value);
	printf("objects3:type=%s,value_length=%d,value=%s\n",objects[3].type,objects[3].value_length,objects[3].value);

    return 0;
}

static void crashHare_test()
{
    char *a = (char *)(NULL);
    printf("Dump crashHare_test aaa\n");
    *a="abcdn";
    printf("Dump crashHare_test bbb\n");
}


static void crashHare()
{
    crashHare_test();
    int *a = (int *)(NULL);
    *a = 1; // 放心的奔溃吧
}

void if_else_if_test(void)
{
    int len1 = 6;
    int len2 = 4;

    if (len1 == 5)
    {
        printf("111 len1=%d\n",len1);
    }
    else if(len2 == 6)
    {
        printf("222 len2=%d\n",len2);
    }
    else
    {
        printf("333 \n");
    }
}

int sum(int num_args, ...)
{
   int val = 0;
   va_list ap;
   int i;
   va_start(ap, num_args);
   for(i = 0; i < num_args; i++)
   {
        val += va_arg(ap, int);
        printf("sum:val %d\n",val);
   }
   va_end(ap);
   return val;
}

int sum_ss(int numt,int num_args, ...)
{
   int val = 0;
   va_list ap;
   int i;
   va_start(ap, num_args);
   for(i = 0; i < num_args; i++)
   {
        val += va_arg(ap, int);
        printf("sum_ss:val %d\n",val);
   }
   va_end(ap);
   return val;
}
typedef void (job_fn_t)(int state, int error, int argc, void *argv[]);
int sum_ss_while_job_set(job_fn_t *job_fn, ...)
{
    int i;
    va_list ap;
    void *arg;

    i = 0;
    va_start(ap, job_fn);
    while (1) {
        arg = va_arg(ap, void *);
        if (arg == NULL) {
            printf("job arg == NULL,break\n");
            break;
        }
        if (i >= 4) {
            printf("job arg too more, argc = %d, max = %d.\n", i + 1, 4);
            va_end(ap);
            return -1;
        }
        printf("job argv[%d] = %p.\n", i, arg);
        i++;
    }
    va_end(ap);
    return 0;
}

int va_start_test(void)
{
   printf("va_start_test:sum    8、20 和 30 的和 = %d\n",  sum(3, 8, 20, 30) );
   /*  sum:val 8
       sum:val 28
       sum:val 58
       va_start_test:sum    8、20 和 30 的和 = 58       */
   printf("va_start_test:sum_ss 2、20、25 和 30 的和 = %d\n",  sum_ss(101,4, 2, 20, 25, 30) );
   /*  sum_ss:val 2
       sum_ss:val 22
       sum_ss:val 47
       sum_ss:val 77
       va_start_test:sum_ss 2、20、25 和 30 的和 = 77    */
   printf("va_start_test:sum_ss_while_job_set 0x4、0x2、NULL、0x22、0x25、0x30\n", 
            sum_ss_while_job_set(11,0x4, 0x2, NULL, 0x22,0x25, 0x30) );
    /*  job argv[0] = 0x4.
        job argv[1] = 0x2.
        job arg == NULL,break
        va_start_test:sum_ss_while_job_set 0x4、0x2、NULL、0x22、0x25、0x30   */
   printf("va_start_test:sum_ss_while_job_set 0x4、0x2、0x20、0x22、0x25、0x30\n", 
            sum_ss_while_job_set(11,0x4, 0x2, 0x20, 0x22,0x25, 0x30) );
    /*  job argv[0] = 0x4.
        job argv[1] = 0x2.
        job argv[2] = 0x20.
        job argv[3] = 0x22.
        job arg too more, argc = 5, max = 4.
        va_start_test:sum_ss_while_job_set 0x4、0x2、0x20、0x22、0x25、0x30   */

   return 0;
}

int popen_run_program_test()
{
    int ret = 0;
    int len = 0;
    char tmpcmd[1024] = {'\0'};
    char arch_info[1024] = {'\0'};
    FILE *fp_os_arch = NULL;
    char err_msg[512] = { 0 };

    memset(tmpcmd, 0, sizeof(tmpcmd));
    snprintf(tmpcmd, sizeof(tmpcmd), "./license_check");
    fp_os_arch = popen(tmpcmd, "r");
    if (NULL == fp_os_arch) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] popen error: %s\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__, strerror(errno));
        system(err_msg);

        return -1;
    }

    len = fread(arch_info, sizeof(char), 1024, fp_os_arch);
    if (len > 0) {
        printf("popen_run_program_test:[]",arch_info);
        ret = 0;
        goto EXIT;
    }

EXIT:
    if (NULL != fp_os_arch) {
        pclose(fp_os_arch);
    }

    return ret;
}


//static char *strip_delimiter(char *string, char delimiter)
char *strip_delimiter(char *string, char delimiter)
{
	register int x, y;
	y = strlen(string);
	x = 0;
    printf("y=%d,string:[%s],delimiter=%c.\n",y,string,delimiter);

	while ((x < y) && (string[x] == delimiter))
	{
        printf("string[%d]=%c.\n",x,string[x]);
		x++;
	}
    printf("x=%d.\n",x);

	while ((y > 0) && (string[y - 1] == delimiter))
	{
	
        printf("string[%d]=%c.\n",y - 1,string[y - 1]);
		y--;
	}
    printf("y=%d.\n",y);

	string[y] = 0;
    printf("sstring[y]=%c.\n",string[y]);
	//strcpy(string[y],'0');
    printf("string + x=%s.\n",string + x);
	return string + x;
}



#define HTTCSEC_MISC_DEVICE_TYPE  0xAF

enum{
	COMMAND_SWITCH_AUDIT_FILE  = 0x1,
	COMMAND_UPDATE_HTTCSEC_POLICY,
	COMMAND_NOTIFY_HTTCSEC_POLICY,
	COMMAND_DISABLE_MEASURE_ENGINE,
	COMMAND_ENABLE_MEASURE_ENGINE,
	COMMAND_EXTERN_MAC_MESSAGE,
	COMMAND_SMEASURE_INTERACTIVE,
	COMMAND_TRUSTLINK,
	COMMAND_IDT_ADDRESS_PROTECT,
	COMMAND_SYSCALL_ADDRESS_PROTECT,
	COMMAND_PLATFORM_MESSAGE = 0x55,
	COMMAND_MAX = 256
};

#define ___IO(cmd)  _IO(HTTCSEC_MISC_DEVICE_TYPE,(cmd))
#define IOCTL_TEST_SMEASURE_INTERACTIVE				_IO(HTTCSEC_MISC_DEVICE_TYPE,COMMAND_SMEASURE_INTERACTIVE)
#define IOCTL_TEST_TRUSTLINK				_IO(HTTCSEC_MISC_DEVICE_TYPE,COMMAND_TRUSTLINK)
#define IOCTL_TEST_IDT_ADDRESS_PROTECT				_IO(HTTCSEC_MISC_DEVICE_TYPE,COMMAND_IDT_ADDRESS_PROTECT)
#define IOCTL_TEST_SYSCALL_ADDRESS_PROTECT				_IO(HTTCSEC_MISC_DEVICE_TYPE,COMMAND_SYSCALL_ADDRESS_PROTECT)


#define IOCTL_SWITCH_AUDIT_FILE					___IO(COMMAND_SWITCH_AUDIT_FILE)
#define IOCTL_UPDATE_HTTCSEC_POLICY			___IO(COMMAND_UPDATE_HTTCSEC_POLICY)
#define IOCTL_NOTIFY_HTTCSEC_POLICY			___IO(COMMAND_NOTIFY_HTTCSEC_POLICY)
#define IOCTL_DISABLE_MEASURE_ENGINE		___IO(COMMAND_DISABLE_MEASURE_ENGINE)
#define IOCTL_ENABLE_MEASURE_ENGINE			___IO(COMMAND_ENABLE_MEASURE_ENGINE)
#define IOCTL_EXTERN_MAC_MESSAGE				___IO(COMMAND_EXTERN_MAC_MESSAGE)
#define IOCTL_PLATFORM_MESSAGE			___IO(COMMAND_PLATFORM_MESSAGE)

void ioctl_io(void)
{
    printf("ioctl_io:%x\n",IOCTL_PLATFORM_MESSAGE);
    return;
}


void sscanf_test(void)
{

    int ret = -1;
    int flag_line = -1;
    char tmpcmd[2048] = {'\0'};
    char key[1024] = {'\0'};
    char val[1024] = {'\0'};
    char line[1024] = {'\0'};
    char soft_installed_version[1024] = {'\0'};
    FILE *fp = NULL;
    const char *soft_name = "tipterminalfd";

    snprintf(tmpcmd, sizeof(tmpcmd), "grep -wrn \"%s\" %s",soft_name, "sys_soft_installed_sum.txt");
    printf("sscanf_test: tmpcmd=%s\n",tmpcmd);
    fp = popen(tmpcmd, "r");
    if (fp == NULL) {
        printf("[%s] popen error: %s\n", __func__, strerror(errno));
        return;
    }
    printf("sscanf_test: fp=%s\n",fp);

    while (!feof(fp)) {
        memset(line, 0, sizeof(line));
        memset(key, 0, sizeof(key));
        memset(val, 0, sizeof(val));
        memset(soft_installed_version, 0, sizeof(soft_installed_version));

        if (fgets(line, sizeof(line), fp) == NULL)
            break;
        printf("sscanf_test: line=%s\n",line);

        if (sscanf(line, "%[^:]: %s", key, val) != 2)
        {
            printf("sscanf_test111: key=%s,val=%s.\n", key, val);
            continue;
        }
    }
    printf("sscanf_test222: key=%s,val=%s.\n", key, val);

    pclose(fp);
    fp = NULL;
    return;

}

int fork_test(void)
{
    pid_t fpid; //fpid表示fork函数得返回值
    int count = 0;
    fpid = fork();
    printf("fpid[fpid = fork()]=%d\n ",fpid);

    if (fpid < 0)
        printf("error in fork!");
    else if(fpid == 0)
    {   sleep(2);
        printf("i am child process,my process id is %d\n",getpid());
        printf("我是子进程\n ");
        count++;
    }
    else
    {   sleep(5);
        printf("i am parent process,my process id is %d\n",getpid());
        printf("我是父进程\n ");
        count++;
    }
    printf("统计结果是：%d\n\n",count);

    /*
        fpid[fpid = fork()]=124822
        fpid[fpid = fork()]=0
         i am child process,my process id is 124822
        我是子进程
         统计结果是：1
        
         i am parent process,my process id is 124821
        我是父进程
         统计结果是：1
    */
    return 0;

}


static void make_daemon_2(void)
{
	int i;
	setsid();
	chdir("/");
	umask(0);
	for(i=0;i<getdtablesize();i++)
		close(i);
}

int popen_program_locale_test()
{
    int ret = 0;
    int len = 0;
    char tmpname[1024] = {"tipsfeinal"};
    char tmpcmd[1024] = {'\0'};
    char arch_info[1024] = {'\0'};
    FILE *fp_os_arch = NULL;
    char err_msg[512] = { 0 };

    memset(tmpcmd, 0, sizeof(tmpcmd));
    /* rpm */
    system("export LANG=zh_CN.UTF-8;rpm -i ded");
    //system("rpm -i ded");
    //snprintf(tmpcmd, sizeof(tmpcmd), "/bin/rpm -q \"%s\"  ", "tiptermi");
    //snprintf(tmpcmd, sizeof(tmpcmd), "export LANG=zh_CN.UTF-8;rpm -i '%s'",tmpname);
    //snprintf(tmpcmd, sizeof(tmpcmd), "rpm -i '%s'",tmpname);
    /* dpkg */
    //snprintf(tmpcmd, sizeof(tmpcmd), "export LANG=zh_CN.UTF-8;dpkg -l '%s'",tmpname);
    //snprintf(tmpcmd, sizeof(tmpcmd), "dpkg -l '%s'",tmpname);
    //printf("soft_multiversion_check_dpkg:tmpcmd=[%s],tmpname=%s\n",tmpcmd,tmpname);
    fp_os_arch = popen(tmpcmd, "r");
    if (NULL == fp_os_arch) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] popen error: %s\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__, strerror(errno));
        system(err_msg);

        return -1;
    }

    len = fread(arch_info, sizeof(char), 1024, fp_os_arch);
    if (len > 0) {
        printf("popen_program_locale_test:[%s]",arch_info);
        ret = 0;
        goto EXIT;
    }

EXIT:
    if (NULL != fp_os_arch) {
        pclose(fp_os_arch);
    }

    return ret;
}

int abort_test()
{
   FILE *fp;
   
   printf("准备打开111 nofile.txt\n");
   fp = fopen( "nofile.txt","r" );
   if(fp == NULL)
   {
      printf("准备终止程序2222\n");
      //abort();
   }
   printf("准备关闭3333 nofile.txt\n");
   if(fp != NULL)fclose(fp);
   
   printf("准备关闭 444 nofile.txt\n");
   return 0;
}
static const char *softlist_temp_file = "/tmp/syssoft_file.txt";

static int dpkg_softlist_generate()
{
    char tmpcmd[1024] = {'\0'};
    char err_msg[512] = { 0 };
    FILE *fp_softlist = NULL;

    //snprintf(tmpcmd, sizeof(tmpcmd), "export LANG=zh_CN.UTF-8;/usr/bin/dpkg -l > %s", softlist_temp_file);
    snprintf(tmpcmd, sizeof(tmpcmd), "export LANG=zh_CN.UTF-8;/usr/bin/dpkg -l|grep ^ii|awk -F' ' '{print $2,$3,$4}'|sed 's/[ ]/_/g' > %s", softlist_temp_file);

    fp_softlist = popen(tmpcmd, "r");
    if (NULL == fp_softlist) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] popen error: %s.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__, strerror(errno)
);
        system(err_msg);

        return -1;
    }

    if (NULL != fp_softlist) {
        pclose(fp_softlist);
        fp_softlist = NULL;
    }

    return 0;
}

static int rpm_softlist_generate()
{
    char tmpcmd[1024] = {'\0'};
    char err_msg[512] = { 0 };
    FILE *fp_softlist = NULL;

    snprintf(tmpcmd, sizeof(tmpcmd), "export LANG=zh_CN.UTF-8;/bin/rpm -qa > %s", softlist_temp_file);

    fp_softlist = popen(tmpcmd, "r");
    if (NULL == fp_softlist) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] popen error: %s.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__, strerror(errno)
);
        system(err_msg);

        return -1;
    }

    if (NULL != fp_softlist) {
        pclose(fp_softlist);
        fp_softlist = NULL;
    }

    return 0;
}

int popen_run_softcmd_test()
{
    int ret = 0;
    int len = 0;
    char tmpcmd[1024] = {'\0'};
    char arch_info[1024] = {'\0'};
    FILE *fp_os_arch = NULL;
    char err_msg[512] = { 0 };

    memset(tmpcmd, 0, sizeof(tmpcmd));
    snprintf(tmpcmd, sizeof(tmpcmd), "./license_check");
    fp_os_arch = popen(tmpcmd, "r");
    if (NULL == fp_os_arch) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] popen error: %s\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__, strerror(errno));
        system(err_msg);

        return -1;
    }


    if (NULL != fp_os_arch) {
        pclose(fp_os_arch);
    }

    return ret;
}


typedef struct sys_softlist_node {
    char name[256];
    char verinfo[64];
    char softarch[64];
    struct sys_softlist_node *pnext;
}sys_soft_node,*ps_node;

struct all_softlist_info {
    char os[64];
    int syscount;
    struct sys_softlist_node * psyssoftlist;
    int tipcount;
    struct sys_softlist_node * ptipsoftlist;
};

static struct all_softlist_info * pall_softlist = NULL;

int check_is_tip_manage_soft(char * softname, char * softver, char * softarch, char * tipterminal_name)
{
    ps_node ptemp = NULL;
    if (NULL != pall_softlist->ptipsoftlist) {
        for (ptemp = pall_softlist->ptipsoftlist; ptemp != NULL; ptemp = ptemp->pnext){
            if(strlen(ptemp->name)== strlen(softname) && 
                    0 == strcmp(ptemp->name, softname) && 
                    strlen(ptemp->verinfo)== strlen(softver) &&
                    0 == strcmp(ptemp->verinfo, softver)){
                memset(ptemp->softarch, 0, strlen(ptemp->softarch));
                strncpy(ptemp->softarch, softarch, sizeof(ptemp->softarch)-1);
                return 0;
            }else if(strlen(ptemp->name)== strlen(softname) && 
                    0 == strcmp(ptemp->name, softname) &&
                    0 == strncmp(ptemp->name, tipterminal_name, strlen(tipterminal_name))){
                memset(ptemp->softarch, 0, strlen(ptemp->softarch));
                strncpy(ptemp->softarch, softarch, sizeof(ptemp->softarch)-1);
                return 0;
            }

        }
    }
    return 1;
}
static const char *tipterminal_type_file = "/opt/softmanager/tipterminal/var/platform_pkgname";
enum OS_PACK {
    OS_PACK_RPM = 1,
    OS_PACK_DPKG,

    OS_PACK_NONE,
};
#define OS_INFO_LENGTH             256
#define INFO_LENGTH               1024

enum OS_PACK ca_get_local_os_pack()
{
    char tipterminal_name[INFO_LENGTH] = { 0 };
    FILE *fp = NULL;
    char err_msg[512] = { 0 };

    if (access(tipterminal_type_file, R_OK) != 0) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] ERROR: access %s error: %s\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__, 
tipterminal_type_file, strerror(errno));
        system(err_msg);

        return OS_PACK_NONE;
    }

    fp = fopen(tipterminal_type_file, "r");
    if (NULL == fp) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] ERROR: fopen %s error: %s\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__, 
tipterminal_type_file, strerror(errno));
        system(err_msg);

        return OS_PACK_NONE;
    }

    fgets(tipterminal_name, sizeof(tipterminal_name), fp);

    /* delete \n in the tipterminal_name */
    if (tipterminal_name[strlen(tipterminal_name) - 1] == '\n') {
        tipterminal_name[strlen(tipterminal_name) - 1] = '\0';
    }

    if (NULL != fp) {
        fclose(fp);
        fp = NULL;
    }

    if (0 == strcmp(tipterminal_name, "tipterminalzblx")) {
        return OS_PACK_RPM;
    } else if (0 == strcmp(tipterminal_name, "tipterminal")) {
        return OS_PACK_RPM;
    } else if (0 == strcmp(tipterminal_name, "tipterminalzblxsvr")) {
        return OS_PACK_RPM;
    } else if (0 == strcmp(tipterminal_name, "tipterminalhgsvr")) {
        return OS_PACK_RPM;
    } else if (0 == strcmp(tipterminal_name, "tipterminalsw")) {
        return OS_PACK_RPM;
    } else if (0 == strcmp(tipterminal_name, "tipterminalfd")) {
        return OS_PACK_DPKG;
    } else if (0 == strcmp(tipterminal_name, "tipterminalfdsvr")) {
        return OS_PACK_RPM;
    } else if (0 == strcmp(tipterminal_name, "tipterminalfdhgsvr")) {
        return OS_PACK_RPM;
    } else if (0 == strcmp(tipterminal_name, "tipterminalft")) {
        return OS_PACK_DPKG;
    } else if (0 == strcmp(tipterminal_name, "tipterminalftsvr")) {
        return OS_PACK_RPM;
    } else if (0 == strcmp(tipterminal_name, "tipterminalzbzx")) {
        return OS_PACK_RPM;
    } else if (0 == strcmp(tipterminal_name, "tipterminalzbhgsvr")) {
        return OS_PACK_RPM;
    } else if (0 == strcmp(tipterminal_name, "tipterminalyhlx")) {
        return OS_PACK_DPKG;
    } else if (0 == strcmp(tipterminal_name, "tipterminalyhlxsvr")) {
        return OS_PACK_RPM;
    } else if (0 == strcmp(tipterminal_name, "tipterminalloong")) {
        return OS_PACK_DPKG;
    } else {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] ERROR: no tipterminal match.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
        system(err_msg);

        return OS_PACK_NONE;
    }
}

int get_tipterminal_name_string(char *tipterminal_name, size_t name_len)
{
    char err_msg[512] = { 0 };

    if (NULL == tipterminal_name) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] ERROR: invalid arg.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
        system(err_msg);

        return -1;
    }

    char name_info[INFO_LENGTH] = { 0 };
    FILE *fp = NULL;

    if (access(tipterminal_type_file, R_OK) != 0) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] ERROR: access file %s error: %s.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__
, tipterminal_type_file, strerror(errno));
        system(err_msg);

        return -1;
    }

    fp = fopen(tipterminal_type_file, "r");
    if (NULL == fp) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] ERROR: fopen file %s error: %s.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__, 
tipterminal_type_file, strerror(errno));
        system(err_msg);

        return -1;
    }

    fgets(name_info, sizeof(name_info), fp);

    /* delete \n in the name_info */
    if (name_info[strlen(name_info) - 1] == '\n') {
        name_info[strlen(name_info) - 1] = '\0';
    }

    strncpy(tipterminal_name, name_info, name_len);

    if (NULL != fp) {
        fclose(fp);
        fp = NULL;
    }

    return 0;
}



int rpm_softinfo_parse(const char *filename, char *pkg_name, char *ver_rels, char *pkg_arch)
{
    char tmpcmd[1024] = {'\0'};
    char err_msg[512] = { 0 };
    FILE *fp_softlist = NULL;
    char pkg_name_tmp[256] = {0};
    char ver_rels_tmp[128] = {0};
    char pkg_arch_tmp[64] = {0};
    char pkg_ver[64] = {0};
    char pkg_release[64] = {0};

    char sline[512] = {'\0'};
    char cmd[1024] = {'\0'};
    char key[64] = {'\0'};
    char val[256] = {'\0'};

    snprintf(tmpcmd, sizeof(tmpcmd), "export LANG=zh_CN.UTF-8;/bin/rpm -qi %s", filename);

    fp_softlist = popen(tmpcmd, "r");
    if (NULL == fp_softlist) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] popen error: %s.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__, strerror(errno)
);
        system(err_msg);

        return -1;
    }
    while (!feof(fp_softlist)) {
        memset(sline, 0, sizeof(sline));
        memset(key, 0, sizeof(key));
        memset(val, 0, sizeof(val));
    
        if (fgets(sline, sizeof(sline), fp_softlist) == NULL)
            break;
    
        if (sscanf(sline, "%[^:]: %s", key, val) != 2)
            continue;
    
        if (strncasecmp(key, "Name", sizeof("Name") - 1) == 0) {
            strncpy(pkg_name_tmp, val, sizeof(pkg_name_tmp));
        } 
        if (strncasecmp(key, "Version", sizeof("Version") - 1) == 0) {
            strncpy(pkg_ver, val, sizeof(pkg_ver));
        }
        if (strncasecmp(key, "Release", sizeof("Release") - 1) == 0) {
            strncpy(pkg_release, val, sizeof(pkg_release));
        }
    
        if (strncasecmp(key, "Architecture", sizeof("Architecture") - 1) == 0) {
            strncpy(pkg_arch_tmp, val, sizeof(pkg_arch_tmp));
            break;
        }
    }
    snprintf(ver_rels_tmp, sizeof(ver_rels_tmp), "%s-%s", pkg_ver, pkg_release);

    if (NULL != fp_softlist) {
        pclose(fp_softlist);
        fp_softlist = NULL;
    }
    strcpy(pkg_name,pkg_name_tmp);
    strcpy(ver_rels,ver_rels_tmp);
    strcpy(pkg_arch,pkg_arch_tmp);
    printf("rpm_softinfo_parse:filename=[%s],pkg_name=[%s], ver_rels=[%s], pkg_arch=[%s]\n",filename,pkg_name, ver_rels,pkg_arch);
    
    return 0;
}


int dpkg_softinfo_parse(const char *filename, char *pkg_name, char *pkg_ver, char *pkg_arch)
{
    char tmpcmd[1024] = {'\0'};
    char err_msg[512] = { 0 };
    FILE *fp_softlist = NULL;
    char pkg_name_tmp[256] = {0};
    char pkg_ver_tmp[64] = {0};
    char pkg_arch_tmp[64] = {0};

    char sline[512] = {'\0'};
    char key[64] = {'\0'};
    char val[256] = {'\0'};

    snprintf(tmpcmd, sizeof(tmpcmd), "export LANG=zh_CN.UTF-8;dpkg -s '%s' ", filename);

    fp_softlist = popen(tmpcmd, "r");
    if (NULL == fp_softlist) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] popen error: %s.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__, strerror(errno)
);
        system(err_msg);

        return -1;
    }

    while (!feof(fp_softlist)) {
        memset(sline, 0, sizeof(sline));
        memset(key, 0, sizeof(key));
        memset(val, 0, sizeof(val));
    
        if (fgets(sline, sizeof(sline), fp_softlist) == NULL) {
            break;
        }
    
        if (sscanf(sline, "%[^:]: %s", key, val) != 2) {
            continue;
        }
    
        if (strncasecmp(key, "Package", sizeof("Package") - 1) == 0) {
            strncpy(pkg_name_tmp, val, sizeof(pkg_name_tmp));
        }
    
        if (strncasecmp(key, "Version", sizeof("Version") - 1) == 0) {
            strncpy(pkg_ver_tmp, val, sizeof(pkg_ver_tmp));
        }
    
        if (strncasecmp(key, "Architecture", sizeof("Architecture") - 1) == 0) {
            strncpy(pkg_arch_tmp, val, sizeof(pkg_arch_tmp));
        }
    }

    if (NULL != fp_softlist) {
        pclose(fp_softlist);
        fp_softlist = NULL;
    }
    strcpy(pkg_name,pkg_name_tmp);
    strcpy(pkg_ver,pkg_ver_tmp);
    strcpy(pkg_arch,pkg_arch_tmp);
    printf("dpkg_softinfo_parse:filename=[%s],pkg_name=[%s], pkg_ver=[%s], pkg_arch=[%s]\n",filename,pkg_name, pkg_ver,pkg_arch);
    

    return 0;
}

static const char *installed_softlist_file_online = "/opt/softmanager/tipterminal/var/installed_soft_list_online.txt";

ps_node get_sys_save_softlist(char *filename, int *count)
{
    int ret = -1;
    int add_count = 0;
    ps_node phead = NULL;
    FILE *fp = NULL;
    char line[512] = {'\0'};
    char soft_name[256] = {'\0'};

    char pkg_name[256] = {0};
    char pkg_ver[64] = {0};
    char pkg_release[64] = {0};
    char pkg_arch[64] = {0};
    char ver_rels[128] = {0};

    char cmd[1024] = {'\0'};
    char key[64] = {'\0'};
    char val[256] = {'\0'};
    ps_node ptemp = NULL;
    char err_msg[512] = { 0 };

    FILE *fpw = NULL;
    char softbuf[256] = {'\0'};
    char *stringtmp = NULL;
    char *stringtmpa = NULL;
    char *stringtmpb = NULL;
    char *stringtmpc = NULL;
    char stringtmpname[256] = {'\0'};
    char os_flag = 0;
    char stringtmpbuf[256] = {'\0'};


    char tipterminal_name[64] = {0};
    if(0 != get_tipterminal_name_string(tipterminal_name, 63)){
        memcpy(tipterminal_name, "tipterminal", 11);
    }

    fp = fopen(filename, "r");
    if (fp == NULL) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] fopen %s error.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__, filename);
        system(err_msg);

        return phead;
    }
    
    if (OS_PACK_RPM == ca_get_local_os_pack())
    {
        os_flag = 1;
    }
    else if (OS_PACK_DPKG == ca_get_local_os_pack())
    {
        os_flag = 2;
    }
    
    /* todo rm */
    char tmpcmd[512] = {'\0'};
    memset(tmpcmd, 0, sizeof(tmpcmd));
    snprintf(tmpcmd, sizeof(tmpcmd), "rm -rf %s", installed_softlist_file_online);
    system(tmpcmd);
    fpw = fopen(installed_softlist_file_online,"a");
    if(NULL == fpw)
    {
        printf("get_sys_save_softlist:fopen fpw error.\n");
    }
    

    while (!feof(fp)) {
        memset(line, 0, sizeof(line));
        memset(pkg_name, 0, sizeof(pkg_name));
        memset(pkg_ver, 0, sizeof(pkg_ver));
        memset(pkg_arch, 0, sizeof(pkg_arch));
        memset(ver_rels, 0, sizeof(ver_rels));
        memset(softbuf, 0, sizeof(softbuf));
        memset(stringtmpname, 0, sizeof(stringtmpname));

        if (fgets(line, sizeof(line), fp) == NULL)
            break;
        memcpy(softbuf,line,strlen(line) - 1);
        
        printf("get_sys_save_softlist: fgets line=[%s]len=%d,softbuf=[%s]len=%d\n",line,strlen(line),softbuf,strlen(softbuf));

#if 0
        /* '_' in the head means the soft have been replaced */
        if ('_' == line[0]) {
            continue;
        }
#endif

        if (1 == os_flag) {
            /*
                libcroco-0.6.12-4.nfs.x86_64
                qt5-rpm-macros-5.11.1-2.nfs.noarch
                
                gpg-pubkey-ec551f03-53619141
                gpg-pubkey-b25e7f66-5dad5bcf
                vid.stab-1.1.0-9.20180529git38ecbaf.ky10.sw_64
            */
            
            if(stringtmpb = strchr(softbuf,'.'))
            {
                memcpy(stringtmpname,softbuf,strlen(softbuf) - strlen(stringtmpb));
                if(stringtmpa = strrchr(stringtmpname,'-'))
                {
                    memcpy(pkg_name,stringtmpname,strlen(stringtmpname) - strlen(stringtmpa));
                    if(stringtmpc = strrchr(softbuf,'.'))
                    {
                        memcpy(pkg_arch,stringtmpc + 1,strlen(stringtmpc) - 1);
                        memcpy(ver_rels,softbuf + strlen(pkg_name) + 1,strlen(softbuf) - strlen(pkg_name)- strlen(pkg_arch) - 2);
                    }
                    else
                    {
                        rpm_softinfo_parse(softbuf,pkg_name,ver_rels,pkg_arch);
                    }
                }
                else
                {
                    rpm_softinfo_parse(softbuf,pkg_name,ver_rels,pkg_arch);
                }
            }
            else
            {
                rpm_softinfo_parse(softbuf,pkg_name,ver_rels,pkg_arch);
            }
            
            /* todo rm */
            memset(stringtmpbuf, 0, sizeof(stringtmpbuf));
            snprintf(stringtmpbuf, sizeof(stringtmpbuf), "%s-%s.%s",pkg_name, ver_rels,pkg_arch);
            printf("get_sys_save_softlist:stringtmpbuf=[%s],pkg_name=[%s], ver_rels=[%s], pkg_arch=[%s],tipterminal_name:[%s]\n\n",stringtmpbuf,pkg_name, ver_rels,pkg_arch,tipterminal_name);
            fputs(stringtmpbuf,fpw);
            fputs("\n",fpw);


            if(0 == check_is_tip_manage_soft(pkg_name, ver_rels, pkg_arch, tipterminal_name)){
                continue;
            }else{
                ptemp = (ps_node)malloc(sizeof(struct sys_softlist_node));
                if (NULL == ptemp) {
                    memset(err_msg, 0, sizeof(err_msg));
                    snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] malloc error.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
                    system(err_msg);
                    goto opsfd_err;
                }
                memset(ptemp, 0, sizeof(struct sys_softlist_node));
                if (0 == add_count) {
                    phead = ptemp;
                } else {
                    ptemp->pnext = phead->pnext;
                    phead->pnext = ptemp;
                }
                strncpy(ptemp->name, pkg_name, sizeof(ptemp->name));
                strncpy(ptemp->verinfo, ver_rels, sizeof(ptemp->verinfo));
                strncpy(ptemp->softarch, pkg_arch, sizeof(ptemp->softarch));
                add_count++;
            }
        }

opsfd_err:

        if (2 == os_flag) {
            /*
                ziptorpmdeb_1.2_all
                zlib1g:amd64_1:1.2.8.dfsg-5+1nfs3_amd64
            */
            
            if(stringtmpb = strchr(softbuf,'_'))
            {
                memcpy(stringtmpname,softbuf,strlen(softbuf) - strlen(stringtmpb));
                
                if (stringtmp = strchr(stringtmpname,':'))
                {
                    memcpy(pkg_name,stringtmpname,strlen(stringtmpname) - strlen(stringtmp));
                }
                else
                {
                    memcpy(pkg_name,stringtmpname,strlen(stringtmpname));
                }
                
                stringtmpc = strrchr(softbuf,'_');
                memcpy(pkg_arch,stringtmpc + 1,strlen(stringtmpc) - 1);
                
                memcpy(pkg_ver,stringtmpb + 1,strlen(stringtmpb) - strlen(stringtmpc) - 1);
            }
            else
            {
                dpkg_softinfo_parse(softbuf,pkg_name,pkg_ver,pkg_arch);
            }
            
            /* todo rm */
            memset(stringtmpbuf, 0, sizeof(stringtmpbuf));
            snprintf(stringtmpbuf, sizeof(stringtmpbuf), "%s_%s_%s",pkg_name, pkg_ver,pkg_arch);
            printf("get_sys_save_softlist:stringtmpbuf=[%s],pkg_name=[%s], pkg_ver=[%s], pkg_arch=[%s],tipterminal_name:[%s]\n",stringtmpbuf,pkg_name, pkg_ver,pkg_arch,tipterminal_name);
            fputs(stringtmpbuf,fpw);
            fputs("\n",fpw);

            if(0 == check_is_tip_manage_soft(pkg_name, pkg_ver, pkg_arch, tipterminal_name)){
                continue;
            }else{
                ptemp = (ps_node)malloc(sizeof(struct sys_softlist_node));
                if (NULL == ptemp) {
                    memset(err_msg, 0, sizeof(err_msg));
                    snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] malloc error.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
                    system(err_msg);
                    goto opsfd_err;
                }
                memset(ptemp, 0, sizeof(struct sys_softlist_node));
                if (0 == add_count) {
                    phead = ptemp;
                } else {
                    ptemp->pnext = phead->pnext;
                    phead->pnext = ptemp;
                    //ptemp->pnext = phead;
                    //phead = ptemp;
                }
                strncpy(ptemp->name, pkg_name, sizeof(ptemp->name));
                strncpy(ptemp->verinfo, pkg_ver, sizeof(ptemp->verinfo));
                strncpy(ptemp->softarch, pkg_arch, sizeof(ptemp->softarch));
                add_count++;
            }
        }
    }

opfd_err:
    if(fp) {
        fclose(fp);
        fp = NULL;
    }

    
    /* todo rm */
    if (NULL != fpw) {
        fclose(fpw);
        fpw = NULL;
    }
    
    pall_softlist->syscount = add_count;
    printf("get_sys_save_softlist:666 add_count:%d,pall_softlist->syscount:%d.\n\n\n",add_count, pall_softlist->syscount);
    return phead;
}

void softlist_get_test()
{
    char err_msg[512] = { 0 };
    
    pall_softlist = (struct all_softlist_info *)malloc(sizeof(struct all_softlist_info));
    if (NULL == pall_softlist) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] malloc error.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
        system(err_msg);

        return -1;
    }

    pall_softlist->syscount = pall_softlist->tipcount = 0;
    pall_softlist->psyssoftlist = pall_softlist->ptipsoftlist = NULL;


}

int init_all_softlist_info_test(void)
{
    int ret = 0;
    int tip_soft_num = 0;
    char os_conf[64] = {'\0'};
    char err_msg[512] = { 0 };

    /* 首先执行此函数进行动态内存申请 */
    softlist_get_test();

    pall_softlist->psyssoftlist = get_sys_save_softlist(softlist_temp_file, &(pall_softlist->syscount));
    if (NULL == pall_softlist->psyssoftlist) {
        return -1;
    }
    strcpy(pall_softlist->os, "testsys");
    
    printf("\npall_softlist_test:pall_softlist->os=%s,pall_softlist->syscount:%d\n",pall_softlist->os,pall_softlist->syscount);
    ps_node ptemp = NULL;
    if (NULL != pall_softlist) 
    {
        if (NULL != pall_softlist->psyssoftlist) 
        {
            for (ptemp = pall_softlist->psyssoftlist; ptemp != NULL; ptemp = ptemp->pnext) 
            {
                printf("pall_softlist_test:ptemp->name:%s\n",ptemp->name);
                printf("pall_softlist_test:ptemp->verinfo:%s\n",ptemp->verinfo);
                printf("pall_softlist_test:ptemp->softarch:%s\n\n",ptemp->softarch);
            }
        }
    }

    return 0;
}

#define KEY_MANAGER_ADDR       "MANAGE_CENTER_ADDR"

int soft_multiversion_check_rpm11(const char* softname,int *checknum)
{
    int ret = 0;
    int line = 0;
    int lineflag = 0;
    char tmp_names1[512] = {'\0'};
    char tmp_names2[512] = {'\0'};
    char sline[512] = {'\0'};
    char cmd[1024] = {'\0'};
    FILE *sfp = NULL;
    FILE *sfpr = NULL;
    char err_msg[512] = { 0 };
    char rpm_name[512] = {'\0'};
    char key[64] = {'\0'};
    char val[256] = {'\0'};
    
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "export LANG=zh_CN.UTF-8;rpm -qa|grep '%s' > /opt/softmanager/tipterminal/var/soft_multi_tmp.txt",softname);
    system(cmd);

    printf("soft_multiversion_check_rpm:111 cmd=[%s],softname=[%s]\n",cmd,softname);
    sfp = fopen("/opt/softmanager/tipterminal/var/soft_multi_tmp.txt", "r");
    if (sfp == NULL) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d]sfp popen error.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
        system(err_msg);
        ret = -1;
        goto out;
    }

    while(!feof(sfp))
    {
        memset(sline, 0, sizeof(sline));
        if (fgets(sline, sizeof(sline), sfp) == NULL)
                break;
        
        memset(rpm_name, 0, sizeof(rpm_name));
        memcpy(rpm_name,sline,strlen(sline) - 1);            
        printf("soft_multiversion_check_rpm:222 line=%d,sline=[%s][%d],rpm_name=[%s][%d]\n\n",line,sline,strlen(sline),rpm_name,strlen(rpm_name));
        snprintf(cmd, sizeof(cmd), "export LANG=zh_CN.UTF-8;rpm -qi '%s'", rpm_name);
        printf("soft_multiversion_check_rpm:333 cmd=[%s]\n",cmd);
        sfpr= popen(cmd, "r");
        if (sfpr == NULL) {
            memset(err_msg, 0, sizeof(err_msg));
            snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d]sfpr popen error.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
            system(err_msg);
            ret = -2;
            goto out;
        }
        
        memset(sline, 0, sizeof(sline));
        memset(key, 0, sizeof(key));
        memset(val, 0, sizeof(val));
        memset(tmp_names1, 0, sizeof(tmp_names1));
        if (fgets(sline, sizeof(sline), sfpr) == NULL)
            break;
        if (sscanf(sline, "%[^:]: %s", key, val) != 2)
            continue;
        if (strncasecmp(key, "Name", sizeof("Name") - 1) == 0) {
            strncpy(tmp_names1, val, sizeof(tmp_names1));
        } 
        
        if (NULL != sfpr) {
            pclose(sfpr);
            sfpr = NULL;
        }
        
        if(strcmp(tmp_names1,softname) == 0)
        {
            line++;
        }
        printf("soft_multiversion_check_rpm:444 line=%d,sline=[%s][%d],tmp_names1=[%s][%d]\n\n",line,sline,strlen(sline),tmp_names1,strlen(tmp_names1));       
    }
    *checknum = line;

out:
    if (NULL != sfp) {
        fclose(sfp);
        sfp = NULL;
    }
    
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "rm -rf /opt/softmanager/tipterminal/var/soft_multi_tmp.txt");
    system(cmd);

    return ret;
}

int soft_multiversion_check_dpkg11(const char* softname,int *checknum)
{
    int ret = 0;
    int line = 0;
    char tmp_names[512] = {'\0'};
    char soft_namestmp[512] = {'\0'};
    char sline[512] = {'\0'};
    char cmd[1024] = {'\0'};
    FILE *sfp = NULL;
    FILE *sfpr = NULL;
    char key[64] = {'\0'};
    char val[256] = {'\0'};
    char err_msg[1024] = { 0 };
    
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "export LANG=zh_CN.UTF-8;dpkg -l|grep ^ii |grep '%s'|awk -F' ' '{print $2}' > /opt/softmanager/tipterminal/var/soft_multi_tmp.txt",softname);
    system(cmd);
    printf("soft_multiversion_check_dpkg:111 cmd=[%s],softname=%s\n",cmd,softname);
    
    sfp = fopen("/opt/softmanager/tipterminal/var/soft_multi_tmp.txt", "r");
    if (sfp == NULL) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] fopen error.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
        system(err_msg);
        ret = -1;
        goto out;
    }

    while(!feof(sfp))
    {
        memset(sline, 0, sizeof(sline));
        if (fgets(sline, sizeof(sline), sfp) == NULL)
                break;
        
        memset(tmp_names, 0, sizeof(tmp_names));
        memcpy(tmp_names,sline,strlen(sline)-1);
        printf("soft_multiversion_check_dpkg:222 line=%d,sline=[%s][%d],rpm_name=[%s][%d]\n\n",line,sline,strlen(sline),tmp_names,strlen(tmp_names));
        snprintf(cmd, sizeof(cmd), "export LANG=zh_CN.UTF-8;dpkg -s '%s'", tmp_names);
        printf("soft_multiversion_check_dpkg:333 cmd=[%s]\n",cmd);
        sfpr= popen(cmd, "r");
        if (sfpr == NULL) {
            memset(err_msg, 0, sizeof(err_msg));
            snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d]sfpr popen error.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
            system(err_msg);
            ret = -2;
            goto out;
        }
        
        memset(sline, 0, sizeof(sline));
        memset(key, 0, sizeof(key));
        memset(val, 0, sizeof(val));
        memset(soft_namestmp, 0, sizeof(soft_namestmp));
        if (fgets(sline, sizeof(sline), sfpr) == NULL)
            break;
        if (sscanf(sline, "%[^:]: %s", key, val) != 2)
            continue;
        if (strncasecmp(key, "Package", sizeof("Package") - 1) == 0) {
            strncpy(soft_namestmp, val, sizeof(soft_namestmp));
        } 
        
        if (NULL != sfpr) {
            pclose(sfpr);
            sfpr = NULL;
        }
        
        if(strcmp(soft_namestmp,softname) == 0)
        {
            line++;
        }
        printf("soft_multiversion_check_dpkg:444 line=%d,sline=[%s][%d],soft_namestmp=[%s][%d]\n",line,sline,strlen(sline),soft_namestmp,strlen(soft_namestmp));
    }    
    *checknum = line;
    printf("soft_multiversion_check_dpkg:555 line=%d,*checknum =[%d]\n",line,*checknum );

out:
    if (NULL != sfp) {
        fclose(sfp);
        sfp = NULL;
    }
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "rm -rf /opt/softmanager/tipterminal/var/soft_multi_tmp.txt");
    system(cmd);

    return ret;
}

int soft_multiversion_check_rpm(const char* softname,int *checknum)
{
    int ret = 0;
    int line = 0;
    char tmp_names1[512] = {'\0'};
    char sline[512] = {'\0'};
    char cmd[1024] = {'\0'};
    FILE *sfp = NULL;
    FILE *sfpr = NULL;
    char err_msg[1024] = { 0 };
    char rpm_name[512] = {'\0'};
    char key[64] = {'\0'};
    char val[256] = {'\0'};
    
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "export LANG=zh_CN.UTF-8;rpm -qa|grep '%s' > /opt/softmanager/tipterminal/var/soft_multi_tmp.txt",softname);
    system(cmd);

    sfp = fopen("/opt/softmanager/tipterminal/var/soft_multi_tmp.txt", "r");
    if (sfp == NULL) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d]sfp fopen error.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
        system(err_msg);
        ret = -1;
        goto out;
    }

    while(!feof(sfp))
    {
        memset(sline, 0, sizeof(sline));
        if (fgets(sline, sizeof(sline), sfp) == NULL)
                break;
        
        memset(rpm_name, 0, sizeof(rpm_name));
        memcpy(rpm_name,sline,strlen(sline) - 1);            
        snprintf(cmd, sizeof(cmd), "export LANG=zh_CN.UTF-8;rpm -qi '%s'", rpm_name);
        sfpr= popen(cmd, "r");
        if (sfpr == NULL) {
            memset(err_msg, 0, sizeof(err_msg));
            snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d]sfpr popen error.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
            system(err_msg);
            ret = -2;
            goto out;
        }
        
        memset(sline, 0, sizeof(sline));
        memset(key, 0, sizeof(key));
        memset(val, 0, sizeof(val));
        memset(tmp_names1, 0, sizeof(tmp_names1));
        if (fgets(sline, sizeof(sline), sfpr) == NULL)
            break;
        if (sscanf(sline, "%[^:]: %s", key, val) != 2)
            continue;
        if (strncasecmp(key, "Name", sizeof("Name") - 1) == 0) {
            strncpy(tmp_names1, val, sizeof(tmp_names1));
        } 
        
        if (NULL != sfpr) {
            pclose(sfpr);
            sfpr = NULL;
        }
        
        if(strcmp(tmp_names1,softname) == 0)
        {
            line++;
        }
    }
    *checknum = line;

out:
    if (NULL != sfp) {
        fclose(sfp);
        sfp = NULL;
    }
    
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "rm -rf /opt/softmanager/tipterminal/var/soft_multi_tmp.txt");
    system(cmd);

    return ret;
}

int soft_multiversion_check_dpkg(const char* softname,int *checknum)
{
    int ret = 0;
    int line = 0;
    char tmp_names[512] = {'\0'};
    char soft_namestmp[512] = {'\0'};
    char sline[512] = {'\0'};
    char cmd[1024] = {'\0'};
    FILE *sfp = NULL;
    FILE *sfpr = NULL;
    char key[64] = {'\0'};
    char val[256] = {'\0'};
    char err_msg[1024] = { 0 };
    
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "export LANG=zh_CN.UTF-8;dpkg -l|grep ^ii |grep '%s'|awk -F' ' '{print $2}' > /opt/softmanager/tipterminal/var/soft_multi_tmp.txt",softname);
    system(cmd);
    
    sfp = fopen("/opt/softmanager/tipterminal/var/soft_multi_tmp.txt", "r");
    if (sfp == NULL) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d] fopen error.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
        system(err_msg);
        ret = -1;
        goto out;
    }

    while(!feof(sfp))
    {
        memset(sline, 0, sizeof(sline));
        if (fgets(sline, sizeof(sline), sfp) == NULL)
                break;
        
        memset(tmp_names, 0, sizeof(tmp_names));
        memcpy(tmp_names,sline,strlen(sline)-1);
        snprintf(cmd, sizeof(cmd), "export LANG=zh_CN.UTF-8;dpkg -s '%s'", tmp_names);
        sfpr= popen(cmd, "r");
        if (sfpr == NULL) {
            memset(err_msg, 0, sizeof(err_msg));
            snprintf(err_msg, sizeof(err_msg), "echo \"%ld [%s:%d]sfpr popen error.\" >> /opt/softmanager/tipterminal/var/appif.log ", time(NULL), __func__, __LINE__);
            system(err_msg);
            ret = -2;
            goto out;
        }
        
        memset(sline, 0, sizeof(sline));
        memset(key, 0, sizeof(key));
        memset(val, 0, sizeof(val));
        memset(soft_namestmp, 0, sizeof(soft_namestmp));
        if (fgets(sline, sizeof(sline), sfpr) == NULL)
            break;
        if (sscanf(sline, "%[^:]: %s", key, val) != 2)
            continue;
        if (strncasecmp(key, "Package", sizeof("Package") - 1) == 0) {
            strncpy(soft_namestmp, val, sizeof(soft_namestmp));
        } 
        
        if (NULL != sfpr) {
            pclose(sfpr);
            sfpr = NULL;
        }
        
        if(strcmp(soft_namestmp,softname) == 0)
        {
            line++;
        }
    }    
    *checknum = line;

out:
    if (NULL != sfp) {
        fclose(sfp);
        sfp = NULL;
    }
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "rm -rf /opt/softmanager/tipterminal/var/soft_multi_tmp.txt");
    system(cmd);

    return ret;
}

/*******************************************************************************
* 函数名称: soft_multiversion_check
* 函数功能: 检查同一软件是否有多个存在，一般为不同版本
* 函数参数: softname
* 参数名称:          类型                     输入/输出     描述
*                   onst char*                softname     要检查的软件名
* 返回值: 0--回调函数触发成功；-1--未匹配到os；-2--软件检查失败；-3--软件未安装
* 函数类型: int
* 函数说明: 无
* -----------------------------------------------------------------
* 2021/12/20    liying      创建文件
*******************************************************************************/
int soft_multiversion_check(const char* softname)
{
    int ret = 0;
	char err_msg[512] = {0}; 
    int checknum = 0;
	char notify_msg[512] = {0};
	
	strncpy(notify_msg,softname,sizeof(notify_msg));
    printf("soft_multiversion_check:softname=[%s][%d],notify_msg=[%s][%d]\n",softname,strlen(softname),notify_msg,strlen(notify_msg));

    if (OS_PACK_RPM == ca_get_local_os_pack()) 
    {
        printf("soft_multiversion_check:RPM\n");
        ret = soft_multiversion_check_rpm(notify_msg,&checknum);
    } 
    else if (OS_PACK_DPKG == ca_get_local_os_pack()) 
    {
        printf("soft_multiversion_check:DPKG\n");
        ret = soft_multiversion_check_dpkg(notify_msg,&checknum);
    }
    else
    {
        memset(err_msg,0,sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"%ld [%s : %d] ca_get_local_os_pack err. \" >> /opt/softmanager/tipterminal/var/test.log ",
                    time(NULL),__func__, __LINE__);
        system(err_msg);
        ret = -1;
        goto out;
    }
    
    printf("\n soft_multiversion_check:ret=%d,checknum=%d\n",ret,checknum);
    
	memset(err_msg,0,sizeof(err_msg));
	snprintf(err_msg,sizeof(err_msg),"echo \"%ld [%s : %d] callback before,ret=%d,checknum=%d \" >> /opt/softmanager/tipterminal/var/test.log ",
	            time(NULL),__func__, __LINE__,ret,checknum);
	system(err_msg);

    if(0 != ret)
    {
        memset(err_msg,0,sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"%ld [%s : %d] soft_multiversion_check err. \" >> /opt/softmanager/tipterminal/var/test.log ",
                    time(NULL),__func__, __LINE__);
        system(err_msg);
        ret = -2;
        goto out;

    }
    
    if(checknum >= 2)
    {
        printf("soft_multiversion_check:checknum=%d,notify_msg=%s,softname=%s,trigger callback!!!!\n",checknum,notify_msg,softname);
        //ret = agent_local_get()->soft_multiver_check_callback(agent_local_get(), notify_msg, strlen(notify_msg)+1, NULL);
    }
    else if (checknum == 0)
    {
        printf("soft_multiversion_check:not installed soft checknum=%d,softname=%s,notify_msg=%s\n",checknum,notify_msg,softname);
        memset(err_msg,0,sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"%ld [%s : %d] not installed soft\" >> /opt/softmanager/tipterminal/var/test.log ",time(NULL),__func__, __LINE__);
        system(err_msg);
        ret = -3;        
        goto out;
    }
    else
    {
        printf("soft_multiversion_check:checknum=%d,notify_msg=%s,softname=%s\n",checknum,notify_msg,softname);
    }

out:

    return ret;
}


void strlen_test1(char* soft_installed_release)
{
    //strcpy(soft_installed_release,"adad2dw");
    int len1 = strlen(soft_installed_release);
    printf("\ntest1,len1=%d,soft_installed_release=[%s]\n",len1,soft_installed_release);
    return;
}


void strcpy_memcpy_test(void)
{
    int len1 = 0;
    int len2 = 0;
    char soft_installed_release[INFO_LENGTH] = {'\0'};
    char soft_installed_releasesum[5][INFO_LENGTH] = {"abcdfffsfesfe","ffab","vvvwwffffgggggg","abc","dw"};

    for(int index = 0;index < 5;index++)
    {
        strcpy(soft_installed_release,soft_installed_releasesum[index]);
        printf("strcpy_memcpy_test 111 ,soft_installed_release=[%s],index=%d\n",soft_installed_release,index);     
    }

    for(int index = 0;index < 5;index++)
    {
        memcpy(soft_installed_release,soft_installed_releasesum[index],sizeof(soft_installed_release));
        printf("strcpy_memcpy_test 222,soft_installed_release=[%s],index=%d\n",soft_installed_release,index);
    }

    
    memset(soft_installed_release, 0, sizeof(soft_installed_release));
    char *soft_release = NULL;
    strlen_test1(soft_installed_release);
    printf("strcpy_memcpy_test 333,soft_installed_release=[%s]\n",soft_installed_release);

    
    len1 = strlen(soft_installed_release);
    printf("strcpy_memcpy_test,len1=%d\n",len1);
    len2 = strlen(soft_release);
    printf("strcpy_memcpy_test,len2=%d\n",len2);

    return;
}

void system_test_return(void)
{
	char cmd[256] = {0};

	snprintf(cmd,sizeof(cmd),"rm -rf /etc/apt/sources.list111");
	if(system(cmd) == -1){
		printf("111 process delete orig conf failed!\n");
    }
    printf("222 process delete orig conf success!\n");
    return;
}

void user_name_test(char *user_name)
{
    if(user_name == NULL)
    {
        printf("111 user_name == NULL\n");
        return 0;
     }
     
    if((strcmp("auditadm",user_name) != 0) || (strlen("auditadm") != strlen(user_name)))
    {
        printf("222 user_name != auditadm\n");
        return 0;
    }
    
    printf("333 user_name_test\n");
    return;
}

unsigned long count_trigger_time1 = 0;
unsigned long count_trigger_time2 = 0;
int g_count_trigger_flag = 0;
int audit_home_page_callback(char *user_name)
{
    int ret = 0;
	char err_msg[2048] = {0};
    struct timeval time1;
    struct timeval time2;
    
    printf("soft_installed_count_callback,user_name=[%s].\n",user_name);
    if(user_name == NULL)
    {
        memset(err_msg,0,sizeof(err_msg));
		snprintf(err_msg,sizeof(err_msg),"echo \"user_name is NULL,return. %ld  [%s : %d]\" >> /opt/softmanager/tipterminal/var/test.log ",time(NULL),__func__,__LINE__);
        system(err_msg);        
        ret = -1;
        goto out;
    }
    
    if((strcmp("auditadm",user_name) != 0) || (strlen("auditadm") != strlen(user_name)))
    {
        ret = -2;
        printf("soft_installed_count_callback strcmp errr,ret=%d.\n",ret);
        goto out;
    }
    
    /* 频繁触发消息给GUI，GUI就会频繁查询数据库，数据库可能访问异常，考虑如何降低数据库查询频率 */
    
    if(g_count_trigger_flag == 0)
    {
        gettimeofday(&time1, 0);
        count_trigger_time1 = time1.tv_sec;
        g_count_trigger_flag = 1;
        printf("audit_home_page_callback,g_count_trigger_flag=%d,count_trigger_time1=%d callback===>111\n",g_count_trigger_flag,count_trigger_time1);
    }
    else
    {
        gettimeofday(&time2, 0);
        count_trigger_time2 = time2.tv_sec;
        printf("audit_home_page_callback,count_trigger_time2=%d\n",count_trigger_time2);
        if((count_trigger_time2 - count_trigger_time1) >= 2)
        {
            gettimeofday(&time1, 0);
            count_trigger_time1 = time1.tv_sec;
            printf("audit_home_page_callback,count_trigger_time1=%d callback===> callback===>222\n",count_trigger_time1);
        }
    }

out:
    printf("soft_installed_count_callback,ret=%d.\n\n",ret);

    return ret;
}


void audit_home_page_callback_test(void)
{
    char buff[300][30]={"auditadm","auditadm","audadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm",
                     "auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm",
                     "auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm",
                     "auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm",
                     "auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm",
                     "auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm",
                     "auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm",
                     "auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm",
                     "auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm",
                     "auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm","auditadm"};

    for(int i = 0; i < 300;i++)
    {
        audit_home_page_callback(buff[i]);
        sleep(1);
    }

}

void main()
{
    int index = 2;
    printf("main:index=%d\n",index);
    define_function_test(index++);


#if 0 
    va_start_test();
    audit_home_page_callback_test();
    strstr_test();
    if_else_if_test();

    init_all_softlist_info_test();
    strcpy_memcpy_test();
    soft_multiversion_check("zlib");
    
    pthread_test();
    abort_test();
    printf("main\n");
    
    fileno_test();

    popen_program_locale_test();


    fork_test();

    strtol_test();
    
    strtok_test();


    sscanf_test();

    int intem = 0;
    char *ptemp = "caccecwcw";
    {
        printf("main:111 %s\n",ptemp);


    }
    printf("main:222 %s\n",ptemp);



    ioctl_io();
    char *stringcode = (char *)malloc(20);
    strcpy(stringcode,"*ncd*cdsc*");
    char *string = strip_delimiter(stringcode,'*');
    printf("main: string:[%s]\n",string); /* main: string:[ncd*cdsc] */
    
    popen_run_program_test();

    crashHare();

    int retval = 0;
    int loc = 0;
    struct register_output *output = NULL;

    output = (struct register_output *)malloc(sizeof(struct register_output));

    addr_value_get_function(output);

    printf("main:output->result=%d,output->msg=%s\n\n",output->result,output->msg);
    
    httcsec_policy_unit_init_test();
    
    struct config_info_st *cfg_get = (struct config_info_st *)malloc(sizeof(struct config_info_st *));
    read_ver(cfg_get);
	printf("main:read_ver: version_info=%s,version_rel=%s,build_time=%s,build_os=%s \n",cfg_get->version_info,cfg_get->version_rel,cfg_get->build_time,cfg_get->build_os);

    struct sys_port *p = (struct sys_port *)malloc(sizeof(struct sys_port) * 30);
    retval = get_tcp_port(p, &loc);


    test_popen();


    while_test();


    retval = get_udp_port(p, loc);
    printf("main: get_tcp_port:p[0] port=%x,program=%s,proto=%s,loc=%d\n",p->port,p->program,p->proto,loc);
    p++;
    printf("main: get_tcp_port:p[1] port=%x,program=%s,proto=%s\n", p->port,p->program,p->proto);
    p++;
    printf("main: get_tcp_port:p[2] port=%x,program=%s,proto=%s\n", p->port,p->program,p->proto);
    p++;
    printf("main: get_tcp_port:p[3] port=%x,program=%s,proto=%s\n", p->port,p->program,p->proto);
    p++;
    printf("main: get_tcp_port:p[4] port=%x,program=%s,proto=%s\n", p->port,p->program,p->proto);
    p++;
    printf("main: get_tcp_port:p[5] port=%x,program=%s,proto=%s\n", p->port,p->program,p->proto);
    p++;
    printf("main: get_tcp_port:p[6] port=%x,program=%s,proto=%s\n", p->port,p->program,p->proto);
    p++;
    printf("main: get_tcp_port:p[7] port=%x,program=%s,proto=%s\n", p->port,p->program,p->proto);
    p += 7;
    printf("main: get_tcp_port:p[7+9] port=%x,program=%s,proto=%s\n", p->port,p->program,p->proto);
     
    get_exe_path_test();
    opendir_readdir_test();
    
    get_tcp_port_test();

    pragma_warning_func();

    retval = strtol_test();
    printf("main:数字（无符号长整数）是 %ld\n", retval);

    do_sys_port_get(pparm);
    printf("main:port=%d,program=%s,proto=%s\n", pparm->port,pparm->program,pparm->proto);

    unsigned char uid[50];
    memset(uid, 0x00, sizeof(uid));
    getOsDiskSymbol_uid_test(uid);
    printf("\nmain:uid=%s\n\n",uid);

    unsigned char mac[13];
    memset(mac, 0x00, sizeof(mac));
    getmac_test(mac, sizeof(mac));
    printf("main:mac=%s\n",mac);

    unsigned char soc[17];
    memset(soc, 0x00, sizeof(soc));
    getsoc_test(soc, sizeof(soc));
    printf("main:soc=%s\n",soc);

    unsigned char cpu[17];
    memset(cpu, 0x00, sizeof(cpu));
    getcpu_test(cpu, sizeof(cpu));
    printf("main:cpu=%s\n",cpu);

    
    rand_test();

	char buff[256] = "hello world";
    upper_test(buff);
	printf("upper_test:%s\n\n",buff);

	char *str="Hello World";
	char buff[256];
	printf("cpystr_test:%s\n\n",cpystr_test(buff,str));

    char linebufdd[1024];
    memset(linebufdd, 0x00, sizeof(linebufdd));
    memcpy(linebufdd,"a bm mmbb",10);
    retval = del_space(linebufdd);
	printf("del_space retval:%d,linebufdd:%s\n\n",retval,linebufdd);
	
    char linebuf[1024];
    memset(linebuf, 0x00, sizeof(linebuf));
    memcpy(linebuf,"abbmmmbb",8);
	erase_char_test(linebuf,'b');
	printf("erase_char_test linebuf：%s\n",linebuf);

    retval = writen_test("/home/ly/tst/pathtestf","ddddbbbbgggguuuummmm",19);
    printf("main writen_test: retval=%d\n",retval);
    char getstore[20] = {0};
    retval = readn_test("/home/ly/tst/pathtestf",getstore,25);
    printf("main readn_test: retval=%d,getstore=%s\n",retval,getstore);
    
 
    math_test();


    string_valid_check("ada_bbtbb_F2-c.c");
    string_valid_check("_bbtbb_cfcc");
    string_valid_check("ada__cfcc");
    string_valid_check("ada_bbtbb_cfcccbbbbbb");
    string_valid_check("_bbtbb222222dd_cfcc");
    string_valid_check("_bbtbb_");
    string_valid_check("ada__");
    string_valid_check("__");
    string_valid_check("adffffffffffddd_bbtbfffffffdddb_cfcfccbddbbbbb");
    
    string_valid_check("查__查查查查");
    

    test_mallocaddr_struct_information();
    
    test_fun();
    test_str_sub_str_len();


    test_notify_callback();
    
    test_define_swap();
    
    test_struct_param_get();
    test_time();
    test_popen();

#endif

}


