#include "uniqid_impl.h"

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


void main()
{
    char *name = "zhangsan";
    char uniqid[256] = {};    
    int retval = 0;

    
    test_define_swap();
    
#if 0
    test_struct_param_get();
    test_time();
    test_popen();

    retval = name_uniqid_impl(name,uniqid);
    if(retval == 0)
    {
        printf("main:retval:%d,uniqid:%s\n",retval,uniqid);
    }
    else
    {
        printf("main:retval:%d\n",retval);
    }
#endif

}
