#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pthread.h>
#include<unistd.h>
#include<stdarg.h>
#include <ctype.h>

//#define NAME_UNIQID_PATH "/home/ly/test/namefile"
#define NAME_UNIQID_PATH "/home/liying/develop/pthread/namefile"
#define NAME_UNIQID_LEN   256
#define NAME_UNIQID_COUNT   1000

static pthread_mutex_t g_mutex_lock;

/* 声明结构体 */
typedef struct name_uniqid
{
    char name[NAME_UNIQID_LEN];
    char uniqid[NAME_UNIQID_LEN];
}Name_uniqid;     

/* 函数功能：保存需要注册的不同的文件的name、uniqid到指定文件的接口
     返回值：0--正常文件； 606--获取配置信息失败；610--入参异常； 611--文件操作异常； 
                612--空文件； 613--status码异常； 614--文件格式都合法但是md5不对； 其他值--
status码值 */
int name_uniqid_save(const char* path)
{    
    FILE *fpr = NULL, *fps = NULL;
    char buff[NAME_UNIQID_LEN] = {0};
    char name[NAME_UNIQID_LEN] = {0};
    char uniqid[NAME_UNIQID_LEN] = {0};
    char err_msg[1024] = { 0 };
    char *temp = NULL;
    char chartemp[10] = {0};
    int count = 0;
    int ret = 0xff;
    int i = 0;
    int intflag = 0;
    struct config_info_st *cfg = NULL;
    unsigned char tmps[16] = {0};
    unsigned char tmpd[32] = {0};
	
    if (NULL == path){
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"input path error, path = %p. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",path,time(NULL),__func__, __LINE__);
        system(err_msg);
		ret = 610;
		goto out;
    }

    fpr = fopen(path, "r");
	if (fpr == NULL) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"fopen fpr error. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
        system(err_msg);
		ret = 611;
		goto out;
	}
    fps = fopen(NAME_UNIQID_PATH, "a");
	if (fps == NULL) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"fopen fps error. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
        system(err_msg);
		ret = 611;
		goto out;
	}
	
#if 0  //工程中校验文件头使用 
    cfg = config_get(CONF_READ);
    if(cfg)
    {
        //ret = md5_file(cfg->nodeid, tmps);
        md5_file_mmap(cfg->nodeid,16,tmps);

        for(i=0; i<16; i++) {
            sprintf(tmpd+2*i,"%02X",tmps[i]);
        }
    }
    else
    {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"config_get error. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
        system(err_msg);
        ret = 606; /* 获取配置信息失败 */
        goto out;
    }
#endif

    while(!feof(fpr))
    {
        if(fgets(buff,sizeof(buff),fpr) == NULL)
        {
            if(0 == count)
            {
                ret = 612; /* 文件为空时返回612 */
                goto out;
            }
            else
            {
                break;
            }
        }
        else
        {
            if(0 == count)
            {
                if(temp = strstr(buff,"status"))
                {
                    memcpy(chartemp,temp + 11,1);
                    if(!strcmp(&chartemp[0],","))
                    {
                        memset(chartemp,0,10);
                        memcpy(chartemp,temp + 8,3);
                        for(i = 0;i < 3;i++)
                        {
                            if(!isdigit(chartemp[i]))
                            {
                                intflag++;
                                ret = 613; /* 文件不正常且status码值异常时返回 */
                                break;
                            }
                        }
                        if(0 == intflag)
                        {
                            ret = atoi(chartemp); /* 文件不正常时返回status码值 */
                        }
                    }
                    else
                    {
                        ret = 613; /*  文件不正常且status码值异常时返回 */
                    }
                    goto out;
                }
                else
                {
                    #if 0  //工程中校验文件头使用 
                    if(!strncasecmp(buff,tmpd,strlen(tmpd)))
                    {
                        ret = 0; /* 文件正常时返回0 */
                    }
                    else
                    {
                        ret = 614; /* 文件格式都合法但是md5不对时返回614 */
                        goto out;
                    } 
                    #endif
                    
                    ret = 0; /* 文件正常时返回0 */
                }
            }
        }

        count++;
        if(1 == count)
        {
            continue;
        }
        else if(1000 <= count) /* 数据量很大时 */
        {
            count = 2;
        }
        sscanf(buff, "%s", name);
        fputs(name,fps);
        fputs("\n",fps);

        if(fgets(buff,sizeof(buff),fpr) == NULL)
            break;
        sscanf(buff, "%s", uniqid);
        fputs(uniqid,fps);
        fputs("\n",fps);
    }

out:
    if (fpr) fclose(fpr);
    if (fps) fclose(fps);

    return ret;
}

int name_uniqid_get_mutex(const char* pname,char* puniqid)
{
	FILE *fp = NULL;
    char buff[NAME_UNIQID_LEN] = {0};
	char name[NAME_UNIQID_LEN] = {0};
	char uniqid[NAME_UNIQID_LEN] = {0};
    char err_msg[1024] = { 0 };
    int count = 0;
	int ret = 0;
	
    if ((NULL == pname) || (NULL == puniqid)){
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"input error,pname = %p. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",pname,time(NULL),__func__, __LINE__);
        system(err_msg);
		ret = -1;
		goto out;
    }
    
    pthread_mutex_lock(&g_mutex_lock);    

    fp = fopen(NAME_UNIQID_PATH, "r");
	if (fp == NULL) {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"fopen fp failed. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",time(NULL),__func__, __LINE__);
        system(err_msg);
		ret = -1;
		goto out;
	}

    while(!feof(fp))
    {
        if(fgets(buff,sizeof(buff),fp) == NULL)
            break;
        count++;
        if(1 == count)
        {
            continue;
        }
        else if(NAME_UNIQID_COUNT <= count) /* 数据量很大时 */
        {
            count = 2;
        }
        sscanf(buff, "%s", name);
        if(strcmp(pname,name) == 0)
        {
            if(fgets(buff,sizeof(buff),fp) == NULL)
                break;
            sscanf(buff, "%s", uniqid);
            strcpy(puniqid,uniqid);
            break;
        }
        
        if(fgets(buff,sizeof(buff),fp) == NULL)
             break;
    }
    pthread_mutex_unlock(&g_mutex_lock);

    if(0 == strlen(puniqid))
    {
        memset(err_msg, 0, sizeof(err_msg));
        snprintf(err_msg,sizeof(err_msg),"echo \"not find name=%s. %ld [%s:%d]\" >> /opt/softmanager/tipterminal/var/appif.log ",pname,time(NULL),__func__, __LINE__);
        system(err_msg);
		ret = -1;
		goto out;
    }
    
out:
    if (fp) fclose(fp);

    return ret;
}

int name_uniqid_get(const char* pname,char* puniqid)
{
    char buff[NAME_UNIQID_LEN] = {0};
	char name[NAME_UNIQID_LEN] = {0}; 
	char uniqid[NAME_UNIQID_LEN] = {0};     
    int count = 0;
    
    if ((NULL == pname) || (NULL == puniqid)){
        printf("%s:input error,please again.\n",__FUNCTION__);
        return -1;
    }

    FILE *fp = fopen(NAME_UNIQID_PATH, "r");
	if (fp == NULL) {
        printf("fopen file failed.\n");
		return -1;
	}

    while(!feof(fp))
    {
        if(fgets(buff,sizeof(buff),fp) == NULL)
            break;
        count++;
        if(1 == count)
        {
            continue;
        }
        else if(NAME_UNIQID_COUNT <= count) /* 数据量很大时 */
        {
            count = 2;
        }
        sscanf(buff, "%s", name);
        if(strcmp(pname,name) == 0)
        {
            if(fgets(buff,sizeof(buff),fp) == NULL)
                break;
            sscanf(buff, "%s", uniqid);
            strcpy(puniqid,uniqid);
            break;
        }
        
        if(fgets(buff,sizeof(buff),fp) == NULL)
             break;
    }
	fclose(fp);
	
    if(0 == strlen(puniqid))
    {
        printf("not find name:%s,return -1.\n",pname);
        return -1;
    }

	return 0;
}

/* 定义线程函数 name_uniqid_thread */
static void *name_uniqid_thread0(void* pName_UniqidInfo)
{
    char uniqid[NAME_UNIQID_LEN] = {};
    if (NULL == pName_UniqidInfo){
        printf("%s:input error,please again.\n",__FUNCTION__);
        return 0;
    }

    Name_uniqid* pName_Uniqid = (Name_uniqid*)pName_UniqidInfo;
    
    /* 线程pthread开始运行 */
    pthread_mutex_lock(&g_mutex_lock);    
    name_uniqid_get(pName_Uniqid->name,uniqid);
    pthread_mutex_unlock(&g_mutex_lock);
    
    strcpy(pName_Uniqid->uniqid,uniqid);
    printf("%s:uniqid:%s,pName_Uniqid->uniqid:%s\n",__FUNCTION__,uniqid,pName_Uniqid->uniqid);
    /* 令主线程继续执行 */
    //sleep(1);
    return 0;
}

/* 定义线程函数 name_uniqid_thread */
static void *name_uniqid_thread1(void* pName_UniqidInfo)
{
    char uniqid[NAME_UNIQID_LEN] = {};
    if (NULL == pName_UniqidInfo){
        return 0;
    }

    Name_uniqid* pName_Uniqid = (Name_uniqid*)pName_UniqidInfo;
    
    /* 线程pthread开始运行 */
    pthread_mutex_lock(&g_mutex_lock);    
    name_uniqid_get(pName_Uniqid->name,uniqid);
    pthread_mutex_unlock(&g_mutex_lock);
    
    strcpy(pName_Uniqid->uniqid,uniqid);
    printf("%s:uniqid:%s,pName_Uniqid->uniqid:%s\n",__FUNCTION__,uniqid,pName_Uniqid->uniqid);
    return 0;
}

/* 定义线程函数 name_uniqid_thread */
static void *name_uniqid_thread2(void* pName_UniqidInfo)
{
    char uniqid[NAME_UNIQID_LEN] = {};
    if (NULL == pName_UniqidInfo){
        return 0;
    }

    Name_uniqid* pName_Uniqid = (Name_uniqid*)pName_UniqidInfo;
    
    /* 线程pthread开始运行 */
    pthread_mutex_lock(&g_mutex_lock);    
    name_uniqid_get(pName_Uniqid->name,uniqid);
    pthread_mutex_unlock(&g_mutex_lock);
    
    strcpy(pName_Uniqid->uniqid,uniqid);
    printf("%s:uniqid:%s,pName_Uniqid->uniqid:%s\n",__FUNCTION__,uniqid,pName_Uniqid->uniqid);        
    return 0;
}

/* 互斥锁初始化函数 */
int name_uniqid_mutex_init(void)
{
    int ret = 0;
    
    ret = pthread_mutex_init(&g_mutex_lock, NULL);
    if (ret != 0) {
        printf("mutex init failed\n");
        return -1;
    }
    return 0;
}
/* 互斥锁释放函数 */
int name_uniqid_mutex_destroy(void)
{
    int ret = 0;
    pthread_mutex_destroy(&g_mutex_lock);
    return 0;
}

void process_info(void)
{
    FILE *fp = NULL;
    char file[32] = {0};
    char line[1024] = {0};
    unsigned char key[16] = {0};
    unsigned char value[16] = {0};
	unsigned char name[16];
	unsigned char user[32];
    sprintf(file, "/proc/%d/status", 157);
    char err_msg[1024] = { 0 };

    if ((fp=fopen(file, "r")) != NULL) 
    {
        while (fgets(line, sizeof(line), fp) != NULL) 
        {
            sscanf(line, "%15s %15s", key, value);
            memset(err_msg, 0, sizeof(err_msg));
            snprintf(err_msg,sizeof(err_msg),"echo \"111 key=%s  value=%s\"  2>&1",key,value);
            system(err_msg);
            if (strcmp(key, "Name:") == 0) {
                strcpy(name, value);
                memset(err_msg, 0, sizeof(err_msg));
                snprintf(err_msg,sizeof(err_msg),"echo \"222 key=%s  value=%s\"  2>&1",key,value);
                system(err_msg);
            } else if (strcmp(key, "Uid:") == 0) {
                strcpy(user, value);
                memset(err_msg, 0, sizeof(err_msg));
                snprintf(err_msg,sizeof(err_msg),"echo \"333 key=%s  value=%s\"  2>&1",key,value);
                system(err_msg);
                break;
            }
            memset(line, 0, sizeof(line));
        }
        fclose(fp);
    }
    memset(err_msg, 0, sizeof(err_msg));
    snprintf(err_msg,sizeof(err_msg),"echo \"444 key=%s  value=%s\"  2>&1",key,value);
    system(err_msg);


}

/* main函数 */
int main(void)
{

    //process_info();

#if 1
    /*
    char err_msg[1024] = { 0 };
    
    memset(err_msg, 0, sizeof(err_msg));
    snprintf(err_msg,sizeof(err_msg),"echo \"check start, path = %p. %ld [%s:%d]\" >> /home/liying/develop/pthread/appif.log ",path,time(NULL),__func__, __LINE__);
    system(err_msg);
    
    memset(err_msg, 0, sizeof(err_msg));
    snprintf(err_msg,sizeof(err_msg),"ls -lh >> /home/liying/develop/pthread/appif.log ");
    system(err_msg);
    
    memset(err_msg, 0, sizeof(err_msg));
    snprintf(err_msg,sizeof(err_msg),"ls -lh 2>&1");
    system(err_msg);
    
    int checkid = 0;
    checkid = name_uniqid_check("/home/liying/develop/pthread/namefilecheck");
    printf("%s: return value:%d\n",__FUNCTION__,checkid);
    */
    
    int ret = 0;
    int Index  = 0;
    int Saveindex  = 0;
    char name[NAME_UNIQID_LEN] = {};
    char uniqid[NAME_UNIQID_LEN] = {};
    //char names_uniqid_path[5][NAME_UNIQID_LEN] = {"/home/ly/test/namefilea","/home/ly/namefileb"};
    char names_uniqid_path[5][NAME_UNIQID_LEN] = {"/home/liying/develop/pthread/namefilea","/home/liying/develop/namefileb"};
    pthread_t tidp[3];
    Name_uniqid* pname_uniqid = (Name_uniqid*)malloc(sizeof(Name_uniqid));    
    memset(pname_uniqid,0,sizeof(Name_uniqid));
    Name_uniqid* pname_uniqid1 = (Name_uniqid*)malloc(sizeof(Name_uniqid));    
    memset(pname_uniqid1,0,sizeof(Name_uniqid));
    Name_uniqid* pname_uniqid2 = (Name_uniqid*)malloc(sizeof(Name_uniqid));    
    memset(pname_uniqid2,0,sizeof(Name_uniqid));

    /* 写测试 */
    //ret = name_uniqid_save(names_uniqid_path[0]);
    //printf("%s: return value ret:%d\n",__FUNCTION__,ret);
    
    
    ret = pthread_mutex_init(&g_mutex_lock, NULL);
    if (ret != 0) {
        printf("mutex init failed\n");
        return -1;
    }
    /* 读测试 */
    for(Index = 0;Index < 1;Index++)
    {
#if 1  /* 1、直接调用获取接口，锁放在接口内*/
        memcpy(name,"zhangsan",8);
        if(name_uniqid_get_mutex(name,uniqid) != 0)
        {
            printf("%s:get failed,return.\n",__FUNCTION__);
            return -1;
        }
        printf("%s:direct get mutex pname:%s,uniqid:%s\n\n",__FUNCTION__,name,uniqid);
        memset(uniqid,0,NAME_UNIQID_LEN);
#else  /* 2、通过线程调用获取 */
        /* 为结构体变量pname_uniqid赋值 */
        strcpy(pname_uniqid->name,"zhangsan");
        /* 创建线程 name_uniqid_thread */
        if ((pthread_create(&tidp[0], NULL, name_uniqid_thread0, (void*)pname_uniqid)) == -1)
        {
            printf("create error!\n");
            return -1;
        }
        
        /* 为结构体变量pname_uniqid1赋值 */
        strcpy(pname_uniqid1->name,"lisi");
        /* 创建线程 name_uniqid_thread */
        if ((pthread_create(&tidp[1], NULL, name_uniqid_thread1, (void*)pname_uniqid1)) == -1)
        {
            printf("create error!\n");
            return -1;
        }
        
        /* 为结构体变量pname_uniqid2赋值 */
        strcpy(pname_uniqid2->name,"maliu");
        /* 创建线程 name_uniqid_thread */
        if ((pthread_create(&tidp[2], NULL, name_uniqid_thread2, (void*)pname_uniqid2)) == -1)
        {
            printf("create error!\n");
            return -1;
        }

        /* 令线程name_uniqid_thread先运行 */
        sleep(1);
        printf("%s:Index:%d,thread get pname_uniqid->uniqid:%s\n",__FUNCTION__,Index,pname_uniqid->uniqid);
        printf("%s:Index:%d,thread get pname_uniqid1->uniqid:%s\n",__FUNCTION__,Index,pname_uniqid1->uniqid);
        printf("%s:Index:%d,thread get pname_uniqid2->uniqid:%s\n\n",__FUNCTION__,Index,pname_uniqid2->uniqid);

        /* 等待线程name_uniqid_thread释放 */
        if (pthread_join(tidp[0],NULL))        
        {
            printf("thread0 is not exit...\n");
            return -2;
        }
        /* 等待线程name_uniqid_thread释放 */
        if (pthread_join(tidp[1],NULL))        
        {
            printf("thread1 is not exit...\n");
            return -2;
        }
        /* 等待线程name_uniqid_thread释放 */
        if (pthread_join(tidp[2],NULL))        
        {
            printf("thread2 is not exit...\n");
            return -2;
        }
#endif
    }
    pthread_mutex_destroy(&g_mutex_lock);
    
    free(pname_uniqid);
    free(pname_uniqid1);
    free(pname_uniqid2);
#endif
    return 0;
}

