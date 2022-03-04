#if 0
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static pthread_mutex_t g_mutex_lock;
static int g_count = 0;

static void *thread_fun_1(void *data)
{
    pthread_mutex_lock(&g_mutex_lock);

    g_count++;
    printf("%s g_count: %d\n", __func__, g_count);

    pthread_mutex_unlock(&g_mutex_lock);
}

static void *thread_fun_2(void *data)
{
    pthread_mutex_lock(&g_mutex_lock);

    g_count++;
    printf("%s g_count: %d\n", __func__, g_count);

    pthread_mutex_unlock(&g_mutex_lock);
}

static void *thread_fun_3(void *data)
{
    pthread_mutex_lock(&g_mutex_lock);

    g_count++;
    printf("%s g_count: %d\n", __func__, g_count);

    pthread_mutex_unlock(&g_mutex_lock);
}

int main(int argc, char const *argv[])
{
    int ret;
    pthread_t pid[3];

    ret = pthread_mutex_init(&g_mutex_lock, NULL);
    if (ret != 0) {
        printf("mutex init failed\n");
        return -1;
    }

    pthread_create(&pid[0], NULL, thread_fun_1, NULL);
    pthread_create(&pid[1], NULL, thread_fun_2, NULL);
    pthread_create(&pid[2], NULL, thread_fun_3, NULL);

    pthread_join(pid[0], NULL);
    pthread_join(pid[1], NULL);
    pthread_join(pid[2], NULL);

    pthread_mutex_destroy(&g_mutex_lock);

    return 0;
}

#endif

#if 0
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static int g_count = 0;

static void *thread_fun_1(void *data)
{
    g_count++;
    printf("%s g_count: %d\n", __func__, g_count);
}

static void *thread_fun_2(void *data)
{
    g_count++;
    printf("%s g_count: %d\n", __func__, g_count);
}

static void *thread_fun_3(void *data)
{
    g_count++;
    printf("%s g_count: %d\n", __func__, g_count);
}

int main(int argc, char const *argv[])
{
    pthread_t pid[3];
    
    pthread_create(&pid[0], NULL, thread_fun_1, NULL);
    pthread_create(&pid[1], NULL, thread_fun_2, NULL);
    pthread_create(&pid[2], NULL, thread_fun_3, NULL);

    pthread_join(pid[0], NULL);
    pthread_join(pid[1], NULL);
    pthread_join(pid[2], NULL);

    return 0;
}
#endif

#if 0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define NAME_UNIQID_PATH_I "/home/ly/test/namefile.txt"

int name_search_uniqidt(char* pname,char* puniqid)
{
    char buff[64] = {0};
	char name[64] = {0}; 
	char uniqid[64] = {0};     
    int count = 0;

    FILE *fp = fopen(NAME_UNIQID_PATH_I, "r");
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
        //sscanf(buff, "%s", uniqid);
        //printf("name:%s; uniqid:%s\n\n",name,uniqid);
    }
	fclose(fp);

	return 0;
}

int main()
{	
    char name[64] = {};
    char uniqid[64] = {};
    char names[5][64] = {"zhangsan","lisi","maliu","ouwen"};
    
    memcpy(name,"zhangsan",8);
    name_search_uniqidt(name,uniqid);
    printf("%s111:uniqid:%s\n",__FUNCTION__,uniqid);
    memset(uniqid,0,64);
    memset(name,0,64);
    memcpy(name,names[2],strlen(names[2]));
    name_search_uniqidt(name,uniqid);
    printf("%s222:uniqid:%s\n",__FUNCTION__,uniqid);

    return 0;
}
#endif

#include <stdio.h>
#include <string.h>
 
 
int main()
{
    const char haystack1[256] = "1 {\"status\":666, \"message\":\"data is null\"}";
    const char haystack2[256] = "1 {\"timestamp\":\"2021-05-25T07:40:42.106+0000\",\"status\":500,\"error\":\"Internal Server Error\",\"message\":\"No message available\",\"path\":\"/httc/genLicService\"}";
    const char needle[64] = "status";
    char *ret;
    char chartemp[5] = {0};
    int rettemp = 0;
    unsigned char tmps[16] = "1111222233334444";
    unsigned char tmpd[32] = {0};
    unsigned char tmpd1[32] = {0};
    int i = 0;
   
    printf("tmps:%s\n",tmps);
    for(i=0; i<16; i++) {
        sprintf(tmpd+2*i,"%02X",tmps[i]);
    }
    printf("tmpd:%s;tmps:%s\n", tmpd,tmps);
    
    for(i=0; i<16; i++) {
        sprintf(&tmpd1[2*i],"%02X",tmps[i]);
    }
    printf("tmpd1:%s;tmps:%s\n", tmpd1,tmps);

    #if 0
    ret = strstr(haystack1, needle);
    printf("111子字符串是： %s\n", ret+8);
    memcpy(chartemp,ret+8,3);
    printf("111子字符串是： %s\n", chartemp);
    rettemp = atoi(chartemp);
    printf("111子字符串是： %d\n", rettemp);

    ret = strstr(haystack2, needle);
    printf("222子字符串是： %s\n", ret+8);
    memcpy(chartemp,ret+8,3);
    printf("222子字符串是： %s\n", chartemp);
    rettemp = atoi(chartemp);
    printf("111子字符串是： %d\n", rettemp);
#endif
    return(0);
}


