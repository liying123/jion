#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>

/*
    项目开发过程中经常需要读取目录下所有文件，故总结此递归读取文件夹下所有文件的示例程序以作备忘。
*/
int read_dir_r(char *path)
{
    DIR *dp = NULL;
    struct dirent *st;
    struct stat sta;
    int ret = 0;
    char tmp_name[1024]={0};
    
    dp = opendir(path);
    if(dp == NULL)
    {
        printf("open dir error!!\n");
        return -1;
    }
    
    while(1)
    {
        st = readdir(dp);
        if(NULL == st) //读取完毕
        {
            printf("readdir,NULL == st\n");
            break;
        }
        strcpy(tmp_name, path);
        if(path[strlen(path)-1] != '/') //判断路径名是否带/
        {
            strcat(tmp_name,"/");
        }
        strcat(tmp_name,st->d_name);  //新文件路径名
        //printf("first:%s\n",tmp_name);
        
        ret = stat(tmp_name, &sta); //查看目录下文件属性
        if(ret < 0)
        {
            printf("read stat fail\n");
            return -1;
        }
        if(S_ISDIR(sta.st_mode)) //如果为目录文件
        {
            if( 0 == strcmp("..",st->d_name) || 0 == strcmp(".",st->d_name)) //忽略当前目录和上一层目录
            {
                continue;
            }
            else
            {
                read_dir_r(tmp_name);  //递归读取
            }
        }
        else //不为目录则打印文件路径名
        {
            printf("%s\n",tmp_name);
        }
    }
    closedir(dp);
    return 0;
}
 
int main(int argc,char *argv[])
{
    read_dir_r("./test"); //打印当前test目录下所有的文件路径
    return 0;
}

/*
运行结果：
./test/struct_unoin.c
./test/control
./test/trsfile.c
./test/test11
./test/test.c
./test/list.c
./test/processdaemon.c.bak
./test/makefile
./test/sys_soft_installed_sum.txt
./test/bintree.c
./test/namefile
./test/addr.c
./test/test
./test/gdbtest.c
./test/doublelist.c
./test/sedtest.txt
./test/list


*/
