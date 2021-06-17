#ifndef _RSFILE_H
#define _RSFILE_H

#ifdef __cplusplus
extern "C"{
#endif


/* 通过name获取uniqid函数 */
int name_uniqid(const char* pname,char* puniqid);
int name_uniqid_get_impl(const char* pname,char* puniqid);

/* 互斥锁初始化函数 */
int name_uniqid_mutex_init(void);
/* 互斥锁释放函数 */
int name_uniqid_mutex_destroy(void);

#ifdef __cplusplus
}
#endif


#endif
