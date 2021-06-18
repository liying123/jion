#include<stdio.h>
void increment(int *i){i++;}

void func(char t[])
{
	printf("fun :sizeof(t)=%d\n",(int)sizeof(t));
}

void ppp(int *j)
{
	printf("ppp :&j=0x%x\n",&j);
	j++;
}
int g_u32Sendbuf[10] = {0};

void addr(void)
{
	int i = 0 ;
	int *Sendbuff = NULL;
	
	for(i = 0 ;i < 10; i++)
	{
		g_u32Sendbuf[i] = 0;
	}

	//printf("111 Sendbuff:%d \n",*Sendbuff);
	Sendbuff = &g_u32Sendbuf[0];
	for(i = 0 ;i < 10; i++)
	{
		printf("111 i=%d,g_u32Sendbuf[%d]:%d \n",i,i,g_u32Sendbuf[i]);
	}
	printf("111 Sendbuff:%d \n\n",*Sendbuff);


	//*Sendbuff++;	
	//printf("222 Sendbuff:%d\n",*Sendbuff);
	*(++Sendbuff) = 2;	
	printf("222 Sendbuff:%d\n",*Sendbuff);
	*(++Sendbuff) = 3;
	printf("222 Sendbuff:%d\n",*Sendbuff);
	for(i = 0 ;i < 10; i++)
	{
		printf("222 i=%d,g_u32Sendbuf[%d]:%d \n",i,i,g_u32Sendbuf[i]);
	}
	printf("222 Sendbuff:%d,Sendbuff:%d,Sendbuff:%d.\n\n",*Sendbuff,*(Sendbuff+1),*(Sendbuff+2));
	printf("222 Sendbuff:%d,*Sendbuff++:%d,*(Sendbuff+1):%d \n\n",
				*Sendbuff,*Sendbuff++,*(Sendbuff+1));


	Sendbuff = &g_u32Sendbuf[0];
	for(i = 0 ;i < 10; i++)
	{
		printf("333 i=%d,g_u32Sendbuf[%d]:%d \n",i,i,g_u32Sendbuf[i]);
	}
	printf("333 Sendbuff:%d,Sendbuff:%d,Sendbuff:%d.\n\n",*Sendbuff,*(Sendbuff+1),*(Sendbuff+2));

}

int main(void)
{
#if 0
	int arr[] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	int *i = &arr[1];
	printf("arr-addr=0x%x,i-addr=0x%x,*i=0x%x \n",arr,i,*i);
	increment(i);
	printf("i-addr=0x%x,*i=0x%x \n",i,*i);

	char a[] = "hello";
	char *p = "world";
	printf("111sizeof(a)=%d\n",(int)sizeof(a));
	printf("222 sizeof(p)=%d\n",(int)sizeof(p));
	func(a);
	a[0] = 'X';
	printf("a=%s\n",a);
	//a++;
	//p[0] = 'X';
#endif
	int i = 100;

	addr();

	printf("111 :i=%d\n",i);
	printf("222 :&i=0x%x\n\n",&i);
	ppp(i);
	printf("ppp(i)\n");
	printf("333 :i=%d\n",i);
	printf("444 :&i=0x%x\n\n",&i);
	ppp(&i);
	printf("ppp(&i)\n");
	printf("333 :i=%d\n",i);
	printf("444 :&i=0x%x\n",&i);

	return 0;
}
