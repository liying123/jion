#include <stdio.h>

/* struct union */
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
union bit32_data
{
	uint32_t data;
	struct
	{
		uint8_t byte0;
		uint8_t byte1;
		uint8_t byte2;
		uint8_t byte3;
	}byte;
};

/* 位移操作 */
#define GET_LOW_BYTE0(x)   ((x >> 0) & 0x000000ff)  /* 获取第0个字节 */
#define GET_LOW_BYTE1(x)   ((x >> 8) & 0x000000ff)  /* 获取第1个字节 */
#define GET_LOW_BYTE2(x)   ((x >> 16) & 0x000000ff)  /* 获取第2个字节 */
#define GET_LOW_BYTE3(x)   ((x >> 24) & 0x000000ff)  /* 获取第3个字节 */


int main(void)
{
	union bit32_data num;
	unsigned int a = 0x12345678;

	num.data = 0x12345678;
	printf("struct_union \n");
	printf("byte0=0x%x \n",num.byte.byte0);
	printf("byte1=0x%x \n",num.byte.byte1);
	printf("byte2=0x%x \n",num.byte.byte2);
	printf("byte3=0x%x \n",num.byte.byte3);
	
	printf("位移操作 \n");
	printf("byte0=0x%x \n",GET_LOW_BYTE0(a));
	printf("byte1=0x%x \n",GET_LOW_BYTE1(a));
	printf("byte2=0x%x \n",GET_LOW_BYTE2(a));
	printf("byte3=0x%x \n",GET_LOW_BYTE3(a));

	/*
		struct_union 小端:低地址存放数据的低字节；高地址存放数据的高字节
		byte0=0x78 低
		byte1=0x56 
		byte2=0x34 
		byte3=0x12 高
		位移操作 
		byte0=0x78 
		byte1=0x56 
		byte2=0x34 
		byte3=0x12 
	*/

	return 0;
}

