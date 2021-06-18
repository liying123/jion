#include <stdio.h>
/* 指针域prior  、数据域data、指针域next */

/* 1、双链表结点定义 */
/*	数据元素类型 */
typedef int Type;
/* 双链表结点结构体 */
typedef struct _DListnode
{
	struct _DListnode *prior; /* 指向直接前驱结点 */
	struct _DListnode *next; /* 指向直接后继结点 */
	Type data; /*数据*/
}DListNode;

/* 2、相关操作示例 */
/* 函数声明 */
static DListNode *dlist_create(void);
static int dlist_find(DListNode *dlist,Type find_data);
static DListNode *dlist_change(DListNode *dlist,int pos, Type new_data);
static DListNode *dlist_insert(DListNode *dlist, Type insert_data, int pos);
static DListNode *dlist_delete(DListNode *dlist, Type del_data);
static void dlist_print_int(DListNode *dlist);
#define LEN 5

static void dlist_print_int(DListNode *dlist)
{
	DListNode *current = dlist;
	/* 2.显示电影列表 */
	if (dlist == NULL)
	{
		printf("No data entered.");
	}
	else
	{
		printf("Here is the data list:\n");
	}
	while (current != NULL)
	{
		printf("data:%d\n",current->data);
		current = current->next;
	}
	printf("\n");
}

/* 2.1 创建一个双链表：5,2,0,13,14 */
static DListNode *dlist_create(void)
{
	/* 创建头指针并指向第一个结点 */
	DListNode *head = NULL;
	/* 创建第一个结点 */
	Type list[5] = {5,2,0,13,14};
	DListNode *node = (DListNode*)malloc(sizeof(DListNode));
	node->prior = NULL;
	node->next = NULL;
	node->data = list[0];
	int i = 1;

	/* 给头结点赋值 */
	head = node;

	/* 创建其他结点并链接成双链表 */
	for(i; i < LEN; i++)
	{
		/* 创建新结点 */
		DListNode *new_node = (DListNode *)malloc(sizeof(DListNode));
		new_node->next = NULL;
		new_node->prior = head; /* 关键点1：新结点的prior指针指向前驱结点 */
		new_node->data = list[i];

		/* 改变前驱结点的next指针指向 */
		head->next = new_node; /* 关键结点2：前驱结点的next指针指向新结点 */

		/* 头指针后移 */
		head = head->next;
	}

	return node;
}

/* 2.2 元素查找 */
static int dlist_find(DListNode * dlist, Type find_data)
{
	DListNode* temp = dlist;
	int pos = 1;

	while(temp)
	{
		if(find_data == temp->data)
		{
			return pos;
		}
		else
		{
			temp = temp->next;
			pos++;
		}
	}
	return -1;
}

/* 2.3 元素替换 */
static DListNode *dlist_change(DListNode * dlist, int pos, Type new_data)
{
	DListNode* temp = dlist;
	int i = 1;

	for(i;i < pos; i++)
	{
		temp = temp->next;
	}
	temp->data = new_data;

	return dlist;
}

/* 2.4 结点插入：头部插入、中间插入、尾部插入 */
static DListNode *dlist_insert(DListNode * dlist, Type insert_data, int pos)
{
	/* 创建新结点待插入 */
	DListNode *new_node = (DListNode*)malloc(sizeof(DListNode));
	new_node->next = NULL;
	new_node->prior = NULL;
	new_node->data = insert_data;
	int i = 1;

	if(pos > LEN + 1)
	{
		printf("insert error!\n");
	}

	if(1 == pos)
	{
		dlist->prior = new_node; /* 步骤1 */	
		new_node->next = dlist; /* 步骤2 */
		dlist = new_node;		/* 步骤3 */
	}
	else
	{
		DListNode *temp = dlist;
		for(i;i < pos - 1;i++)
		{
			temp = temp->next;
		}
		/* 中间插入 */
		if(temp->next != NULL)
		{
			new_node->next = temp->next;  /* 步骤1 */
			new_node->prior = temp;       /* 步骤2 */
			temp->next->prior = new_node; /* 步骤3 */
			temp->next = new_node;        /* 步骤4 */
		}
		else /* 尾部插入 */
		{
			temp->next = new_node;
			new_node->prior = temp;
	
		}
	}

	return dlist;
}

/* 2.5 结点删除 */
static DListNode *dlist_delete(DListNode * dlist, Type del_data)
{
	DListNode *temp = dlist;

	while(temp)
	{
		if(del_data == temp->data)
		{
			temp->next->prior = temp->prior;
			temp->prior->next = temp->next;
			free(temp);
			return dlist;
		}
		temp = temp->next;
	}
	return dlist;
}

/* 3.主函数  验证 */
int main(void)
{
	printf("创建一个双链表：\n");
	DListNode *dlist = dlist_create();
	dlist_print_int(dlist);

	printf("元素13所在的位置是：\n");
	int pos = dlist_find(dlist,13);
	if(-1 == pos)
	{
		printf("该元素不存在：\n");
	}
	else
	{
		printf("pos:%d\n\n",pos);
	}

	printf("把第1个位置的元素替换为2020得到新的双链表：\n");
	dlist = dlist_change(dlist,1,2020);
	dlist_print_int(dlist);

	printf("第2个位置插入888得到新的双链表为：\n");
	dlist = dlist_insert(dlist,888,2);
	dlist_print_int(dlist);

	printf("删除元素2得到新的双链表为：\n");
	dlist = dlist_delete(dlist,2);
	dlist_print_int(dlist);

	return 0;
}


