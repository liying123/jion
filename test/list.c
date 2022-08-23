/*
 *  list.c
 *
 *  (C) 2021
 */
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdbool.h>

//结构体定义
typedef struct Node
{
	int data;
	struct Node* next;
}Node;

//创建结点
Node* create_node(int data)
{
	Node* node = (Node*)malloc(sizeof(Node));
	if(NULL == node)
	{
        printf(" malloc err.\n ");
	}
	memset(node,0,sizeof(struct Node));
	node->data = data;
	node->next = NULL;
	return node;
}

//创建单链表：先创建一个头结点，之后头结点指向一个新结点，新的结点又指向一个新结点。
//			  可以通过循环来创建一个指定长度的单链表
Node* create_list(int num)
{
	int i = 0;

	Node* head = create_node(1);//创建头结点
	Node* tmp = head;//初始化tmp指针指向头结点，表示头结点
	for(i = 2; i <= num; ++i)
	{
		Node* node = create_node(i);//创建新结点
		tmp->next = node;//头结点的下一个结点等于新结点
		tmp = node;//tmp指针指向新结点
	}
	return head;
}

//显示链表的数据
void show_list(Node* head)
{
	while(head)
	{
		printf("data:%d",head->data);
		head = head->next;
	}
	printf("\n");
}

//获取链表的长度
int list_len(Node* head)
{
	int len = 0;
	while(head)
	{
		head = head->next;
		len++;
	}
	return len;
}

//插入节点：插入前判断插入的位置是否超出链表的范围;插入的位置为0时，即插入一个头结点
/*插入步骤：新结点下一个结点等于当前指针指向的结点的下一个结点;
			改变当前指针的指向；
			当前指针指向的结点指向新结点*/
Node* list_insert(Node* head,int index,int data)//在链表指定位置插入一个结点，返回头结点
{
	int i = 0;

	//判断链表是否为空以及插入的位置是否超出链表的范围
	if((index > list_len(head)) || index < 0 || head == NULL)
	{
		return head;
	}
	else if(index == 0)// 插入0位置，即插入一个头结点
	{
		Node* node = create_node(data);
		node->next = head; //新结点的下一个结点等于头结点
		head = node; //头结点等于新结点
	}
	else
	{
		Node* tmp = head;
		for(i = 0; i < index - 1; i++)
		{
			tmp = tmp->next;
		}
		Node* node = create_node(data);
		node->next = tmp->next;
		tmp->next = node;
	}
	return head;

}

//尾插法
void insert_tail(Node* head,Node* new)
{
    //第一步  先找到链表中的最后一个节点
    Node* phead = head;
    while(NULL != phead->next)
    {
        phead = phead->next;
    }
    //第二步 将新节点插入到最后
    phead->next = new;

}

//头插法
void insert_head(Node* head,Node* new)
{
    new->next = head;
    head = new;

}

//删除节点:删除前判断链表是否为空，删除的位置是否超出链表的范围；删除的位置为0，即删除一个头结点；删除的结点记得释放内存防止野指针
/*删除步骤：将指针移到删除节点的前一个结点node;
			通过tmp保存要删除的结点；
			node的下一个结点等于tmp的下一个结点；
			释放tmp的内存，并将tmp置空，防止野指针*/
Node* list_delete(Node* head,int index)//删除指定位置的一个结点，返回头结点
{
	int i = 0;

	if((index > list_len(head)) || index < 0 || head == NULL)
	{
		return head;
	}
	else if(index == 0)
	{
		Node* tmp = head;
		head = tmp->next;//头结点等于头结点的下一个结点
		free(tmp);//释放删除节点的内存
		tmp = NULL;
	}
	else
	{
		Node* node = head;
		for(i = 0; i< index -1;i++)
		{
			node = node->next;
		}
		Node* tmp = node->next;
		node->next = tmp->next;
		free(tmp);
		tmp = NULL;
	}
	return head;
}

//查找链表中指定的数据：链表的头结点 ; 指定的数据
//返回值：该数据对应得结点
Node* list_find(Node* head, int data)
{
	if(head == NULL)
	{
		return NULL;
	}
	Node* node = head;
	while(node)
	{
		if(node->data == data)
		{
			return node;//返回该数据对应的结点
		}
		else
		{
			node = node->next;
		}
	}
	return NULL;//链表中不存在该数据，返回NULL
}

//修改链表中指定位置结点的值：链表的头结点；指定的位置；新的数据
//返回值：该数据对应的结点
bool modify_index(Node* head,int index,int data)
{
	int i = 0;

	if(head == NULL || index < 0)
	{
		return -1;
	}
	Node* node = head;
	for(i = 0;i< index; ++i)
	{
		if(node == NULL)
		{
			return false;
		}
		else
		{
			node = node->next;
		}
	}
	node->data = data;
	return true;
}

//修改链表中指定数据的值：链表的头结点；指定的数据；新的数据
//返回值：该数据对应得结点
//如果链表中有多个数据等于指定的数据，只修改第一个
bool modify_data(Node* head,int data,int val)
{
	Node* node = list_find(head,data);
	if(node)
	{
		node->data = val;
		return true;
	}
	return false;
}

/*   test  start  */
void test_create_list()
{
	Node* head = create_list(10);
	show_list(head);
	printf("list length:%zd\n",list_len(head));
}

void test_list_insert()
{
	printf("------------test_list_insert------------\n");
	
	printf("test 1------------\n");
	Node* head = NULL;
	show_list(head);
	printf("list length:%zd\n",list_len(head));
	
	printf("test 2------------\n");
	Node* list = list_insert(head, 0, 1);
	printf("insert data 1 to index 0 \n");
	show_list(list);
	printf("list length:%zd\n",list_len(list));
	
	printf("test 3------------\n");
	list = list_insert(head, 1, 3);
	printf("insert data 3 to index 1 \n");
	show_list(list);
	printf("list length:%zd\n",list_len(list));
	
	printf("test 4------------\n");
	list = list_insert(head, 0, 5);
	printf("insert data 5 to index 0 \n");
	show_list(list);
	printf("list length:%zd\n",list_len(list));
	
	printf("test 5------------\n");
	list = list_insert(head, 2, 7);
	printf("insert data 7 to index 2 \n");
	show_list(list);
	printf("list length:%zd\n",list_len(list));
	
}

void test_list_delete()
{
	printf("------------test_list_delete------------\n");
	
	printf("test 1------------\n");
	Node* node = NULL;
	Node* list = list_delete(node, 0);
	if(list == NULL)
	{
		printf("list is NULL:\n");
	}

	printf("generate list------------\n");
	Node* head = create_list(10);
	show_list(head);
	printf("list length:%zd\n",list_len(head));


}

//尾插法
int test_insert_tail(void)
{
	Node* head = create_node(1);//创建头结点
    insert_tail(head, create_node(4));
    insert_tail(head, create_node(2));
    insert_tail(head, create_node(3));
    insert_tail(head, create_node(5));

	while(head)
	{
		printf("data:%d\n",head->data);
		head = head->next;
	}
	/*
        data:1
        data:4
        data:2
        data:3
        data:5
	*/

}

//头插法
int test_insert_head(void)
{
	Node* head = create_node(1);//创建头结点

    for(int i = 0 ; i < 4 ; i++)
    {
        Node* temp = (Node*)malloc(sizeof(Node));
        temp->data = i+3;
        temp->next = head;
        head = temp;
    }

	while(head)
	{
		printf("data:%d\n",head->data);
		head = head->next;
	}
	/*
        data:6
        data:5
        data:4
        data:3
        data:1
	*/

}

void main(void)
{
    test_insert_head();

	
	printf("list:\n");
	return;
}

#if 0
#include <stdio.h>
#include <stdlib.h> /* 提供malloc()原型 */
#include <string.h> /* 提供strcpy()原型 */
#define TSIZE 45    /* 储存片名的数组大小 */

struct film{
	char title[TSIZE];
	int rating;
	struct film *next; /* 指向链表中的下一个结构 */
};
char *s_gets(char *st, int n);

int main(void)
{
	struct film *head = NULL;
	struct film *prev,*current;
	char input[TSIZE];

	/* 1.收集并储存信息 */
	puts("Enter first movie title:");
	while(s_gets(input, TSIZE) != NULL && input[0] != '\0')
	{
		current = (struct film *)malloc(sizeof(struct film));
		if (head == NULL) /* 第一个结构体 */
		{
			head = current;
		}
		else
		{
			prev->next = current;
		}
		current->next = NULL;

		strcpy(current->title, input);
		puts("Enter your rating <0-10>:");
		scanf("%d",&current->rating);
		while(getchar() != '\n')
		{
			continue;
		}
		
		puts("Enter next movie title (empty line to stop):");
		prev = current;
	}

	/* 2.显示电影列表 */
	if (head == NULL)
	{
		printf("No data entered.");
	}
	else
	{
		printf("Here is the movie list:\n");
	}
	current = head;
	while (current != NULL)
	{
		printf("Movie: %s Rating: %d\n",current->title,current->rating);
		current = current->next;
	}

	/* 3.完成任务，释放已分配内存 */
	current = head;
	while (current != NULL)
	{
		free(current);
		current = current->next;
	}
	printf("Bye!\n");

	return 0;
}

char *s_gets(char * st, int n)
{
	char *ret_val;
	char *find;

	ret_val = fgets(st, n, stdin);
	if (ret_val)
	{
		find = strchr(st, '\n'); //查找换行符
		if (find)	//如果地址不是NULL
		{
			*find = '\0';  //在此处放置一个空字符
		}
		else
		{
			while(getchar() != '\n')
			{
				continue;  //处理剩余输入行
			}
		}
	}
	return ret_val;
}
#endif


