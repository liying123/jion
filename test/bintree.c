#include <stdio.h>

typedef struct _BITTREE
{
	struct _BITTREE* left;
	struct _BITTREE* right;
	int data;
}BINTREE;

/* 将数值插入二叉搜索树 */
int insert_node(BINTREE** pptree, int value)
{
	if(NULL == (*pptree)) /* 基础条件 */
	{
		(*pptree) = (BINTREE*)malloc(sizeof(BINTREE));
		if(NULL == (*pptree))
		{
			printf("insert %d failed for malloc failed\n",value);
			return -1;
		}
		(*pptree)->data = value;
		(*pptree)->left = (*pptree)->right = NULL;
	}
	else /* 递归条件 */
	{
		if(value < (*pptree)->data)
		{
			insert_node(&(*pptree)->left,value);
		}
		else if(value > (*pptree)->data)
		{
			insert_node(&(*pptree)->right,value);
		}
		else
		{
			printf("value %d exist!\n",value);
		}
	}
	
	return 0;
}

/* 从二叉搜索树中搜索一个值 */
BINTREE* search_node(BINTREE* ptree, int value)
{
	BINTREE* n = ptree;
	while(n)
	{
		if(value > n->data)
		{
			n = n->right;
		}
		else if(value < n->data)
		{
			n = n->left;
		}
		else
		{
			return n;
		}
	}
	return NULL;
}

/* 从二叉树中删除一个节点 */ 
int delete_node(BINTREE** pptree, int value)
{
	BINTREE* dn = NULL, *sn = NULL;
	BINTREE* fdn = NULL, *fsn = NULL;

	/* 找到删除节点和它的父节点 */
	dn = *pptree;
	while(dn && (value != dn->data))
	{
		fdn = dn;
		if(value > dn->data)
		{
			dn = dn->right;
		}
		else if(value < dn->data)
		{
			dn = dn->left;
		}
	}
	
	/* 如果没找到 */
	if(NULL == dn)
	{
		printf("no value %d in bintree\n",value);
		return -1;
	}
	printf("found %d, now delete...\n",dn->data);
	/* 情况1.叶子节点 */
	if((NULL == dn->left) && (NULL == dn->right))
	{
		if(NULL == fdn)
			*pptree = NULL;
		else if(fdn->left == dn)
			fdn->left = NULL;
		else
			fdn->right = NULL;
		goto end;
	}

	/* 情况2.1有左节点 */
	if((NULL != dn->left) && (NULL == dn->right))
	{
		if(NULL == fdn)
			*pptree = dn->left;
		else if(fdn->left == dn)
			fdn->left = dn->left;
		else
			fdn->right = dn->left;
		goto end;
	}

	/* 情况2.2有右节点 */
	if((NULL == dn->left) && (NULL != dn->right))
	{
		if(NULL == fdn)
			*pptree = dn->right;
		else if(fdn->left == dn)
			fdn->left = dn->right;
		else
			fdn->right = dn->right;
		goto end;
	}

	/* 情况3.1先找替代节点 */
	fsn = dn;
	sn = dn->left;
	while(NULL != sn->right)
	{
		fsn = sn;
		sn = sn->right;
	}
	
	/* 情况3.2先将替代节点放在删除节点的父节点下 */
	if(NULL == fdn)
		*pptree = sn;
	else if(fdn->left == dn)
		fdn->left = sn;
	else
		fdn->right = sn;
	sn->right = dn->right;

	/* 情况3.3因为将替代节点拿过来了，所以要处理替代节点原来的子节点 */
	if(fsn != dn)
	{
		sn->left = dn->left;
		if(fsn->left == sn)
			fsn->left = sn->left;
		else
			fsn->right = sn->left;
	}
	
	end:
	free(dn);
	dn = NULL;
	return 0;
}

/* 打印二叉树 */
void _print_tree(BINTREE* ptree)
{
	if(NULL != ptree)
	{
		printf("%d ",ptree->data);
		_print_tree(ptree->left);
		_print_tree(ptree->right);
	}
}

void print_tree(BINTREE* ptree)
{
	printf("\n");
	_print_tree(ptree);
	printf("\n\n");
}

int main(void)
{
	int ret = 0;
	BINTREE *ptree = NULL;

	ret += insert_node(&ptree, 9);
	ret += insert_node(&ptree, 1);
	ret += insert_node(&ptree, 29);
	ret += insert_node(&ptree, 31);
	ret += insert_node(&ptree, 12);
	printf("ret: %d, ptree: %p\n",ret, ptree);

	print_tree(ptree);

	BINTREE* s =search_node(ptree,29); /*查询*/
	printf("search 29: %p-> %d \n",s, s->data);

	delete_node(&ptree,12); /* 删除 */
	print_tree(ptree);

	return 0;
}
