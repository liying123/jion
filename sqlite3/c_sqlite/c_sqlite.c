#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

typedef struct sqlitedb{
    int id;
    char name[512];
    int age;
    char address[512];
	long long salary;
}SqliteCompany;

static int callback(void *NotUsed, int argc, char **argv, char **azColName)
{
    int i = 0;
    
    fprintf(stdout, "%s: argc=%d member.\n", (const char*)NotUsed,argc);
    for(i = 0; i<argc; i++)
    {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    //printf("\n");
    return 0;
}

int main(int argc, char* argv[])
{
    sqlite3 *db;
    char *zErrMsg = 0;
    int ret = 0;
    char *sql = NULL;
    const char* data = "Callback function called";
    char *errmsg=NULL;    //用来存储错误信息字符串
    char **dbResult;
    int id = 0;
    int nRow=0, nColumn=0;     //nRow 查找出的总行数,nColumn 存储列
    SqliteCompany *Companyitem;
    Companyitem = (SqliteCompany *)malloc(sizeof(SqliteCompany) * 10);

    
    /* 1.创建或者打开数据库 */
    ret = sqlite3_open("test.db", &db);
    if( ret )
    {
        fprintf(stderr, "Step1, Can't open database: %s\n", sqlite3_errmsg(db));
        exit(0);
    }
    else
    {
        fprintf(stdout, "Step1, Opened database successfully\n\n");
    }

    /* 2.创建一个表 */
    //sql = "DROP TABLE IF EXISTS COMPANY;"
    //      "CREATE TABLE COMPANY(ID INT PRIMARY KEY    NOT NULL, NAME   TEXT   NOT NULL, AGE    INT   NOT NULL, ADDRESS    CHAR(50),SALARY    REAL );";
    sql = "DROP TABLE IF EXISTS COMPANY;"
          "CREATE TABLE COMPANY(ID INT PRIMARY KEY, NAME TEXT, AGE INT, ADDRESS  CHAR(50),SALARY  REAL);";
    ret = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( ret != SQLITE_OK )
    {
        fprintf(stderr, "Step2，SQL CREATE error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;//错误，返回
    }
    else
    {
        fprintf(stdout, "Step2，Created table successfully\n\n");
    }

    /* 3.表中插入数据 */
    #if 0
    sql = "INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY) "  \
          "VALUES (1, 'Paul', 32, 'California', 20000.00 ); " \
          "INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY) "  \
          "VALUES (2, 'Allen', 25, 'Texas', 15000.00 ); "     \
          "INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY)" \
          "VALUES (3, 'Teddy', 23, 'Norway', 20000.00 );" \
          "INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY)" \
          "VALUES (4, 'Mark', 25, 'Rich-Mond ', 65000.00 );";
    #endif
    sql = "INSERT INTO COMPANY VALUES(1, 'Paul', 32, 'California', 20000.00 );"
          "INSERT INTO COMPANY VALUES(2, 'Allen', 25, 'Texas', 15000.00 );"
          "INSERT INTO COMPANY VALUES(3, 'Teddy', 23, 'Norway', 20000.00 );"
          "INSERT INTO COMPANY VALUES(4, 'Mark', 25, 'Rich-Mond ', 65000.00 );"
          "INSERT INTO COMPANY VALUES(5, 'zhangsan', 28, 'NEW-YORK ', 85000.10 );"
          "INSERT INTO COMPANY VALUES(6, 'lisi', 25, 'Ba-Li ', 65000.00 );"
          "INSERT INTO COMPANY VALUES(7, 'maliu', 28, 'Shang-hai ', 85000.10 );";
    ret = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( ret != SQLITE_OK )
    {
        fprintf(stderr, "Step3，SQL INSERT error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;//错误，返回
    }else
    {
        fprintf(stdout, "Step3，Insert data successfully\n\n");
    }

    /* 4.读取数据 */
    printf("Step4，[SELECT * from COMPANY]\n");
    sql = "SELECT * from COMPANY";
    ret = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);
    if( ret != SQLITE_OK )
    {
        fprintf(stderr, "Step4，SQL SELECT * from COMPANY error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    }
    else
    {
        //fprintf(stdout, "Step4，Operation done SELECT[read] data successfully\n\n");
        //fprintf(stdout, data);
    }
    
    /* 5.修改数据 */
    printf("\nStep5，[UPDATE COMPANY set SALARY = 25000.00 where ID=1; SELECT * from COMPANY]\n");
    sql = "UPDATE COMPANY set SALARY = 25000.00 where ID=1; SELECT * from COMPANY";
    ret = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);
    if( ret != SQLITE_OK )
    {
        fprintf(stderr, "Step5，SQL UPDATE error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    }else
    {
        //fprintf(stdout, "Step5，Operation UPDATE[modify] data successfully\n\n");
    }

 #if 0
    /* 6.删除数据 */
    printf("\nStep6，[DELETE from COMPANY where ID=2; SELECT * from COMPANY]\n");
    sql = "DELETE from COMPANY where ID=2; SELECT * from COMPANY";
    ret = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);
    if( ret != SQLITE_OK )
    {
        fprintf(stderr, "Step6，SQL DELETE error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    }
    else
    {
        //fprintf(stdout, "Step6，Operation done DELETE data ID=2 successfully\n\n");
    }

#endif

    /* 7.获取表数据 */
    printf("\nStep7，[SELECT * from COMPANY;   sqlite3_get_table]\n");
    ret = sqlite3_get_table(db, "SELECT * from COMPANY;", &dbResult, &nRow, &nColumn, &errmsg);
    if(NULL != errmsg)
    {
        sqlite3_free_table(dbResult);
        errmsg = NULL;
        printf("errmsg.\n");
        return -1;
    }
    /* 假设COMPANY表里有n个字段:n = nColumn = 5
       *      *      *      * .........*  (dbResult[0]~[n-1]分别代表字段名)
      dbResult[0]   [1]    [2]    [3].....  [n-1]  (dbResult[0]~[n-1]分别代表字段名)
      dbResult[n]   [n+1]  [n+2]  [n+3].....[n+n-1] (dbResult[n]~[n+n-1]分别代表第一条记录的值)
      dbResult[2n]  [2n+1] [2n+2] [2n+3]....[2n+n-1](dbResult[2n]~[2n+n-1]分别代表第二条记录的值)
      dbResult[3n]  [3n+1] [3n+2] 32n+3]....[3n+n-1](dbResult[3n]~[3n+n-1]分别代表第三条记录的值)
    */
    id = atoi(dbResult[5+2]);
    printf("nRow=%d,nColumn=%d,id=%d.\n",nRow,nColumn,id);
    printf("dbResult[0]=%s,dbResult[1]=%s,dbResult[2]=%s,dbResult[3]=%s,dbResult[4]=%s[分别代表字段名].\n",
            dbResult[0],dbResult[1],dbResult[2],dbResult[3],dbResult[4]);
    printf("dbResult[5]=%s,dbResult[5+1]=%s,dbResult[5+2]=%s,dbResult[5+3]=%s,dbResult[5+4]=%s.\n",
            dbResult[5],dbResult[5+1],dbResult[5+2],dbResult[5+3],dbResult[5+4]);
    printf("dbResult[2*5]=%s,dbResult[2*5+1]=%s,dbResult[2*5+2]=%s,dbResult[2*5+3]=%s,dbResult[2*5+4]=%s.\n\n",
            dbResult[2*5],dbResult[2*5+1],dbResult[2*5+2],dbResult[2*5+3],dbResult[2*5+4]);

    int index = nColumn;
    for (int i = 0; i < nRow; i++) {
        printf("nRow-i=%d,nColumn-index=%d,",i,index);
        Companyitem[i].id = atoi(dbResult[index++]);  //id
        
        strncpy(Companyitem[i].name, dbResult[index++], 512);  //name
        Companyitem[i].name[512] = "\0";
        
        Companyitem[i].age = atoi(dbResult[index++]);  //age
        
        strncpy(Companyitem[i].address, dbResult[index++], 512);  //address
        Companyitem[i].address[512] = "\0";
        
        Companyitem[i].salary = atoi(dbResult[index++]);  //salary
        
        printf("Companyitem[%d]: id=%d,name=%s,age=%d,address=%s,salary=%d.\n",
                i,Companyitem[i].id,Companyitem[i].name,Companyitem[i].age,Companyitem[i].address,Companyitem[i].salary);
    }
    printf("\n\n");


    /* 8.获取表数据 */
    printf("\nStep8，[SELECT * from COMPANY where ID=3;   sqlite3_get_table]\n");
    ret = sqlite3_get_table(db, "SELECT * from COMPANY where ID=3;", &dbResult, &nRow, &nColumn, &errmsg);
    if(NULL != errmsg)
    {
        sqlite3_free_table(dbResult);
        errmsg = NULL;
        printf("errmsg.\n");
        return -1;
    }
    printf("nRow=%d,nColumn=%d.\n",nRow,nColumn);
    printf("dbResult[0]=%s,dbResult[1]=%s,dbResult[2]=%s,dbResult[3]=%s,dbResult[4]=%s[分别代表字段名].\n",
            dbResult[0],dbResult[1],dbResult[2],dbResult[3],dbResult[4]);
    printf("dbResult[5]=%s,dbResult[5+1]=%s,dbResult[5+2]=%s,dbResult[5+3]=%s,dbResult[5+4]=%s.\n",
            dbResult[5],dbResult[5+1],dbResult[5+2],dbResult[5+3],dbResult[5+4]);
    sqlite3_free_table(dbResult);


    /* 9.find_items 查找元素 */
    printf("\nStep9-1，[select count(*) from COMPANY where AGE = 25;]\n");
	char sqlbuf[2048] = "select count(*) from COMPANY where AGE = 25;";
	sqlite3_stmt *stmt = NULL;
	int sum_item = 0;
	int step_ret = 0;
    sqlite3_prepare(db, sqlbuf, -1, &stmt, NULL);
    step_ret = sqlite3_step(stmt);
    sum_item = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    printf("Step9-1: sum_item =%d ,step_ret=%d.\n",sum_item,step_ret);


    printf("\nStep9-2，[select * from COMPANY where AGE = 25 ORDER BY id ASC LIMIT 0, -1;]\n");
	char sqlbuf2[2048] = "select * from COMPANY where AGE = 25 ORDER BY id ASC LIMIT 0, -1;";
	int i,sum_value,sum_value1,sum_value2,sum_value3,sum_value4,bytes,bytes1,bytes2,bytes3,bytes4,n = 0;
	char *text, *text1,*text2,*text3,*text4,*text5,*p;
    ret = sqlite3_get_table(db, "select * from COMPANY where AGE = 25 ORDER BY id ASC LIMIT 0, -1;", &dbResult, &nRow, &nColumn, &errmsg);
    if(NULL != errmsg)
    {
        sqlite3_free_table(dbResult);
        errmsg = NULL;
        printf("errmsg.\n");
        return -1;
    }
    
    printf("\nStep9-2:nRow=%d,nColumn=%d.\n",nRow,nColumn);
    for (int i = 0; i < nRow; i++) {        
        Companyitem[i].id = atoi(dbResult[nColumn++]);  //id
        
        strncpy(Companyitem[i].name, dbResult[nColumn++], 512);  //name
        Companyitem[i].name[512] = "\0";
        
        Companyitem[i].age = atoi(dbResult[nColumn++]);  //age
        
        strncpy(Companyitem[i].address, dbResult[nColumn++], 512);  //address
        Companyitem[i].address[512] = "\0";
        
        Companyitem[i].salary = atoi(dbResult[nColumn++]);  //salary
        
        printf("Step9-2:id=%d,name=%s,age=%d,address=%s,salary=%d.\n",
                Companyitem[i].id,Companyitem[i].name,Companyitem[i].age,Companyitem[i].address,Companyitem[i].salary);
    }
    sqlite3_free_table(dbResult);
    printf("\n");

	
    sqlite3_prepare(db, sqlbuf2, -1, &stmt, NULL);
    for(i = 0;i < sum_item && 100 == sqlite3_step(stmt);)
    {
        sum_value = sqlite3_column_int(stmt, 0); 
        sum_value1 = sqlite3_column_int(stmt, 1); 
        sum_value2 = sqlite3_column_int(stmt, 2); 
        sum_value3 = sqlite3_column_int(stmt, 3); 
        sum_value4 = sqlite3_column_int(stmt, 4); 
        printf("Step9-2: sum_value=%d,sum_value1=%d,sum_value2=%d,sum_value3=%d,sum_value4=%d.\n",sum_value,sum_value1,sum_value2,sum_value3,sum_value4);
        
        text = sqlite3_column_text(stmt, 0);
        text1 = sqlite3_column_text(stmt, 1);
        text2 = sqlite3_column_text(stmt, 2);
        text3 = sqlite3_column_text(stmt, 3);
        text4 = sqlite3_column_text(stmt, 4);
        text5 = sqlite3_column_text(stmt, 5);
        printf("Step9-2: text=%s,text1=%s,text2=%s,text3=%s,text4=%s,text5=%s.\n",text,text1,text2,text3,text4,text5);
        
        bytes = sqlite3_column_bytes(stmt, 0);
        bytes1 = sqlite3_column_bytes(stmt, 1);
        bytes2 = sqlite3_column_bytes(stmt, 2);
        bytes3 = sqlite3_column_bytes(stmt, 3);
        bytes4 = sqlite3_column_bytes(stmt, 4);
        printf("Step9-2: bytes=%d,bytes1=%d,bytes2=%d,vbytes3=%d,bytes4=%d.\n\n",bytes,bytes1,bytes2,bytes3,bytes4);
        i++;
    }
    sqlite3_finalize(stmt);
    printf("Step9-2: sum_item =%d ,n=%d.\n",sum_item,n);


	
    
    sqlite3_close(db);
    free(Companyitem);
    return 0;
}

