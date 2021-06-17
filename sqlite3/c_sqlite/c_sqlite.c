#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

static int callback(void *NotUsed, int argc, char **argv, char **azColName)
{
    int i = 0;
    
    fprintf(stdout, "%s: ", (const char*)NotUsed);
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
    int  rc;
    char *sql;
    const char* data = "Callback function called";
    
    /* 创建或者打开数据库 */
    rc = sqlite3_open("test.db", &db);
    if( rc )
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        exit(0);
    }
    else
    {
        fprintf(stdout, "Opened database successfully\n\n");
    }

    /* 创建一个表*/
    sql = "CREATE TABLE COMPANY(ID INT PRIMARY KEY    NOT NULL, NAME   TEXT   NOT NULL, AGE    INT   NOT NULL, ADDRESS    CHAR(50),SALARY    REAL );";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK )
    {
        fprintf(stderr, "SQL CREATE error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;//错误，返回
    }
    else
    {
        fprintf(stdout, "Table created successfully\n\n");
    }

    /*表中插入数据*/
    sql = "INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY) "  \
          "VALUES (1, 'Paul', 32, 'California', 20000.00 ); " \
          "INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY) "  \
          "VALUES (2, 'Allen', 25, 'Texas', 15000.00 ); "     \
          "INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY)" \
          "VALUES (3, 'Teddy', 23, 'Norway', 20000.00 );" \
          "INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY)" \
          "VALUES (4, 'Mark', 25, 'Rich-Mond ', 65000.00 );";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK )
    {
        fprintf(stderr, "SQL INSERT error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;//错误，返回
    }else
    {
        fprintf(stdout, "Insert data successfully\n\n");
    }

    /*读取数据*/
    sql = "SELECT * from COMPANY";
    rc = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);
    if( rc != SQLITE_OK )
    {
        fprintf(stderr, "SQL SELECT error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    }
    else
    {
        fprintf(stdout, "Operation done SELECT[read] data successfully\n\n");
        //fprintf(stdout, data);
    }
    
    /*修改数据*/
    sql = "UPDATE COMPANY set SALARY = 25000.00 where ID=1; SELECT * from COMPANY";
    rc = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);
    if( rc != SQLITE_OK )
    {
        fprintf(stderr, "SQL UPDATE error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    }else
    {
        fprintf(stdout, "Operation UPDATE[modify] data successfully\n\n");
    }
    
    /*删除数据*/
    sql = "DELETE from COMPANY where ID=2; SELECT * from COMPANY";
    rc = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);
    if( rc != SQLITE_OK )
    {
        fprintf(stderr, "SQL DELETE error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    }
    else
    {
        fprintf(stdout, "Operation done DELETE data ID=2 successfully\n\n");
    }
    sqlite3_close(db);

    return 0;
}

