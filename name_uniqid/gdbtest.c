#include <stdio.h>

int func(int n)
{
    int sum=0;
    int i;
    for(i=1; i<=100; i++)
    {
        sum+=i;
    }
    return sum;
 }

int main(void)
{
    int i;
    long result = 0;
    for(i=1; i<=100; i++)
    {
        result += i;
    }

    printf("result[1-100] = %d\n", result);
    printf("result[1-250] = %d\n", func(250));
    return 0;
}

