#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int hex2num(char c)
{
    if (c>='0' && c<='9') return c - '0';
    if (c>='a' && c<='z') return c - 'a' + 10;//这里+10的原因是:比如16进制的a值为10
    if (c>='A' && c<='Z') return c - 'A' + 10;

    printf("unexpected char: %c", c);
    return '0';
}

//注意！！！！：这个函数会替换str为encode之后的内容，所以要保证所给的str空间足够,返回值也是str
const char* URLEncode(char* str)
{
    int j = 0;//for result index
    char ch;
    int strSize=strlen(str);

    char *result = (char *)malloc(3*strSize);
    if ((str==NULL) || (result==NULL) || (strSize==0) ) {
        free(result);
        return NULL;
    }
    int i;
    for (i=0; i<strSize; ++i) {
        ch = str[i];
        if (((ch>='A') && (ch<'Z')) ||
            ((ch>='a') && (ch<'z')) ||
            ((ch>='0') && (ch<'9'))) {
            result[j++] = ch;
        } else if (ch == ' ') {
            result[j++] = '+';
        } else if (ch == '.' || ch == '-' || ch == '_' || ch == '*') {
            result[j++] = ch;
        } else {
            sprintf(result+j, "%%%02X", (unsigned char)ch);
            j += 3;
        }
    }

    result[j] = '\0';
    strcpy(str,result);
    free(result);
    return str;
}


//注意！！！！：这个函数会替换str为encode之后的内容，返回值也是str
const char * URLDecode(char* str)
{
    char ch,ch1,ch2;
    int i;
    int j = 0;//record result index

    int strSize = strlen(str);

    char* result = (char*)malloc(strSize);
    if ((str==NULL) || (result==NULL) || (strSize<=0) ) {
        free(result);
        return 0;
    }

    for ( i=0; i<strSize; ++i) {
        ch = str[i];
        switch (ch) {
        case '+':
            result[j++] = ' ';
            break;
        case '%':
            if (i+2<strSize) {
                ch1 = hex2num(str[i+1]);//高4位
                ch2 = hex2num(str[i+2]);//低4位
                if ((ch1!='0') && (ch2!='0'))
                    result[j++] = (char)((ch1<<4) | ch2);
                i += 2;
                break;
            } else {
                break;
            }
        default:
            result[j++] = ch;
            break;
        }
    }
    result[j] = 0;
    strcpy(str,result);
    free(result);
    return str;
}
