#include <json-c/json.h>
#include <stdio.h>

struct json_object* json_object_from_FILE(FILE* fp);        //从文件生成一个json_object
