#include <stdio.h>
#include <errno.h>
#include <json/json.h>
#include <json/json_util.h>
#include <json/printbuf.h>
#include <unistd.h>
#include <string.h>


struct json_object* json_object_from_FILE(FILE* fp)
{
    struct printbuf *pb;
    struct json_object *obj;
    char buf[JSON_FILE_BUF_SIZE];
    int  ret;
    if(!(pb = printbuf_new())) {
        MC_ERROR("json_object_from_FILE: printbuf_new failed\n");
        return NULL;
    }
    if(fseek(fp,0,SEEK_SET)<0){
        MC_ERROR ("fseek error:%s\n",strerror ( errno ) );
        return NULL;
    }
    while((ret = fread(buf,1, JSON_FILE_BUF_SIZE,fp)) > 0) {
        printbuf_memappend(pb, buf, ret);
    }
    if(ret < 0) {
        MC_ABORT("json_object_from_FILE: error reading file: %s\n",strerror(errno));
        printbuf_free(pb);
        return NULL;
    }
    obj = json_tokener_parse(pb->buf);
    printbuf_free(pb);
    return obj;
}
