#include "baiduapi.h"
#include "utils.h"
#include "threadpool.h"
#include <unistd.h>
#include <iostream>
#include <vector>
#include <limits>
#include <mutex>
#include <string>
#include <json-c/json.h>
#include <string.h>

using namespace std;

static bool verbose = false;
static bool autofix = false;
static bool recursive = false;

static mutex console_lock;

std::ostream& lock(std::ostream& os) {
    console_lock.lock();
    return os;
}

std::ostream& unlock(std::ostream& os) {
    console_lock.unlock();
    return os;
}

int readblklist(string path, vector<string> &blks) {
    buffstruct bs;
    int ret = HANDLE_EAGAIN(baiduapi_download((path + METAPATH).c_str(), 0, 0, bs));
    if (ret != 0) {
        cerr<<lock<<"read meta file "<<path<<" failed: "<<ret<<endl<<unlock;
        return ret;
    }
    json_object *json_get = json_tokener_parse(bs.buf);
    if (json_get == NULL) {
        cerr<<lock<<"json_tokener_parse filed: " << bs.buf << endl <<unlock;
        return ret;
    }

    json_object *jsize;
    json_object_object_get_ex(json_get, "size", &jsize);

    json_object *jblksize;
    json_object_object_get_ex(json_get, "blksize", &jblksize);


    json_object *jblock_list;
    json_object_object_get_ex(json_get, "block_list", &jblock_list);
    blks.reserve(json_object_array_length(jblock_list));
    for (int i = 0; i < json_object_array_length(jblock_list); ++i) {
        json_object *block = json_object_array_get_idx(jblock_list, i);
        const char  *name = json_object_get_string(block);
        blks.push_back(name);
    }
    json_object_put(json_get);
    return 0;
}

void fixNoMeta(const string &path, const std::map<std::string, struct stat> &files) {
    if (files.empty()) {
        cerr <<lock<< "there is no blocks of file: " << decodepath(path) << ", so delete it" << endl<<unlock;
        goto del;
        return;
    }
    cerr<<lock << decodepath(path)<<" has blocks:" << endl;
    for (auto f : files) {
        cerr << f.first.c_str() + path.length() + 1<<endl;
    }
    do {
        fflush(stdin);
        cerr << "delete this file or ignore it([D]elete/[I]gnore) I?";
        char a = getchar();
        if (a == '\n') {
            a = 'I';
        } else if (a != 'D' && a != 'I') {
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            continue;
        }
        cerr<<unlock;
        if (a == 'I') {
            return;
        } else {
            goto del;
        }
    } while (true);
del:
    int ret = HANDLE_EAGAIN(baiduapi_delete(path.c_str()));
    if (ret != 0) {
        cerr<<lock << "delete dir " << path << "failed: " << ret << endl << unlock;
    }
}

void fixMissBlock(const string &path, const std::map<std::string, struct stat> &files, uint64_t no) {
    set<string> fit;
    string No = to_string(no);
    for (auto i : files) {
        if (i.first == No || startwith(i.first, No + '_')) {
            fit.insert(i.first);
        }
    }
    if (fit.empty()) {
        cerr<<lock<< decodepath(path) << "has no block fit for " << No << ", should reset it to 'x' (not implement)" << endl<<unlock;
        return;
    }
    cerr <<lock<< decodepath(path) <<"has some block fit for " << No << ", please pick one:" << endl;
    size_t n = 0;
    for (auto i : fit) {
        cerr << n << ". " << i << endl;
    }
    getchar();
    cerr << "not implement now" << endl<<unlock;
}

bool blockMatchNo(string block, uint64_t no) {
    if (block == "x") {
        return true;
    }
    return (uint64_t)stoi(block) == no;
}

void checkchunk(char *pathStr) {
    string path = pathStr;
    free(pathStr);
    std::map<std::string, struct stat> files;
    int ret  = HANDLE_EAGAIN(baiduapi_list(path.c_str(), 100000, files));
    if (ret != 0) {
        cerr<<lock<< "list dir "<<path<<" failed: "<<ret<<endl<<unlock;
        return;
    }
    set<string> fs;
    for (auto f : files) {
        fs.insert(f.first.substr(path.length() + 1));
    }
    if (fs.count(METANAME) == 0) {
        cerr<<lock<< "file: "<<decodepath(path)<<" have no meta.json"<<endl<<unlock;
        if (autofix) {
            fixNoMeta(path, files);
        }
        return;
    }
    fs.erase(METANAME);
    vector<string> blks;
    ret = readblklist(path, blks);
    if (ret != 0) {
        cerr<<lock<<"file: "<<decodepath(path)<<" have malformed meta.json"<<endl<<unlock;
        if (autofix) {
            fixNoMeta(path, files);
        }
        return;
    }
    int no = 0;
    for (auto b : blks) {
        bool haswrong = false;
        if (!blockMatchNo(b, no)) {
            cerr<<lock<<"file: "<<decodepath(path)<<" has block "<<b<<" on No."<<no<<endl<<unlock;
            haswrong = true;
        }
        if (b != "x" && fs.count(b) == 0) {
            cerr<<lock<<"file: "<<decodepath(path)<<" miss block: "<<b<<endl<<unlock;
            haswrong = true;
        }
        if (haswrong && autofix) {
            fixMissBlock(path, files, no);
        }
        no++;
    }
    set<string> ftrim;
    for (auto f : fs) {
        if (!isdigit(f[0])){
            cerr<<lock<<"file: "<<decodepath(path)<<" has unwanted block: "<<f<<endl<<unlock;
            if(autofix){
                ftrim.insert(path + "/" + f);
            }
            continue;
        }
        int i = stoi(f);
        if(i < 0 || blks.size() <= (size_t)i){
            cerr<<lock<<"file: "<<decodepath(path)<<" has unwanted block: "<<f<<endl<<unlock;
            if(autofix){
                ftrim.insert(path + "/" + f);
            }
            continue;
        }
        if (blks[i] != f) {
            cerr<<lock<<"file: "<<decodepath(path)<<" has lagecy block: "<<f<<"/"<<blks[stoi(f)]<<endl<<unlock;
            if (autofix) {
                ftrim.insert(path + "/" + f);
            }
        }
    }
    if (!ftrim.empty()) {
        int ret = HANDLE_EAGAIN(baiduapi_batchdelete(ftrim));
        if (ret != 0) {
            cerr<<lock<< "delete lagecy block in: "<<path<<" failed"<<endl<<unlock;
        }
    }
    if (verbose) {
        cout <<lock<< decodepath(path) << " check finish" << endl<<unlock;
    }
    return;
}

void checkfile(char* pathStr) {
    string path = pathStr;
    free(pathStr);
    std::map<std::string, struct stat> files;
    int ret  = HANDLE_EAGAIN(baiduapi_list(path.c_str(), 100000, files));
    if (ret != 0) {
        cerr<<lock<< "list dir "<<path<<" failed: "<<ret<<endl<<unlock;
        return;
    }
    for (auto f : files) {
        if (S_ISREG(f.second.st_mode)) {
            if (verbose) {
                cout<<lock << f.first << " skip check" << endl<<unlock;
            }
            continue;
        }

        if(endwith(f.first, ".def")){
            addtask((taskfunc)checkchunk, strdup(f.first.c_str()), 0, 0);
        }else if(recursive){
            addtask((taskfunc)checkfile, strdup(f.first.c_str()), 0, 0);
        }
    }
}


int main(int argc, char **argv)
{
    baiduapi_prepare();
    char ch;
    while ((ch = getopt(argc, argv, "vfr")) != -1)
        switch (ch) {
        case 'v':
            cout << "verbose mode" << endl;
            verbose = true;
            break;
        case 'f':
            cout << "will try fix error" << endl;
            autofix = true;
            break;
        case 'r':
            cout << "will check recursive" <<endl;
            recursive = true;
            break;
        }
    const char *path;
    if (argv[optind]) {
        path = argv[optind];
    } else {
        path = "/";
    }
    cout << "will check path: " << path << endl;
    creatpool(50);
    checkfile(strdup(path));
    waittask(0);
    return 0;
}
