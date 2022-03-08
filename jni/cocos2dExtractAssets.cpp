
#include <stdarg.h>
#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string>
#include <map>
#include <dirent.h>
#include <vector>

extern "C" void _frida_log(char*); 
extern "C" void _frida_exit();
extern "C" void _frida_hexdump(void*, unsigned int);

#define TEST_VERION 1

//////////////////////////////////////////////////                
// help macros

#define LOG_INFO(N,fmt, args...) do{                                     \
    char buf[N];                                                         \
    snprintf(buf,N, "[%s:%d]" fmt , __FILE__, __LINE__, ##args);         \
    _frida_log(buf);                                                     \
}while(0)                                                               

#define LOG_ERR(N,fmt, args...) do{                                      \
    char buf[N];                                                         \
    snprintf(buf,N, "[%s:%d]" fmt , __FILE__, __LINE__, ##args);         \
    _frida_log(buf);                                                     \
    _frida_exit();                                                       \
}while(0)                                                               

#define ZIPFILE_OBJ_SIZE 0x20
namespace cocos2d
{
    struct ZipFile
    {
        // extern "C" void* _ZN7cocos2d7ZipFile11getFileDataERKSsPm(void*, void*, unsigned long *); // cocos2d::ZipFile::getFileData(std::string const&, unsigned long *)
        unsigned char* getFileData(std::string const&, unsigned long *);
    };
    struct CCFileUtils
    {
        //extern "C" void* _ZN7cocos2d11CCFileUtils15sharedFileUtilsEv(); 
        static void* sharedFileUtils(); 
    };
    struct CCFileUtilsAndroid
    {
        // extern "C" void* _ZN7cocos2d18CCFileUtilsAndroid11getFileDataEPKcS2_Pm(void*, void*, void*, void*);
        unsigned char * getFileData( const char *, const char *, unsigned long*);
    };
}

/* test that dir exists (1 success, -1 does not exist, -2 not dir) */
int xis_dir (const char *d)
{
    DIR *dirptr;

    if (access ( d, F_OK ) != -1 ) {
        // file exists
        if ((dirptr = opendir (d)) != NULL) {
            closedir (dirptr); /* d exists and is a directory */
        } else {
            return -2; /* d exists but is not a directory */
        }
    } else {
        return -1;     /* d does not exist */
    }

    return 1;
}


static int do_mkdir(const char *path, mode_t mode)
{
    struct stat            st;
    int             status = 0;

    if (stat(path, &st) != 0)
    {
        /* Directory does not exist. EEXIST for race condition */
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            status = -1;
    }
    else if (!S_ISDIR(st.st_mode))
    {
        errno = ENOTDIR;
        status = -1;
    }

    return(status);
}

int writeDataToFile(const char* path, unsigned char* data, unsigned long sz){
    FILE* fp = fopen(path,"wb");
    if(!fp) LOG_ERR(0x100, " can not open file %s for writing ", path);
    unsigned long wrote = fwrite(data, 1, sz, fp);
    if(wrote != sz) LOG_INFO(0x100, " wrote failed %lu / %lu ", wrote, sz);
    fclose(fp);
    return 0;
}

/**
** mkpath - ensure all directories in path exist
** Algorithm takes the pessimistic view and works top-down to ensure
** each directory in path exists, rather than optimistically creating
** the last element and working backwards.
*/
int mkpath(const char *path, mode_t mode)

{
    char           *pp;
    char           *sp;
    int             status;
    char           *copypath = strdup(path);

    status = 0;
    pp = copypath;
    while (status == 0 && (sp = strchr(pp, '/')) != 0)
    {
        if (sp != pp)
        {
            /* Neither root nor double slash in path */
            *sp = '\0';
            status = do_mkdir(copypath, mode);
            *sp = '/';
        }
        pp = sp + 1;
    }
    if (status == 0)
        status = do_mkdir(path, mode);
    free(copypath);
    return (status);
}

//////////////////////////////////////////////////                
// utils functions
//////////////////////////////////////////////////                
// global variables
extern "C" int test(void* baseaddress,  char* outdir) 
{

#ifdef  __arm__  // for 32-bit ARM
    LOG_INFO(0x100,"arch armeabi ");
#else
    #ifdef __aarch64__ //  64-bit ARM
        LOG_INFO(0x100,"arch aach64 ");
    #else
#error "unsupported architecture "
    #endif
#endif
    // get a list of all encrypt files
    std::vector<std::string> encryptFiles; 
    {
        // print some info for debug
#ifdef __arm__
        LOG_INFO(0x100, "sizeof(int) %d", sizeof(int));
        LOG_INFO(0x100, "sizeof(long) %d", sizeof(long));
        LOG_INFO(0x100, "sizeof(void*) %d", sizeof(void*));
#else
    #ifdef __aarch64__ //  64-bit ARM
        LOG_INFO(0x100, "sizeof(int)   %ld", sizeof(int));
        LOG_INFO(0x100, "sizeof(long)  %ld", sizeof(long));
        LOG_INFO(0x100, "sizeof(void*) %ld", sizeof(void*));
    #else
#error "unsupported architecture "
    #endif
#endif


#ifdef __arm__
        cocos2d::ZipFile* pzipfile = (cocos2d::ZipFile*)*(void**)&(((unsigned char*)baseaddress)[0x608E68]);
#else
    #ifdef __aarch64__ //  64-bit ARM
        cocos2d::ZipFile* pzipfile = (cocos2d::ZipFile*)*(void**)&(((unsigned char*)baseaddress)[0x9223A0]);
    #else
#error "unsupported architecture "
    #endif
#endif

        // ZipFilePrivate *_data;
        // typedef std::map<std::string, struct ZipEntryInfo> FileListContainer;
        //FileListContainer fileList;
#ifdef __arm__
        void* _data = *(void**)(&((unsigned char*)pzipfile)[4]);
        void* fileList = (void*)(&((unsigned char*)_data)[4]);
#else
    #ifdef __aarch64__
        void* _data = *(void**)(&((unsigned char*)pzipfile)[8]);
        void* fileList = (void*)(&((unsigned char*)_data)[8]);
    #else
#error "unsupported architecture "
    #endif
#endif
        typedef std::map<std::string, void*> FileListContainer;
        typedef std::map<std::string, void*>::iterator FileListContainerIterator;
        FileListContainer* filelistContainer= (FileListContainer*) fileList;
        for(FileListContainerIterator it = filelistContainer->begin(); it!=filelistContainer->end(); it ++)
        {
#if TEST_VERION
            bool exit=false;                    
#endif
            const char* fname = it->first.c_str();
            std::string name(fname);
            unsigned long datalen=0l;
            unsigned char* data = pzipfile->getFileData(name, &datalen);
            if(data!=NULL){
                // _frida_hexdump(data, 0x20);
                if(!memcmp(data, "\xfe\xfe\xfe\xfe", 4)){
                    encryptFiles.push_back(it->first);
                    LOG_INFO(0x100,"add  %s %lu ", fname, datalen);
#if TEST_VERION
                    exit=true;                    
#endif
                }
                free(data); 
            }
#if TEST_VERION
            if(exit) break;
#endif
        }
        pzipfile =NULL;
    }
    // try to decrypt files
    {
        cocos2d::CCFileUtilsAndroid* pFileUtils =  (cocos2d::CCFileUtilsAndroid*)cocos2d::CCFileUtils::sharedFileUtils();
        if(pFileUtils==NULL) LOG_ERR(0x100, " can not get pFileUtils ");
        LOG_INFO(0x100, "%p",pFileUtils);
        for(std::vector<std::string>::iterator it = encryptFiles.begin(); it!=encryptFiles.end(); it++)
        {
            const char* fname = it->c_str();
            unsigned long datalen=0l;
            void* data =  pFileUtils->getFileData(fname, "rb", &datalen);
            if(data!=NULL){
                _frida_hexdump(data, 0x20);
                char outputname[0x100];
                snprintf(outputname, 0x100, "%s/%s", outdir, fname);
                char *dname = dirname(outputname);
                // create folder for output file if need
                if(xis_dir(dname)!=1){
                    // create folder
                    //LOG_INFO(0x200," create folder %s for file %s", dname, outputname);
                    mkpath(dname, 0777);
                }
                // write file 
                {
                    LOG_INFO(0x200," %s => %s ", fname, outputname);
                    writeDataToFile(outputname, (unsigned char*)data, datalen);
                }
                free(data);
            }
#if TEST_VERION
            break;
#endif
        }
    }
    LOG_INFO(0x100, "go here , test ok");
    return 0;
}
