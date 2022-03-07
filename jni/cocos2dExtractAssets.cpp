
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <map>
#include <vector>

extern "C" void _frida_log(char*); 
extern "C" void _frida_exit();
extern "C" void _frida_hexdump(void*, unsigned int);


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
        unsigned char _dummy[ZIPFILE_OBJ_SIZE];
        // extern "C" void _ZN7cocos2d7ZipFileC2ERKSsS2_(void*, void*, void*); // cocos2d::ZipFile::ZipFile(std::string const&,std::string const&)
        ZipFile(std::string const&, std::string const&);
        // extern "C" void* _ZN7cocos2d7ZipFile11getFileDataERKSsPm(void*, void*, unsigned long *); // cocos2d::ZipFile::getFileData(std::string const&, unsigned long *)
        unsigned char* getFileData(std::string const&, unsigned long *);
        //_ZN7cocos2d7ZipFileD2Ev(pzipfile);
        ~ZipFile();
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


//////////////////////////////////////////////////                
// utils functions
//////////////////////////////////////////////////                
// global variables
extern "C" int test(char* apkName, char* path) 
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
        std::string sApkname(apkName);
        std::string sPath( path);
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

        cocos2d::ZipFile zipfile(sApkname, sPath);
        cocos2d::ZipFile* pzipfile = &zipfile;

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
            const char* fname = it->first.c_str();
            std::string name(fname);
            unsigned long datalen=0l;
            unsigned char* data = pzipfile->getFileData(name, &datalen);
            if(data!=NULL){
                // _frida_hexdump(data, 0x20);
                if(!memcmp(data, "\xfe\xfe\xfe\xfe", 4)){
                    encryptFiles.push_back(it->first);
                    LOG_INFO(0x100,"add  %s %lu ", fname, datalen);
                }
                free(data); 
            }
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
                LOG_INFO(0x100," fname %s %lu ", fname, datalen);
                _frida_hexdump(data, 0x20);
                free(data);
            }
            break; // only for test
        }
    }
    LOG_INFO(0x100, "go here , test ok");
    return 0;
}
