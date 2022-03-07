
import * as soutils from './tsmodules/soutils'
import * as fridautils from './tsmodules/fridautils'
// load compiled ts module
import * as libcocos2dExtractAssets_arm32 from './tsmodules/libcocos2dExtractAssets_arm32'
import * as libcocos2dExtractAssets_arm64 from './tsmodules/libcocos2dExtractAssets_arm64'
import { Console } from 'console';

let frida_log_callback =  new NativeCallback(function(sp:NativePointer){
    let s = sp.readUtf8String();
    console.log(s);
}, 'void', ['pointer']);

let frida_exit_callback =  new NativeCallback(function(){
    console.log('exit');
}, 'void', []);

let iterRBTree = function(p:NativePointer){
    if(p.equals(0)) return;
    let k = p.add(0x20).readPointer().readUtf8String();
    console.log(k);
    let left = p.add(0x10).readPointer();
    iterRBTree(left);
    let right = p.add(0x18).readPointer();
    iterRBTree(right);
}

let frida_hexdump_callback =  new NativeCallback(function(p:NativePointer,n:number){
    fridautils.dumpMemory(p, n);
    // debug 
    //let pp = p.add(0x8).readPointer().add(8).add(0x10).readPointer();
    //fridautils.dumpMemory(pp, 0x40);
    //iterRBTree(pp);

}, 'void', ['pointer','uint']);

// .text:0000000000240F84 ; bt_decrypt(unsigned char *, unsigned long *)
// .text:0000000000240F84                 EXPORT _Z10bt_decryptPhPm
// .text:0000000000240F84 _Z10bt_decryptPhPm 

var test0 = ()=>{
    let soname = 'libgame.so'
    fridautils.hookDlopen(soname,()=>{
        console.log('loaded')
        let funs=[
{enable:false,soname:soname, loc:"_ZN7cocos2d11CCFileUtils11getFileDataEPKcS2_Pm", enterFun:function(args:NativePointer[], tstr:string, thiz:InvocationContext, userdata: any ){
}, leaveFun:function (retval:NativePointer, tstr:string, thiz:InvocationContext, userdata: any){
}, },
{soname:soname, loc:"_ZN7cocos2d7ZipFile11getFileDataERKSsPm", enterFun:function(args:NativePointer[], tstr:string, thiz:InvocationContext, userdata: any ){
    let s1 = args[1].readPointer().readUtf8String();
    console.log(s1);
}, leaveFun:function (retval:NativePointer, tstr:string, thiz:InvocationContext, userdata: any){
    fridautils.dumpMemory(retval);
}, },
{soname:soname, loc:"_ZN7cocos2d7ZipFileC2ERKSsS2_", enterFun:function(args:NativePointer[], tstr:string, thiz:InvocationContext, userdata: any ){
    let s1 = args[1].readPointer().readUtf8String();
    let s2 = args[2].readPointer().readUtf8String();
    console.log(s1,s2)
}, leaveFun:function (retval:NativePointer, tstr:string, thiz:InvocationContext, userdata: any){
}, },
{enable:false,soname:null, loc:"fopen", enterFun:function(args:NativePointer[], tstr:string, thiz:InvocationContext, userdata: any ){
    let s1 = args[0].readUtf8String();
    let s2 = args[1].readUtf8String();
    console.log(tstr,s1,s2)
}, leaveFun:function (retval:NativePointer, tstr:string, thiz:InvocationContext, userdata: any){
}, },
{enable:false,soname:soname, loc:"_ZN7cocos2d18CCFileUtilsAndroid11getFileDataEPKcS2_Pm", enterFun:function(args:NativePointer[], tstr:string, thiz:InvocationContext, userdata: any ){
    let s1 = args[1].readUtf8String();
    let s2 = args[2].readUtf8String();
    console.log(tstr,s1,s2)
    thiz.szptr = args[3]
}, leaveFun:function (retval:NativePointer, tstr:string, thiz:InvocationContext, userdata: any){
    console.log(tstr,thiz.szptr.readU32())
    fridautils.dumpMemory(retval)
}, },
        ]
        fridautils.hookFunList(funs);
            
    });
}

var test0 = ()=>{
    Java.perform(function(){
        let soname = 'libgame.so';
        console.log('arch', Process.arch);
        console.log('andriod version', Java.androidVersion);
        let m = Process.getModuleByName(soname);
        if(!m) throw `can find module ${soname}`;
        const cm = new CModule(`
            extern void _frida_log(char*); 
            extern void _frida_exit();
            extern void _frida_hexdump(void*, unsigned int);

            extern int snprintf(char *str, int size, const char *format, ...);
            extern void *malloc(unsigned int size);
            extern void free(void *ptr);
            extern void string_ctor(void* ptr, char* s, void* ); // constructor of std::string class
            // extern void string_dtor(void* ptr); // destructor of std::string class, need not to call ?
            extern void _ZN7cocos2d7ZipFileC2ERKSsS2_(void*, void*, void*); // cocos2d::ZipFile::ZipFile(std::string const&,std::string const&)
            extern void _ZN7cocos2d7ZipFileD2Ev(void*);// __fastcall cocos2d::ZipFile::~ZipFile(cocos2d::ZipFile *__hidden this)
//            extern void* _ZN7cocos2d7ZipFile11getFileDataERKSsPm(void*, void*, unsigned long *); // cocos2d::ZipFile::getFileData(std::string const&, unsigned long *)
     
            //////////////////////////////////////////////////                
            // help macros
            #define STRING_OBJ_SIZE  0x20
            #define ZIPFILE_OBJ_SIZE 0x20
            #define NULL ((void*)0)
            #define LOG_INFO(N,fmt, args...) do{                                     \
                char buf[N];                                                         \
                snprintf(buf,N, "[%s:%d]" fmt , __FILE__, __LINE__, ##args);         \
                _frida_log(buf);                                                     \
            }while(0)                                                               

            //////////////////////////////////////////////////                
            // utils functions
            struct RBTreeNode {
                // unknonw  
                unsigned char _unknown[0x10];                 //offset 0x00
                void*    pred ; // pointer to red node        //offset 0x10
                void*    pblack; // pointer to black node     //offset 0x18
                void*    pstring;// pointer to key            //offset 0x20
            };
            //////////////////////////////////////////////////                
            // global variables
            void* pzipfile = NULL;
            void iterRBTree(struct RBTreeNode* p){
                if(p==(void*)0) return;
                char* key = (char*)p->pstring;
                // show key
                LOG_INFO(0x100, "%s", key);
                //iterRBTree((struct RBTreeNode*)(p->pred));
                //iterRBTree((struct RBTreeNode*)(p->pblack));

                // create a std::string instance 
                void* pstring = malloc(STRING_OBJ_SIZE);
                if(!pstring){
                    LOG_INFO(0x80, "malloc failed");
                    _frida_exit();
                }
                string_ctor(pstring, key, NULL);
                if(pzipfile==NULL){
                    LOG_INFO(0x80, "pzipfile is NULL");
                    _frida_exit();
                }
                // unsigned long datalen=0l;
                // unsigned char* data = _ZN7cocos2d7ZipFile11getFileDataERKSsPm(pzipfile, pstring, &datalen);
                // if(data==NULL){
                //     LOG_INFO(0x80, "data is NULL");
                //     _frida_exit();
                // }
                // LOG_INFO(0x80, "data %p %l", data, datalen);
                // free(data);
                free(pstring);
            }

            void test(void) {

                char* apkname =  "/data/app/com.sincetimes.fknsg-d8Ac2pGqTUviPk4Dm_Ylvw==/base.apk"; 
                char* path = "assets/";
                // print some info for debug
                LOG_INFO(0x100, "sizeof(int) %d", sizeof(int));
                LOG_INFO(0x100, "sizeof(long) %d", sizeof(long));
                LOG_INFO(0x100, "sizeof(void*) %d", sizeof(void*));
                
                LOG_INFO(0x100, "go here ");
                void* pcstring0 = malloc(STRING_OBJ_SIZE);
                if(!pcstring0){
                    LOG_INFO(0x80, "malloc failed");
                    _frida_exit();
                }
                string_ctor(pcstring0, apkname, NULL);
                LOG_INFO(0x100, "go here ");
                void* pcstring1 = malloc(STRING_OBJ_SIZE);
                if(!pcstring1){
                    LOG_INFO(0x80, "malloc failed");
                    _frida_exit();
                }
                string_ctor(pcstring1, path, NULL);
                LOG_INFO(0x100, "go here 111");

#if 0
                pzipfile = malloc(ZIPFILE_OBJ_SIZE);
                if(!pzipfile){
                    LOG_INFO(0x80, "malloc failed");
                    _frida_exit();
                }
                LOG_INFO(0x100, "go here 111");
                _ZN7cocos2d7ZipFileC2ERKSsS2_(pzipfile, pcstring0, pcstring1);
                LOG_INFO(0x100, "go here ");

                // inspect zipfile
                void* pRBTree = NULL;
                LOG_INFO(0x100, "go here ");
                {
                    // get RBTree pointer from  ZipFile instance pointer
                    unsigned char* _p = (unsigned char*) pzipfile;
                    _p = (unsigned char*)*(void**)(_p+0x8);
                    _p = (unsigned char*)*(void**)(_p+0x18);
                    pRBTree= _p;
                }
                LOG_INFO(0x100, "go here ");
                //iterRBTree(pRBTree);
                _ZN7cocos2d7ZipFileD2Ev(pzipfile);
                LOG_INFO(0x100, "go here ");
                
                // string_dtor(pcstring1);
                // string_dtor(pcstring0);
                LOG_INFO(0x100, "go here ");
                free(pzipfile);
                pzipfile =NULL;
#endif
                free(pcstring1);
                free(pcstring0);
            }
        `,
            // all extern symbols;
            {
                _frida_log                      : frida_log_callback,
                _frida_exit                     : frida_exit_callback,
                _frida_hexdump                  : frida_hexdump_callback,
                snprintf                        : Module.getExportByName(null, "snprintf"),
                malloc                          : Module.getExportByName(null, "malloc"),
                free                            : Module.getExportByName(null, "free"),
                string_ctor                     : m.base.add(0x70E29C),
                //string_dtor                     : m.base.add(0x70E29C),
                _ZN7cocos2d7ZipFileC2ERKSsS2_   : Module.getExportByName(soname,'_ZN7cocos2d7ZipFileC2ERKSsS2_') ,
                _ZN7cocos2d7ZipFileD2Ev         : Module.getExportByName(soname,'_ZN7cocos2d7ZipFileD2Ev') ,
//                _ZN7cocos2d7ZipFile11getFileDataERKSsPm : Module.getExportByName(soname,'_ZN7cocos2d7ZipFile11getFileDataERKSsPm') ,
            }
        );
        console.log(JSON.stringify(cm));
        new NativeFunction(cm.test, 'void', [])();
    });
}
var test0 = ()=>{
    // get apk path 
    Java.perform(function(){
        let current_application = Java.use('android.app.ActivityThread').currentApplication();
        var context = current_application.getApplicationContext();
        let packageName=context.getPackageName();
        let pm = context.getPackageManager();
        let ai = pm.getApplicationInfo(packageName,0);
        let apkpath = ai.publicSourceDir;
        console.log('packageName', packageName, apkpath.value);
        // debug
        {
            let soname = 'libgame.so';
            console.log('arch', Process.arch);
            console.log('andriod version', Java.androidVersion);
            let info;
            if(Process.arch=='arm'){
                info = libcocos2dExtractAssets_arm32.info;
            }
            else if(Process.arch=='arm64'){
                info = libcocos2dExtractAssets_arm64.info;
            }
            else{
                throw `unsupported arm ${Process.arch}`
            }
            let m = Process.getModuleByName(soname);
            let loadm = soutils.loadSo(info,{
                _frida_log : frida_log_callback,
                _frida_exit: frida_exit_callback,
                _frida_hexdump: frida_hexdump_callback,
            },[
                soname,
            ])
            console.log(JSON.stringify(loadm));
            // debug
            //if(false)
            {
            }
            {
                let fun = new NativeFunction(loadm.syms.test, 'void', ['pointer' ,'pointer']);
                fun(Memory.allocUtf8String(apkpath.value), Memory.allocUtf8String("assets/"));
            }
        }
    });
}

console.log('hello world')
test0()
