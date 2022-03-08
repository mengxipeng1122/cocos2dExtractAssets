
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

let frida_hexdump_callback =  new NativeCallback(function(p:NativePointer,n:number){
    fridautils.dumpMemory(p, n);
}, 'void', ['pointer','uint']);

var test0 = ()=>{
    // get apk path 
    Java.perform(function(){
        let current_application = Java.use('android.app.ActivityThread').currentApplication();
        var context = current_application.getApplicationContext();
        let packageName=context.getPackageName();
        let pm = context.getPackageManager();
        let ai = pm.getApplicationInfo(packageName,0);
        let apkpath = ai.publicSourceDir;
        let datapath = ai.dataDir;
        console.log('packageName', packageName)
        console.log('apkpath',apkpath.value);
        console.log('datapath',datapath.value);
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
            let m = Process.findModuleByName(soname);
            if(!m){ Module.load(soname); }
            let loadm = soutils.loadSo(info,{
                _frida_log : frida_log_callback,
                _frida_exit: frida_exit_callback,
                _frida_hexdump: frida_hexdump_callback,
            },[
                soname,
            ],'/data/local/tmp/')
            console.log(JSON.stringify(loadm));
            {
                let fun = new NativeFunction(loadm.syms.test, 'void', ['pointer' ,'pointer', 'pointer']);
                let pApkPath = Memory.allocUtf8String(apkpath.value);
                let pAssert  = Memory.allocUtf8String("assets/");
                let pDumpPath = Memory.allocUtf8String(datapath.value+'/dumps')
                fun(pApkPath, pAssert, pDumpPath);
            }
        }
    });
}

console.log('hello world')
test0()
