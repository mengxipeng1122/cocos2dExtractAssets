
import 'ts-frida'
import * as path from 'path'
// import * as libcocos2dExtractAssets_arm32 from './libcocos2dExtractAssets_arm32'
import {mod as libcocos2dExtractAssets_arm64} from './libcocos2dExtractAssets_arm64.js'


var dumpAssets = ()=>{

    if(Process.arch!='arm64'){
        throw `unsupported arch ${Process.arch}`
    }

    const apkInfo = MyFrida.getApkInfo();
    const {dataPath} = apkInfo;
    console.log('datapath',dataPath.value);
    const loadm = libcocos2dExtractAssets_arm64.load(
        '/data/local/tmp/libcocos2dExtractAssets.so',
        [
            'libgame.so',
        ],{
            ... MyFrida.frida_dummy_symtab([
                '__google_potentially_blocking_region_begin',
                '__google_potentially_blocking_region_end',
            ]),

            ... MyFrida.frida_symtab, 

        }
    );
        
    if(0)
    {
        const m = Process.getModuleByName('libgame.so');
        let fun = new NativeFunction(loadm.symbols.test, 'void', ['pointer', 'pointer']);
        let baseaddress = m.base;
        let pDumpPath = Memory.allocUtf8String(path.join(dataPath.value, 'dumps'))
        fun(baseaddress, pDumpPath);
    }
}

const hook_game = ()=>{

    const hooks : {p:NativePointer, name:string, opts:MyFrida.HookFunActionOptArgs}[] =[

    // _ZN7cocos2d18CCFileUtilsAndroid11getFileDataEPKcS2_Pm
    {
        p: Module.getExportByName('libgame.so', '_ZN7cocos2d18CCFileUtilsAndroid11getFileDataEPKcS2_Pm'),
        name: 'cocos2d::CCFileUtilsAndroid::getFileData(char const*, char const*, unsigned long*)',
        opts: {
            enterFun(args, tstr, thiz) {
                const path = args[1].readUtf8String();
                const mode = args[2].readUtf8String();
                console.log(tstr, path, mode);
            },
        },
    }
    ];

    hooks.forEach((h:{p:NativePointer, name:string, opts:MyFrida.HookFunActionOptArgs})=>{
        const {p, name, opts} = h;
        console.log('hook', JSON.stringify(h));
        MyFrida.HookAction.addInstance(p, new MyFrida.HookFunAction({...opts, name}));
    });


}

var entry = ()=>{
//    hook_game();
    dumpAssets();
}

console.log('##################################################')
Java.perform(entry)
