
import 'ts-frida'
import * as path from 'path'
// import * as libcocos2dExtractAssets_arm32 from './libcocos2dExtractAssets_arm32'
import {mod as libcocos2dExtractAssets_arm64} from './modinfos/libcocos2dExtractAssets_arm64.js'


const soname = 'libgame.so'

const load_patched_lib = ()=>{

    const mod = libcocos2dExtractAssets_arm64.load(
        '/data/local/tmp/libcocos2dExtractAssets.so',
        [
            soname,
        ],{
            ... MyFrida.frida_dummy_symtab([
                '__google_potentially_blocking_region_begin',
                '__google_potentially_blocking_region_end',
            ]),

            ... MyFrida.frida_symtab, 

        }
    );

    add_rpc_funs(mod);

    return mod;
}
        
type HOOK_TYPE = {
    p:NativePointer,
    name:string,
    opts:MyFrida.HookFunActionOptArgs,
}

const add_rpc_funs = (mod:MyFrida.PATHLIB_INFO_TYPE)=>{

    const baseaddress = Process.getModuleByName(soname).base;

    const fun_map : {[key:string]:(arg:any)=>any} = {
        getAssetsList: (arg:any):string[] => {
            const assetsList :string[] = [];
            const cb = new NativeCallback(function (p:NativePointer){
                        const name = p.readUtf8String();
                        if(name){
                            assetsList.push(name);
                        }
                    }, 'void', ['pointer']);
            if (mod.symbols.getAssetsList) {
                const ret = new NativeFunction(mod.symbols.getAssetsList, 'int', ['pointer','pointer'])(baseaddress, cb)
            }
            return assetsList;
        },

        getAssetBinary: (arg:string):ArrayBuffer|null=>{
            const path = arg;
            let data:ArrayBuffer|null = null;
            const cb = new NativeCallback(function (p:NativePointer, sz:number){
                const readed     = p.readByteArray( sz);
                if(readed){
                    data = readed;
                }
            }, 'void', ['pointer', 'int']);
            if (mod.symbols.getAssetBinary) {
                const ret = new NativeFunction(mod.symbols.getAssetBinary, 
                    'int', ['pointer','pointer','pointer'])(baseaddress, Memory.allocUtf8String(path), cb)
                if(ret<0){
                    return null;
                }
            }
            return data;
        },


    };

    rpc.exports.invoke_frida_function = (fun:string, arg:any) =>{
        if (fun_map[fun]){
            return fun_map[fun](arg);
        }
    }

    // 
    // fun_map.getAssetsList([])
}

const patch_game = (mod:MyFrida.PATHLIB_INFO_TYPE)=>{

}

const hook_game = (mod:MyFrida.PATHLIB_INFO_TYPE)=>{

    const hooks : HOOK_TYPE[] =[

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

    hooks.forEach((h:HOOK_TYPE)=>{
        const {p, name, opts} = h;
        console.log('hook', JSON.stringify(h));
        MyFrida.HookAction.addInstance(p, new MyFrida.HookFunAction({...opts, name}));
    });


}

const explore_game = (mod:MyFrida.PATHLIB_INFO_TYPE)=>{

}

var entry = ()=>{
    const mod = load_patched_lib();

    patch_game(mod);
    hook_game(mod);
    explore_game(mod);

}

if(Process.arch!='arm64'){
    throw `unsupported arch ${Process.arch}`
}

console.log('##################################################')
Java.perform(entry)
