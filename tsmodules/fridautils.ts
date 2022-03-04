
'use strict';

import { type } from 'os';
import * as path from 'path'

export interface HookFunInfo{
    enable?: boolean;
    soname: string | null; // offset or name
    loc: string | NativePointer; // offset or name
    nparas?: number;
    hide?: boolean;
    enterFun?: CallbackFunctionEnter;
    leaveFun?: CallbackFunctionLeave;
};
type CallbackFunctionEnter =  (args:NativePointer[], tstr:string, thiz:InvocationContext, userdata: any)=>void;
type CallbackFunctionLeave =  (retval:NativePointer, tstr:string, thiz:InvocationContext, userdata: any)=>void;

var tlevel = 0;
export function hookFunList (funs:HookFunInfo[], hooks?:InvocationListener[], userdata?:any) {
    funs.forEach(fun=>{
            if(fun.enable == undefined) fun.enable = true;
            if(fun.enable) { 
                var address:NativePointer | null;
                let soname      = fun.soname
                let loc         = fun.loc 
                let nparas      = fun.nparas !=undefined?fun.nparas : 4;
                let hide        = fun.hide != undefined ?fun.hide : false;
                if(typeof(loc) == 'string') {
                    address = Module.findExportByName(soname, loc);
                    if(address==null && soname !=null){
                        let m = Process.getModuleByName(soname);
                        m.enumerateSymbols()
                            .forEach(e=>{
                                if(e.name==fun.loc)address = e.address;
                            })
                    }
                }
                else if(soname !=null){
                    if(soname==null) throw `soname can be null when loc is an offset ,${JSON.stringify(fun)}`
                    address = Process.getModuleByName(soname).base.add(loc);
                }
                else {
                    throw(`can not found ${loc} at ${soname}`);
                }
                if(address==null)throw `address is null when handle ${JSON.stringify(fun)}`
                console.log('hooking', fun.soname, fun.loc, address);
                let hookLisener = Interceptor.attach(address, {
                    onEnter: function (args:NativePointer[]) {
                        this.loc=loc ; // set loc 
                        tlevel++;
                        let tstr = "  ".repeat(tlevel);
                        var targs:string[]=[]
                        for(var i = 0;i<nparas; i++){targs.push(args[i].toString());}
                        if(!hide) {
                            let tloc = JSON.stringify({soname:fun.soname, loc:fun.loc});
                            console.log(tstr,'enter', tloc,  ' (' ,targs.join(',') , ')')
                        }
                        if(fun.enterFun) fun.enterFun(args, tstr, this, userdata);
                    },
                    onLeave: function (retval) {
                        let tstr = "  ".repeat(tlevel);
                        if(!hide){
                            let tloc = JSON.stringify({soname:fun.soname, loc:fun.loc});
                            console.log(tstr,'leave' , tloc , retval);
                        }
                        if(fun.leaveFun)fun.leaveFun(retval,tstr, this, userdata);
                        tlevel--;
                    },
                });
                if(hooks!=undefined) hooks.push(hookLisener);
        }
    });
}

export function hookDlopen(soname:string, afterFun:()=>void, beforeFun?:()=>void|null) {
    var afterDone=false;
    var beforeDone=false;
    let funs = ['dlopen', 'android_dlopen_ext']
    funs.forEach(fun=>{
    let funptr = Module.getExportByName(null, fun);
        Interceptor.attach(funptr, {
            onEnter: function (args) {
                const loadpath = args[0].readUtf8String();
                this.loadpath = loadpath;
                if(loadpath==null) return;
                if(path.basename(loadpath)==soname){
                    if(!beforeDone){ 
                        if(beforeFun!=undefined) {beforeFun();}
                    }
                    beforeDone=true;
                }
            },
            onLeave: function (retval) {
                if(this.loadpath==undefined) return;
                if(!afterDone) {
                    if ( retval.toUInt32() != 0) {
                        if (path.basename(this.loadpath) == soname){
                            afterFun();
                            afterDone=true;
                        }
                    }
                }
            },
        });
    })
}

export function hookFunListByDlopen (funs:HookFunInfo[] ,soname:string, userdata:any) {
    hookDlopen(soname, function(){
        hookFunList(funs, userdata);
    }, function(){});
}

export function dumpMemoryToFile(p:NativePointer, l:number, fn:string, tstr?:string|undefined) {
    if (tstr==undefined) tstr="";
    console.log(tstr+'p '+ p + ' ' + l + ' to ' + fn)
    try{
        let f = new File(fn, "wb");
        if(f==null) throw 'can not open file to write '
        let content = p.readByteArray(l) 
        if( content==null) throw 'can not read memory '
        f.write(content)
        f.close();
    }
    catch(err) {
        console.log(err);
    }
}

export function typedArrayToBuffer(array: Uint8Array): ArrayBuffer {
    return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset) as ArrayBuffer
}

export function alignNum(n:number, align:number){
    return Math.floor((n+align-1)/align) *align
}

export function dumpMemory(p:NativePointer, l?:number|undefined) {
    if (l == undefined) l = 0x20;
    console.log(hexdump(p, {
        offset: 0,
        length: l,
        header: true,
        ansi: false
    }));
};

export function showAsmCode(p:NativePointer, count?: number| undefined){
    if (count == undefined) count = 5;
    let addr = p;
    for(var i = 0; i<count; i++){
        const inst = Instruction.parse(addr);
        console.log(addr, inst.toString())
        addr = addr.add(inst.size);
    }
}

export function hookRegisterNatives(clzname?:string, handles?: Map<string, InvocationListenerCallbacks> ){
    var addrRegisterNatives = null;
    const module = Process.findModuleByName("libart.so");
    if(module){
        module.enumerateSymbols()
            .forEach(symbol=>{
            //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
            if (symbol.name.indexOf("art") >= 0 &&
                symbol.name.indexOf("JNI") >= 0 && 
                symbol.name.indexOf("RegisterNatives") >= 0 && 
                symbol.name.indexOf("CheckJNI") < 0) {
                addrRegisterNatives = symbol.address;
                console.log("RegisterNatives is at ", symbol.address, symbol.name);
                Interceptor.attach(addrRegisterNatives,{
                    onEnter:(args)=>{
                        var env = args[0];
                        var java_class = args[1];
                        var class_name = Java.vm.tryGetEnv().getClassName(java_class);
                        var methods_ptr = args[2];
                        var method_count = args[3].toUInt32();
                        for (var i = 0; i < method_count; i++) {
                            var name = methods_ptr.add(i*Process.pointerSize*3+0x00).readPointer().readCString();
                            var sig = methods_ptr.add(i*Process.pointerSize*3+Process.pointerSize).readPointer().readUtf8String();
                            var fnPtr_ptr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
                            var find_module=Process.findModuleByAddress(fnPtr_ptr);
                            if(clzname){
                                if(class_name.includes(clzname)){
                                    console.log("[RegisterNatives] java_class:", class_name, "name:", name, "sig:", sig, "fnPtr:", fnPtr_ptr, JSON.stringify(find_module));
                                    if(name && handles!=undefined){
                                        const h = handles.get(name);
                                        if(h){
                                            Interceptor.attach(fnPtr_ptr,h);
                                            console.log(name,'attached');
                                        }
                                    }
                                }
                            }
                            else{
                                console.log("[RegisterNatives] java_class:", class_name, "name:", name, "sig:", sig, "fnPtr:", fnPtr_ptr);
                            }
                        }
                    },
                    onLeave:(retval)=>{},
                });
            }
        })
        return ;
    }
    console.log('can not found RegisterNativates function')
}

export function copyfile(fn: string, dfn:string){
    Java.perform(function(){
        const File = Java.use('java.io.File');
        const FileInputStream = Java.use('java.io.FileInputStream');
        const FileOutputStream = Java.use('java.io.FileOutputStream');
        const BufferedInputStream = Java.use('java.io.BufferedInputStream');
        const BufferedOutputStream = Java.use('java.io.BufferedOutputStream');
        var sourceFile = File.$new.overload('java.lang.String').call(File, fn);
        if (sourceFile.exists() && sourceFile.canRead()) {
            var destinationFile = File.$new.overload('java.lang.String').call(File, dfn);
            destinationFile.createNewFile();
            var fileInputStream = FileInputStream.$new.overload('java.io.File').call(FileInputStream, sourceFile);
            var fileOutputStream = FileOutputStream.$new.overload('java.io.File').call(FileOutputStream, destinationFile);
            var bufferedInputStream = BufferedInputStream.$new.overload('java.io.InputStream').call(BufferedInputStream, fileInputStream);
            var bufferedOutputStream = BufferedOutputStream.$new.overload('java.io.OutputStream').call(BufferedOutputStream, fileOutputStream);
            var data = 0;
            while ((data = bufferedInputStream.read()) != -1) {
                bufferedOutputStream.write(data);
            }
            bufferedInputStream.close();
            fileInputStream.close();
            bufferedOutputStream.close();
            fileOutputStream.close();
        }
        else {
            console.log('Error : File cannot read.')
        }
    })
}

export function dumpSo(name:string, outputDir?:string){
    outputDir = outputDir !=undefined? outputDir :  "/mnt/sdcard/";
    let m = Process.getModuleByName(name);
    let fn = outputDir+m.name+'.'+m.base+'.dump';
    dumpMemoryToFile(m.base, m.size, fn);
}

export function dumpProgress(thiz:InvocationContext, outputDir?:string){
    let infos: {[k: string]: any}[] = [];
    Process.enumerateRanges('')
        .forEach(m=>{
            let fn = outputDir+'/' + m.base+'.dump'
            let obj:{[k: string]: any} = m;
            obj.fn=fn;
            infos.push(obj);
            dumpMemoryToFile(m.base, m.size, fn);
        })
    let s = JSON.stringify({context:thiz.context,infos:infos});
    let n = s.length;
    let sbuf=Memory.allocUtf8String(s);
    dumpMemory(sbuf, 0x80);
    console.log('n',ptr(n));
    let fn = "/mnt/sdcard/dumpInfos.json"
    dumpMemoryToFile(sbuf, n, fn);
}

export function findInstructInso(wantinst:string, soname:string){
    console.log('find', wantinst, 'in', soname)
    let m = Process.getModuleByName(soname);
    let addr = m.base;
    do{
        try{
            let inst = Instruction.parse(addr);
            if(inst.mnemonic.toLowerCase().includes(wantinst)){
                console.log(addr, inst.toString(),'@',m.name, addr.sub(m.base));
            }
            addr=addr.add(inst.size);
        }
        catch{
            addr=addr.add(2);
        }
    } while(addr.compare(m.base.add(m.size))<0);
    console.log('end find', soname)
}

export function listAllAssetFiles(){
    Java.perform(function(){
        function listAssetFiles(assets_manager:any, path:string) {
            function typedArrayToBuffer(array: Uint8Array): ArrayBuffer {
                return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset) as ArrayBuffer
            }
            try{
                let assetsList = assets_manager.list(path) as Array<string>;
                if(assetsList.length==0){
                    // is a file
                    let f = assets_manager.open(path);
                    console.log('path', path, f.available());
                    //let bufflen = 0x1000;
                    //let  buffer = Java.array('byte', new Array(bufflen).fill(0));
                    //let memory = Memory.alloc(bufflen);
                    //let x;
                    //while ((x = f.read(buffer)) != -1) {
                    //    for(let t = 0;t<x;t++){
                    //        memory.add(t).writeS8(buffer[t]);
                    //    }
                    //    fridautils.dumpMemory(memory)
                    //    console.log(x);
                    //}
                    f.close();
                }
                assetsList.forEach(e => {
                    let newpath;
                    if(path=='') newpath=e
                    else newpath=path+'/'+e;
                    listAssetFiles(assets_manager,newpath)
                });
            }
            catch(e){
                // path is a file
                console.log(e);
            }
            // console.log('asserts', JSON.stringify(assetsList))
        }
        let current_application = Java.use('android.app.ActivityThread').currentApplication();
        var context = current_application.getApplicationContext();
        console.log('current_appliction', current_application);
        let assets_manager = context.getAssets();
        listAssetFiles(assets_manager,'');
    })
}

export function showBacktrace(thiz:InvocationContext, tstr?:string)
{
    var callbacktrace = Thread.backtrace(thiz.context,Backtracer.ACCURATE);
    console.log(tstr!=undefined?tstr:"", ' callbacktrace ' + callbacktrace);
    callbacktrace.forEach(c=>{
        let sym =DebugSymbol.fromAddress(c);
        console.log(tstr!=undefined?tstr:"", c, '=>', sym);
    })
}

export function resolveSymbol(name:string, libs?:string[])
{
    try{
        let resolved = false;
        let address:NativePointer=ptr(0);
        if(!resolved){
            if(libs!=undefined){
                libs.forEach(soname=>{
                    if(!resolved){
                        try{
                            address = Module.getExportByName(soname, name);
                            resolved = true;
                        }
                        catch(_e){
                            // pass
                            // console.log(`can not get address for ${name} in ${soname}`)
                        }
                    }
                })
            }
        }
        if(!resolved){
            try{
            address = Module.getExportByName(null, name);
            resolved=true;
            }
            catch(_e){
                //pass
                //console.log(` resolve symbol ${name} failed with error ${result}`);
            }
        }
        if(resolved) {
            //console.log(`resloved ${name} with ${address} ${buffer.add(gotOffset+offset)}`)
            return address;
        }
        else{
            console.log(`resolve symbol ${name} failed`);
        }
    }
    catch(_e){
        let result = JSON.stringify(_e);
        console.log(` resolve symbol ${name} failed with error ${result}`);
    }
}
