

'use strict';

let allocatedBufs:NativePointer[] = [];
import * as fridautils from './fridautils'
export type SoInfoType = {

    machine_type: string,
    load_size : number,
    name : string,

    loads : {
        virtual_address:number,
        virtual_size   :number,
        alignment      :number,
        file_offset    :number,
        size           :number,
        content        :number[],
    }[ ],

    exported_symbols:{name:string, address:number}[],

    relocations : {address:number, size:number, sym_name:string, type:number}[],

};

export type LoadSoInfoType = {
    buff: NativePointer,
    syms: {[key:string]:NativePointer} ,
};

function resolveSymbol(sym_name:string, loadedSyms?:{[key:string]:NativePointer}, syms?:{[key:string]:NativePointer}, libs?:string[] ){
    if (loadedSyms!=undefined && sym_name in loadedSyms) return loadedSyms[sym_name];
    if (syms!=undefined && sym_name in syms) return syms[sym_name];
    {
        let found = false;
        let symp = ptr(0);
        if(libs!=undefined){
            libs.forEach(soname=>{
                if(found) return;
                let p = Module.findExportByName(soname,sym_name);
                if(p!=undefined&&!p.equals(0)) {found=true; symp=p;}
                let m = Process.getModuleByName(soname);
                if(m!=undefined && found==false){
                    m.enumerateSymbols()
                        .filter(e=>{
                            return e.name==sym_name;
                        })
                        .forEach(e=>{
                            found=true;
                            symp=e.address;
                        })
                }
            })
        }
        if(found) return symp;
    }
    {
        let p = Module.findExportByName(null, sym_name);
        if(p!=undefined&&!p.equals(0)) return p;
    }
}

export function loadSo(info:SoInfoType, syms?:{[key:string]:NativePointer}, libs?:string[], dir?:string):LoadSoInfoType
{
    // sanity check
    let arch = Process.arch;
    if(arch=='arm'){
        if(info.machine_type!='ARM')  throw `archtecture mismatch ${info.machine_type}/${Process.arch}`
    }
    else if (arch=='arm64'){
        if(info.machine_type!='AARCH64')  throw `archtecture mismatch ${info.machine_type}/${Process.arch}`
    }
    else{
        throw `unsupported archtecture ${arch}`
    }

    let buff = Memory.alloc(info.load_size);
    Memory.protect(buff, info.load_size, 'rwx');
    // allocate memory fot new so
    {
        info.loads.forEach(l=>{
            // load 
            let content = new Uint8Array(l.content);
            buff.add(l.virtual_address).writeByteArray(fridautils.typedArrayToBuffer(content));
        })
    }

    // handle export syms
    let loadedSyms:{[key:string]:NativePointer} ={};
    {
        info.exported_symbols.forEach(s=>{
            let p = buff.add(s.address);
            loadedSyms[s.name] = p;
        })
    }

    // handle relocations for hot patch 
    {
        info.relocations.forEach(r=>{
            if (r.type==23) { // R_ARM_RELATIVE
                if(r.size != 32) throw `only support for 32bits now`
                let p =buff.add(r.address).readPointer();
                buff.add(r.address).writePointer(p.add(buff));
            }
            else if (r.type==21) { // R_ARM_GLOB_DAT
                if(r.size != 32) throw `only support for 32bits now`
                let p = resolveSymbol(r.sym_name, loadedSyms, syms, libs);
                if(p!=undefined&&!p.equals(0)){
                    buff.add(r.address).writePointer(p) ;
                }
            }
            else if (r.type==22) { // R_ARM_JUMP_SLOT
                if(r.size != 32) throw `only support for 32bits now`
                let p = resolveSymbol(r.sym_name, loadedSyms, syms, libs);
                console.log('R_ARM_JUMP_SLOT', ptr(r.address), r.sym_name, p);
                if(p!=undefined&&!p.equals(0)){
                    buff.add(r.address).writePointer(p) ;
                }
            }
            else if (r.type==2) { // R_ARM_ABS32
                if(r.size != 32) throw `only support for 32bits now`
                let p = resolveSymbol(r.sym_name, loadedSyms, syms, libs);
                if(p!=undefined&&!p.equals(0)){
                    buff.add(r.address).writePointer(p) ;
                }
            }
            else if (r.type==257) { // R_AARCH64_ABS64
                if(r.size != 64) throw `only support for 64bits now`
                let p = resolveSymbol(r.sym_name, loadedSyms, syms, libs);
                if(p!=undefined&&!p.equals(0)){
                    buff.add(r.address).writePointer(p);
                }
            }
            else if (r.type==1025) { // R_AARCH64_GLOB_DA
                if(r.size != 64) throw `only support for 64bits now`
                let p = resolveSymbol(r.sym_name, loadedSyms, syms, libs);
                if(p!=undefined&&!p.equals(0)){
                    buff.add(r.address).writePointer(p);
                }
            }
            else if (r.type==1026) { // R_AARCH64_JUMP_SL
                if(r.size != 64) throw `only support for 64bits now`
                let p = resolveSymbol(r.sym_name, loadedSyms, syms, libs);
                if(p!=undefined&&!p.equals(0)){
                    buff.add(r.address).writePointer(p);
                }
            }
            else if (r.type==1027) { // R_AARCH64_RELATIV
                if(r.size != 64) throw `only support for 64bits now`
                let p =buff.add(r.address).readPointer();
                buff.add(r.address).writePointer(p.add(buff));
            }
            else{
                throw `unhandle relocation type ${r.type}`
            }
        })
    }
//    Memory.protect(buff, info.load_size, 'r-x');

    // dump for debug
    if(false)
    {
        let fn = '/data/data/com.sincetimes.fknsg/dump.'+info.name+'.'+buff+'.dump'
        fridautils.dumpMemoryToFile(buff, info.load_size, fn)
    }

    return {buff:buff, syms:loadedSyms};
}
