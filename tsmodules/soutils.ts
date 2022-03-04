

'use strict';

let allocatedBufs:NativePointer[] = [];
import * as fridautils from './fridautils'
export type SoInfoType = {

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


export function loadSo(info:SoInfoType, syms?:{[key:string]:NativePointer}, libs?:string[], dir?:string):LoadSoInfoType
{
    let buff = Memory.alloc(info.load_size)
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
                if (loadedSyms!=undefined && r.sym_name in loadedSyms){
                    let p = loadedSyms[r.sym_name];
                    buff.add(r.address).writePointer(p) ;
                }
                else if(syms!=undefined && r.sym_name in syms){
                    let p = syms[r.sym_name];
                    buff.add(r.address).writePointer(p) ;
                }
                else{
                    let p = fridautils.resolveSymbol(r.sym_name,libs);
                    if(p!=undefined&&!p.equals(0)){
                        buff.add(r.address).writePointer(p) ;
                    }
                }
            }
            else if (r.type==22) { // R_ARM_JUMP_SLOT
                if(r.size != 32) throw `only support for 32bits now`
                if (loadedSyms!=undefined && r.sym_name in loadedSyms){
                    let p = loadedSyms[r.sym_name];
                    buff.add(r.address).writePointer(p) ;
                }
                else if(syms!=undefined && r.sym_name in syms){
                    let p = syms[r.sym_name];
                    buff.add(r.address).writePointer(p) ;
                }else {
                    let p = fridautils.resolveSymbol(r.sym_name,libs);
                    if(p!=undefined&&!p.equals(0)){
                        buff.add(r.address).writePointer(p) ;
                    }
                }
            }
            else if (r.type==2) { // R_ARM_ABS32
                if(r.size != 32) throw `only support for 32bits now`
                if (loadedSyms!=undefined && r.sym_name in loadedSyms){
                    let p = loadedSyms[r.sym_name];
                    buff.add(r.address).writePointer(p) ;
                }
                else if(syms!=undefined && r.sym_name in syms){
                    let p = syms[r.sym_name];
                    buff.add(r.address).writePointer(p) ;
                }else {
                    let p = fridautils.resolveSymbol(r.sym_name,libs);
                    if(p!=undefined&&!p.equals(0)){
                        buff.add(r.address).writePointer(p) ;
                    }
                }
            }
            else{
                throw `unhandle relocation type ${r.type}`
            }
        })
    }
//    Memory.protect(buff, info.load_size, 'r-x');


    // dump for debug
    //if(false)
    {
        let fn = '/data/data/com.sincetimes.fknsg/dump.'+info.name+'.'+buff+'.dump'
        fridautils.dumpMemoryToFile(buff, info.load_size, fn)
    }

    return {buff:buff, syms:loadedSyms};
}