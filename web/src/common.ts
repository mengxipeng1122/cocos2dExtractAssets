
export interface LogEntry {
    assetType: string;
    assetName: string;
    assetLang: string;
    type: string;
    crc: string;
    size: number;
}

export interface TextureInfo {
    level: number;
    width: number;
    height: number;
    pitch: number;
    glFormat: number;
}

export interface CompiledShader {
    vertex_shader: string ;
    fragment_shader: string ;
}

export const app_name = 'Riptide GP';
