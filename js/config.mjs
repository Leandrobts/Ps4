// js/config.mjs

// Offsets para estruturas do JavaScriptCore (JSC) no ambiente alvo
export const JSC_OFFSETS = {
    ArrayBuffer: {
        PTR_TO_INTERNAL_STRUCT_OFFSET: 0x20,
        BYTELENGTH_WITHIN_INTERNAL_STRUCT_OFFSET: 0x20,
        // STATUS: MODELO TEÓRICO SUPORTADO.
    },
    TypedArray: {
        VTABLE_OFFSET: 0x0,                 // STATUS: TEÓRICO (comum para C++).
        M_VECTOR_OFFSET: 0x10,              // STATUS: ALTA CONFIANÇA.
        M_LENGTH_OFFSET: 0x18,              // STATUS: ALTA CONFIANÇA (para contagem de elementos).
        M_BYTELENGTH_OFFSET_IN_VIEW: 0x20,  // STATUS: PROVÁVEL/SUPORTADO.
        M_MODE_OFFSET: 0x28,                // STATUS: ALTA CONFIANÇA.
        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x30 // STATUS: ALTA CONFIANÇA.
    },
    JSCell: { // Usado para identificação genérica de objetos
        STRUCTURE_ID_OR_VTABLE_OFFSET: 0x0, // O primeiro qword é frequentemente Structure* ou VTable*.
                                            // STATUS: ALTA CONFIANÇA (como conceito geral de JSCell).
    },
    JSFunction: {
        M_EXECUTABLE_OFFSET: 0x18,          // STATUS: PLACEHOLDER.
    }
};

// Informações extraídas da biblioteca WebKit do alvo
export const WEBKIT_LIBRARY_INFO = {
    // Estes são OFFSETS RELATIVOS à base da biblioteca WebKit
    KNOWN_OFFSETS: {
        JSCell_Strings: ["0x1f7594"], // "JSCell" foi encontrado aqui (provavelmente uma string ou símbolo)
        StructureID_Strings: ["0x1f758a", "0x3f12b4", "0x40331f", "0x420f74"], // "StructureID" strings/símbolos
        TypedArray_Strings: ["0x1f75a5", "0x226f48", "0x27e007", "0x2e23db", "0x2e2555"], // "TypedArray" strings/símbolos
        VTable_Possible_Offsets: ["0x3dd43f", "0x3f12b0"], // "VTable" strings/símbolos ou reais offsets de vtable
        // Adicionar mais de top_functions_offsets.txt aqui:
        // Exemplo: JSObjectGetArrayBufferByteLength: "0x55C9F0",
    },
    // Segmentos de 'extracted_analysis.txt' (endereços virtuais são relativos à base da lib)
    SEGMENTS: [
        { name: "TEXT_EXEC", vaddr_start_hex: "0x0", memsz_hex: "0x3a98798", flags: "r-x" }, // Code
        { name: "RO_DATA", vaddr_start_hex: "0x3a9c000", memsz_hex: "0x223318", flags: "r--" }, // Read-only data
        { name: "RW_DATA", vaddr_start_hex: "0x3cc0000", memsz_hex: "0x040a68", filesz_hex: "0x13668", flags: "rw-" }, // Read-write data
    ],
    // Offsets de funções importantes de top_functions_offsets.txt e Offsets.txt
    // Estes são RELATIVOS ao início do primeiro segmento LOAD (vaddr 0x0).
    FUNCTION_OFFSETS: {
        // Preencher com os dados de top_functions_offsets.txt e Offsets.txt
        // "NomeDaFuncao": "OffsetHex",
        "sceKernelMprotect": "0x24280",
        "JSObjectGetArrayBufferByteLength": "0x55C9F0",
        "JSObjectGetTypedArrayBytesPtr": "0x2A3B50",
        "free": "0x28D70",
        "malloc": "0x28D60",
        "memalign": "0x28DB0",
        "JSC::JSFunction::getCallData": "0x64D3D0",
        // Adicione mais conforme necessário
    }
};

export let OOB_CONFIG = {
    ALLOCATION_SIZE: 32768,
    BASE_OFFSET_IN_DV: 128,
    INITIAL_BUFFER_SIZE: 32
};

export function updateOOBConfigFromUI() {
    const oobAllocSizeEl = document.getElementById('oobAllocSize');
    const baseOffsetEl = document.getElementById('baseOffset');
    const initialBufSizeEl = document.getElementById('initialBufSize');

    if (oobAllocSizeEl) {
        const val = parseInt(oobAllocSizeEl.value, 10);
        if (!isNaN(val) && val > 0) OOB_CONFIG.ALLOCATION_SIZE = val;
    }
    if (baseOffsetEl) {
        const val = parseInt(baseOffsetEl.value, 10);
        if (!isNaN(val) && val >= 0) OOB_CONFIG.BASE_OFFSET_IN_DV = val;
    }
    if (initialBufSizeEl) {
        const val = parseInt(initialBufSizeEl.value, 10);
        if (!isNaN(val) && val >= 0) OOB_CONFIG.INITIAL_BUFFER_SIZE = val;
    }
}
