// js/config.mjs

// Offsets para estruturas do JavaScriptCore (JSC) no ambiente alvo
export const JSC_OFFSETS = {
    ArrayBuffer: {
        // Offset do ponteiro para a estrutura interna que contém o ponteiro de dados e o tamanho.
        PTR_TO_INTERNAL_STRUCT_OFFSET: 0x20, // STATUS: MODELO TEÓRICO SUPORTADO.
        // Offset do byteLength dentro da estrutura interna do ArrayBuffer.
        BYTELENGTH_WITHIN_INTERNAL_STRUCT_OFFSET: 0x20, // STATUS: MODELO TEÓRICO SUPORTADO.
        // NOTA: Em algumas implementações, o ponteiro de dados pode estar em um offset e o bytelength em outro
        // dentro da estrutura apontada por PTR_TO_INTERNAL_STRUCT_OFFSET.
        // Ou, o ponteiro de dados e o bytelength podem estar diretamente no objeto ArrayBuffer.
        // INVESTIGUE SEU ALVO ESPECÍFICO.
    },
    TypedArray: { // Para JS TypedArray Views como Uint32Array, etc.
        VTABLE_OFFSET: 0x0,                 // Ponteiro VTable (comum para C++). STATUS: TEÓRICO.
        M_VECTOR_OFFSET: 0x10,              // Ponteiro para os dados brutos (m_vector). STATUS: ALTA CONFIANÇA.
        M_LENGTH_OFFSET: 0x18,              // Número de elementos (m_length). STATUS: ALTA CONFIANÇA.
        M_BYTELENGTH_OFFSET_IN_VIEW: 0x20,  // Tamanho em bytes da view (m_byteLength). STATUS: PROVÁVEL/SUPORTADO.
        M_MODE_OFFSET: 0x28,                // Modo do TypedArray (indica tipo: Uint8, Int32, etc.). STATUS: ALTA CONFIANÇA.
        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x30 // Ponteiro para o ArrayBuffer associado. STATUS: ALTA CONFIANÇA.
    },
    JSCell: { // Usado para identificação genérica de objetos JSC
        STRUCTURE_ID_OR_VTABLE_OFFSET: 0x0, // O primeiro qword é frequentemente StructureID* ou VTable*.
                                            // STATUS: ALTA CONFIANÇA (como conceito geral de JSCell).
    },
    JSFunction: { // Para objetos de função JavaScript
        M_EXECUTABLE_OFFSET: 0x18,          // Ponteiro para o objeto Executable (contém código JIT, etc.). STATUS: PLACEHOLDER.
    }
};

// Informações extraídas da biblioteca WebKit alvo (ex: libSceNKWebKit.sprx.elf)
// PREENCHA ESTA SEÇÃO COM DADOS PRECISOS DO SEU BINÁRIO ALVO!
export const WEBKIT_LIBRARY_INFO = {
    LIBRARY_NAME: "libSceNKWebKit.sprx.elf", // Confirme o nome da sua biblioteca alvo.
    // Segmentos de memória (baseado no seu extracted_analysis.txt - Program Headers)
    // vaddr_start_hex é relativo ao início da biblioteca (0x0 no arquivo ELF PIE)
    // memsz_hex é o tamanho do segmento na memória.
    SEGMENTS: [
        { name: "TEXT_EXEC", vaddr_start_hex: "0x0", memsz_hex: "0x3a98798", flags: "r-x", description: "Segmento de Código Executável" },
        { name: "RO_DATA", vaddr_start_hex: "0x3a9c000", memsz_hex: "0x223318", flags: "r--", description: "Segmento de Dados Somente Leitura" },
        { name: "RW_DATA", vaddr_start_hex: "0x3cc0000", memsz_hex: "0x040a68", flags: "rw-", description: "Segmento de Dados Leitura/Escrita" },
        // Adicione outros segmentos relevantes se sua análise mostrar (ex: .got, .plt, etc., se precisar deles)
    ],
    // Offsets conhecidos DENTRO da biblioteca (relativos ao início da lib, ou seja, vaddr 0x0 do TEXT_EXEC)
    KNOWN_OFFSETS: {
        // Offsets de VTables conhecidas. Ex: "JSC::Uint32Array::VTABLE": "0xOFFSET_HEX",
        // Você precisará encontrar estes offsets na sua análise estática do binário.
        VTable_Possible_Offsets: [
            // "0x1A2B3C4D", // Exemplo: Offset para VTable de Uint32Array
            // "0x5E6F7A8B", // Exemplo: Offset para VTable de ArrayBuffer
            // PREENCHA COM OFFSETS REAIS DO SEU ALVO
        ],
        // Offsets de Strings conhecidas. Ex: "Uint32ArrayClassName": "0xOFFSET_HEX",
        // Útil para validar ponteiros ou o endereço base vazado.
        STRINGS: {
            // "NOME_DESCRITIVO_STRING": "OFFSET_HEX_DA_STRING",
            // Ex: "JSC::GetterSetter::callHostGetter": "0x123ABC", // Se for uma string usada em logs/erros
            // Ex: "ArrayBufferOutOfMemory": "0xDEF123",
            // PREENCHA COM OFFSETS REAIS DO SEU ALVO (se identificadas via `strings` e análise)
        }
    },
    // Offsets de funções importantes (baseado em top_functions_offsets.txt, Offsets.txt e sua análise)
    // Estes são RELATIVOS ao início do primeiro segmento LOAD (vaddr 0x0 do TEXT_EXEC).
    // PREENCHA ESTA SEÇÃO CUIDADOSAMENTE COM OS DADOS DO SEU BINÁRIO!
    FUNCTION_OFFSETS: {
        // Exemplo de como você deve preencher (use nomes e offsets do seu `top_functions_offsets.txt`):
        // "JSC::Executable::generatedJITCodeForCall": "0x1C2D3E4F",
        // "JSC::JSGlobalObject::createThis": "0xA1B2C3D4",
        // "WTF::fastMalloc": "0xF0E1D2C3",
        // "JSC::JSObject::put": "0xDEADBEEF", // Função para definir propriedade
        // "JSC::JSObject::get": "0xCAFEBABE", // Função para obter propriedade

        // Mantendo alguns exemplos genéricos (VERIFIQUE E SUBSTITUA se não aplicável ao seu alvo):
        "sceKernelMprotect": "0x24280",            // Provavelmente de uma lib do sistema, não WebKit. Verifique.
        "JSObjectGetArrayBufferByteLength": "0x55C9F0", // Nome genérico, verifique se existe e o offset.
        "JSObjectGetTypedArrayBytesPtr": "0x2A3B50", // Nome genérico, verifique se existe e o offset.
        "free": "0x28D70",                         // Pode ser uma importação ou re-exportação.
        "malloc": "0x28D60",                       // Idem.
        "memalign": "0x28DB0",                     // Idem.
        "JSC::JSFunction::getCallData": "0x64D3D0",  // Comum em JSC, verifique o offset.
        // Adicione mais funções que você identificar como importantes ou que aparecem no seu `top_functions_offsets.txt`.
        // Quanto mais funções precisas aqui, melhor o VictimFinder poderá calcular o base da WebKit.
    }
};

// Configuração para a primitiva Out-Of-Bounds (OOB)
export let OOB_CONFIG = {
    ALLOCATION_SIZE: 32768,   // Tamanho do ArrayBuffer "real" para a janela OOB (em bytes)
    BASE_OFFSET_IN_DV: 128,   // Offset dentro do ArrayBuffer "real" onde a DataView OOB começa (em bytes)
    INITIAL_BUFFER_SIZE: 32   // Tamanho do ArrayBuffer "inicial" usado para acionar a confusão de tipo/OOB (em bytes)
};

// Função para atualizar OOB_CONFIG com valores da UI
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
        if (!isNaN(val) && val > 0) OOB_CONFIG.INITIAL_BUFFER_SIZE = val;
    }
}
