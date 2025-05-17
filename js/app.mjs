// js/app.mjs
import { log as appLog, PAUSE_LAB, toHexS1 } from './utils.mjs';
import * as Int64Lib from './int64.mjs';
import * as Core from './core_exploit.mjs';
import * as Groomer from './heap_groomer.mjs';
import * as Corruptor from './victim_corruptor.mjs';
import * as PostExploit from './post_exploit_conceptual.mjs';
import * as JsonExploitTest from './json_exploit_test.mjs';
import * as VictimFinder from './victim_finder.mjs';
import { updateOOBConfigFromUI as updateGlobalOOBConfig, OOB_CONFIG } from './config.mjs';

let uiInitialized = false;

function parseMaybeHex(valueStr, defaultValue = 0) {
    if (typeof valueStr !== 'string' || valueStr.trim() === "") {
        if (typeof defaultValue === 'function') return defaultValue();
        return defaultValue;
    }
    const str = valueStr.trim().toLowerCase();
    try {
        let parsedValue;
        if (str.startsWith("0x")) {
            parsedValue = parseInt(str, 16);
        } else {
            parsedValue = parseInt(str, 10);
        }
        if (isNaN(parsedValue)) {
            appLog(`Valor '${valueStr}' resultou em NaN após parse. Usando default ${defaultValue}.`, "warn", "App.ParseHelper");
            if (typeof defaultValue === 'function') return defaultValue();
            return defaultValue;
        }
        return parsedValue;
    } catch (e) {
        appLog(`Exceção ao parsear '${valueStr}': ${e.message}. Usando default ${defaultValue}.`, "error", "App.ParseHelper");
        if (typeof defaultValue === 'function') return defaultValue();
        return defaultValue;
    }
}


const App = {
    exploitSuccessfulThisSession: false,
    isCurrentlyRunningIterativeSearch: false,
    isCurrentlyRunningGrooming: false,
    isCurrentlyFindingVictims: false,

    setupUIEventListeners: function () {
        const FNAME_SETUP_UI = "App.setupUIListeners";
        // Passo 0: Config OOB
        document.getElementById('btnTriggerOOB')?.addEventListener('click', async () => {
            const FNAME = `${FNAME_SETUP_UI}.btnTriggerOOB`;
            appLog("Botão 'Configurar Primitiva OOB' clicado.", "tool", FNAME);
            await Core.triggerOOB_primitive();
            const oobStatusEl = document.getElementById('oobStatus');
            if (Core.oob_dataview_real) {
                 oobStatusEl.textContent = `CONFIGURADO: Janela OOB de ${Core.getOOBAllocationSize()} bytes em offset ${Core.getBaseOffsetInDV()}.`;
                 oobStatusEl.style.color = "#b5cea8"; // good
            } else {
                oobStatusEl.textContent = "FALHA AO CONFIGURAR. Verifique o console.";
                oobStatusEl.style.color = "#f44747"; // error
            }
        });
        document.getElementById('btnClearOOB')?.addEventListener('click', Core.clearOOBEnvironment);
        document.getElementById('btnTestCoreModule')?.addEventListener('click', () => Core.testModule(appLog));

        // Passo 1: Heap Grooming
        document.getElementById('btnPrepareVictim')?.addEventListener('click', async () => {
            const FNAME = `${FNAME_SETUP_UI}.btnPrepareVictim`;
            const victimSizeEl = document.getElementById('victimObjectSize');
            const victimSize = victimSizeEl ? victimSizeEl.value : OOB_CONFIG.ALLOCATION_SIZE.toString();
            appLog(`Botão 'Preparar Vítima' clicado. Tamanho: ${victimSize}`, "tool", FNAME);
            await Groomer.prepareVictim(victimSize);
        });
        document.getElementById('btnRunGroomingExperimental')?.addEventListener('click', Groomer.groomHeapButtonHandler);
        document.getElementById('btnClearSprayArray')?.addEventListener('click', Groomer.clearSprayArrayButtonHandler);

        // Passo 2: Victim Finder
        document.getElementById('btnSetLeakedBase')?.addEventListener('click', VictimFinder.setLeakedWebKitBaseAddressFromUI);
        document.getElementById('btnFindVictim')?.addEventListener('click', VictimFinder.findVictimButtonHandler);


        // Passo 3: Victim Corruptor
        document.getElementById('btnTestCorruptKnownGap')?.addEventListener('click', Corruptor.testCorruptKnownGapButtonHandler);
        document.getElementById('btnFindAndCorruptIterative')?.addEventListener('click', Corruptor.findAndCorruptVictimFields_Iterative);

        // Passo 4: Post Exploit
        document.getElementById('btnSetupAddrofFakeobj')?.addEventListener('click', PostExploit.setup_addrof_fakeobj_pair_conceptual);
        document.getElementById('btnTestAddrof')?.addEventListener('click', PostExploit.test_addrof_conceptual);
        document.getElementById('btnTestFakeobj')?.addEventListener('click', PostExploit.test_fakeobj_conceptual);

        // Testes JSON
        document.getElementById('btnRunJsonRecursionTest')?.addEventListener('click', async () => {
            const scenarioEl = document.getElementById('jsonRecursionScenario');
            if (scenarioEl) await JsonExploitTest.runJsonRecursionTest(scenarioEl.value);
        });
        document.getElementById('btnRunJsonOOBExploit')?.addEventListener('click', async () => {
            const targetObjEl = document.getElementById('jsonOobTargetObject');
            const offsetEl = document.getElementById('jsonOobRelativeOffset');
            const valueHexEl = document.getElementById('jsonOobValueToWriteHex');
            const bytesEl = document.getElementById('jsonOobBytesToReadWrite'); // ID Corrigido no HTML também

            const target = targetObjEl ? targetObjEl.value : "new_array_buffer";
            const offset = offsetEl ? offsetEl.value : "0x50";
            const valueHex = valueHexEl ? valueHexEl.value : "0xDEADBEEF";
            const bytes = bytesEl ? parseInt(bytesEl.value, 10) : 1;

            await JsonExploitTest.jsonTriggeredOOBInteraction(target, offset, valueHex, bytes);
        });


        // Geral
        document.getElementById('btnClearLog')?.addEventListener('click', () => {
            const logOutputDiv = document.getElementById('logOutput');
            if (logOutputDiv) logOutputDiv.innerHTML = '';
            appLog("Log limpo pelo usuário.", "info", "App.ClearLog");
        });

        // Atualizar display de GAPs - ESTAS SÃO AS LINHAS RELEVANTES PARA O ERRO
        if (typeof Corruptor.setGapUpdateUICallback === 'function') {
            Corruptor.setGapUpdateUICallback((gap) => {
                const currentGapUIEl = document.getElementById('current_gap_display');
                if (currentGapUIEl) currentGapUIEl.textContent = gap !== null ? toHexS1(gap) + ` (${gap})` : "N/A";
            });
        } else {
            appLog("AVISO: Corruptor.setGapUpdateUICallback não é uma função.", "warn", FNAME_SETUP_UI);
        }

        if (typeof Corruptor.setSuccessfulGapUpdateUICallback === 'function') {
            Corruptor.setSuccessfulGapUpdateUICallback((gap) => {
                const successfulGapUIEl = document.getElementById('last_successful_gap_display');
                if (successfulGapUIEl) successfulGapUIEl.textContent = gap !== null ? toHexS1(gap) + ` (${gap})` : "N/A";
            });
        } else {
            appLog("AVISO: Corruptor.setSuccessfulGapUpdateUICallback não é uma função.", "warn", FNAME_SETUP_UI);
        }


        appLog("Ouvintes de eventos da UI configurados.", "info", FNAME_SETUP_UI);
    },

    initialize: function () {
        if (uiInitialized) {
            appLog("App.initialize: UI já inicializada. Ignorando.", "warn", "App.Init");
            return;
        }
        updateGlobalOOBConfig(); // Garante que os valores da UI sejam lidos no início

        App.setupUIEventListeners();
        App.exploitSuccessfulThisSession = false;
        App.isCurrentlyRunningIterativeSearch = false;
        App.isCurrentlyRunningGrooming = false;
        App.isCurrentlyFindingVictims = false;

        let version = "?.?.?"; // Default version
        try {
            const titleMatch = document.title.match(/v(\d+\.\d+\.\d+)/);
            if (titleMatch && titleMatch[1]) version = titleMatch[1];
        } catch(e){ /* ignora erro de match no título */ }
        appLog(`Laboratório Modular (v${version}) pronto.`, "good", "App.Init");

        // Limpa campos de input que podem persistir entre reloads de página
        const addrofGapEl = document.getElementById('addrofGap');
        if (addrofGapEl) addrofGapEl.value = "";
        const gapToTestInputEl = document.getElementById('gap_to_test_input');
        if (gapToTestInputEl) gapToTestInputEl.value = "";
        const leakedWebKitBaseHexEl = document.getElementById('leakedWebKitBaseHex');
        if (leakedWebKitBaseHexEl) leakedWebKitBaseHexEl.value = "";
        const oobStatusEl = document.getElementById('oobStatus');
        if (oobStatusEl) {
            oobStatusEl.textContent = "Não configurado";
            oobStatusEl.style.color = "#ce9178"; // warn
        }
        const successfulGapUIEl = document.getElementById('last_successful_gap_display');
        if (successfulGapUIEl) successfulGapUIEl.textContent = "N/A";
         const currentGapUIEl = document.getElementById('current_gap_display');
        if (currentGapUIEl) currentGapUIEl.textContent = "N/A";


        uiInitialized = true;
    }
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', App.initialize);
} else {
    // DOM já carregado
    App.initialize();
}

// Expor módulos para depuração no console, se necessário
window.LabModules = {
    Core,
    Groomer,
    Corruptor,
    PostExploit,
    JsonExploitTest,
    VictimFinder,
    Int64Lib,
    AppUtils: { log: appLog, PAUSE_LAB, toHexS1, parseMaybeHex },
    Config: { OOB_CONFIG } // Removido JSC_OFFSETS e WEBKIT_LIBRARY_INFO para simplificar, eles são usados internamente
};
appLog("app.mjs carregado e pronto.", "info", "Global");

