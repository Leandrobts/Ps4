// js/app.mjs
import { log as appLog, PAUSE_LAB, toHexS1 } from './utils.mjs';
import * as Int64Lib from './int64.mjs';
import * as Core from './core_exploit.mjs';
import * as Groomer from './heap_groomer.mjs';
import * as Corruptor from './victim_corruptor.mjs';
import * as PostExploit from './post_exploit_conceptual.mjs';
import * as JsonExploitTest from './json_exploit_test.mjs';
import * as VictimFinder from './victim_finder.mjs'; // Importa VictimFinder
import { updateOOBConfigFromUI as updateGlobalOOBConfig } from './config.mjs';

let uiInitialized = false;

// Helper para parsear input que pode ser decimal ou hex
function parseMaybeHex(valueStr, defaultValue = 0) {
    if (typeof valueStr !== 'string' || valueStr.trim() === "") return defaultValue;
    const str = valueStr.trim().toLowerCase();
    try {
        if (str.startsWith("0x")) {
            return parseInt(str, 16);
        }
        return parseInt(str, 10);
    } catch (e) {
        appLog(`Erro ao parsear valor '${valueStr}'. Usando default ${defaultValue}. Erro: ${e.message}`, "warn", "App.ParseHelper");
        return defaultValue;
    }
}


const App = {
    isCurrentlyRunningIterativeSearch: false,

    setupUIEventListeners: () => {
        // Testes de Módulos
        document.getElementById('btnTestInt64')?.addEventListener('click', () => Int64Lib.testModule(appLog));
        document.getElementById('btnTestUtils')?.addEventListener('click', () => { import('./utils.mjs').then(utils => utils.testModule(appLog)); });
        document.getElementById('btnTestCore')?.addEventListener('click', () => Core.testModule(appLog));

        // Passo 0
        document.getElementById('btnTriggerOOB')?.addEventListener('click', Core.triggerOOB_primitive);

        // Passos 1 & 2 (Grooming & Corruptor)
        document.getElementById('btnPrepareVictim')?.addEventListener('click', () => {
            const sizeStr = document.getElementById('victim_object_size_groom').value;
            Groomer.prepareVictim(sizeStr); // prepareVictim agora espera string
        });
        document.getElementById('btnRunGroomingExperimental')?.addEventListener('click', Groomer.groomHeapButtonHandler);

        document.getElementById('btnFindAndCorrupt')?.addEventListener('click', async () => {
            if (App.isCurrentlyRunningIterativeSearch) {
                appLog("Busca iterativa de GAP já em execução.", "warn", "App.FindAndCorrupt");
                return;
            }
            App.isCurrentlyRunningIterativeSearch = true;
            const btn = document.getElementById('btnFindAndCorrupt');
            if(btn) btn.disabled = true;

            const gapStartStr = document.getElementById('gap_start_input').value;
            const gapEndStr = document.getElementById('gap_end_input').value;
            const gapStepStr = document.getElementById('gap_step_input').value;
            const victimSizeStr = document.getElementById('victim_object_size_groom').value;
            await Corruptor.findAndCorruptVictimFields_Iterative(gapStartStr, gapEndStr, gapStepStr, victimSizeStr);

            if(btn) btn.disabled = false;
            App.isCurrentlyRunningIterativeSearch = false;
        });
        document.getElementById('btnTestCorruptKnownGap')?.addEventListener('click', Corruptor.testCorruptKnownGapButtonHandler);

        // Listener para o VictimFinder
        document.getElementById('btnFindVictim')?.addEventListener('click', VictimFinder.findVictimButtonHandler);

        // Passos 3 & 4 (PostExploit)
        document.getElementById('btnSetupAddrofFakeobj')?.addEventListener('click', () => {
            const gapStr = document.getElementById('addrofGap').value;
            PostExploit.setup_addrof_fakeobj_pair_conceptual(gapStr);
        });
        document.getElementById('btnTestAddrof')?.addEventListener('click', () => {
            const objName = document.getElementById('objectNameToLeak').value;
            PostExploit.test_addrof_conceptual(objName);
        });
        document.getElementById('btnTestFakeObj')?.addEventListener('click', () => {
            const addrHex = document.getElementById('fakeObjAddrHex').value;
            PostExploit.test_fakeobj_conceptual(addrHex);
        });
        
        // Passo 5 (JSON DoS)
        document.getElementById('btnRunJsonRecursionTest')?.addEventListener('click', () => {
            const scenario = document.getElementById('jsonRecursionScenario').value;
            JsonExploitTest.runJsonRecursionTest(scenario);
        });

        // Passo 6 (JSON OOB Trigger)
        document.getElementById('btnRunJsonOOBExploit')?.addEventListener('click', () => {
            const targetType = document.getElementById('jsonOobTargetObject').value;
            const relativeOffset = parseMaybeHex(document.getElementById('jsonOobRelativeOffset').value, 0);
            const valueHex = document.getElementById('jsonOobValueToWriteHex').value; // Passa como string, json_exploit_test fará o parse
            const bytesToRead = parseInt(document.getElementById('jsonOobBytesToRead').value, 10);
            // Atualiza os inputs com os valores parseados (ou default) para consistência na UI
            document.getElementById('jsonOobRelativeOffset').value = toHexS1(relativeOffset);

            JsonExploitTest.jsonTriggeredOOBInteraction(targetType, relativeOffset, valueHex, bytesToRead);
        });
        
        // Log
        document.getElementById('btnClearLog')?.addEventListener('click', () => {
            const logOutputDiv = document.getElementById('logOutput');
            if (logOutputDiv) logOutputDiv.innerHTML = '';
            appLog("Log limpo.", "info", "App.ClearLog");
        });

        // Listeners para atualização de config OOB ao mudar os inputs
        document.getElementById('oobAllocSize')?.addEventListener('change', updateGlobalOOBConfig);
        document.getElementById('baseOffset')?.addEventListener('change', updateGlobalOOBConfig);
        document.getElementById('initialBufSize')?.addEventListener('change', updateGlobalOOBConfig);
    },

    initialize: () => {
        if (uiInitialized) {
            appLog("App.initialize: UI já inicializada. Ignorando.", "warn", "App.Init");
            return;
        }
        // Lê valores iniciais da UI para OOB_CONFIG ao carregar.
        // Isso garante que os valores no HTML sejam os iniciais usados.
        updateGlobalOOBConfig();
        
        App.setupUIEventListeners();
        App.exploitSuccessfulThisSession = false; // Reset de estado
        App.isCurrentlyRunningIterativeSearch = false;
        
        appLog("Laboratório Modular (v3.1.0 - Correções e Refinamentos) pronto.", "good", "App.Init");
        
        // Limpar campos de GAP ao iniciar
        const addrofGapEl = document.getElementById('addrofGap');
        if (addrofGapEl) addrofGapEl.value = ""; 
        const gapToTestInputEl = document.getElementById('gap_to_test_input');
        if (gapToTestInputEl) gapToTestInputEl.value = "";

        uiInitialized = true;
    }
};

// Garante que o DOM está carregado antes de inicializar
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', App.initialize);
} else {
    App.initialize(); // DOM já carregado
}

appLog("app.mjs carregado e pronto.", "info", "Global");
