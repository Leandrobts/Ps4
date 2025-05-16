// js/app.mjs
import { log as appLog, PAUSE_LAB } from './utils.mjs';
import * as Int64Lib from './int64.mjs';
import * as Core from './core_exploit.mjs';
import * as Groomer from './heap_groomer.mjs';
import * as Corruptor from './victim_corruptor.mjs';
import * as PostExploit from './post_exploit_conceptual.mjs';
import * as JsonExploitTest from './json_exploit_test.mjs';
import * as VictimFinder from './victim_finder.mjs'; // <-- NOVA IMPORTAÇÃO
import { updateOOBConfigFromUI as updateGlobalOOBConfig } from './config.mjs';

let uiInitialized = false;

const App = {
    exploitSuccessfulThisSession: false,
    isCurrentlyRunningStrategies: false,

    runAllGroomingStrategies: async () => {
        const FNAME_STRAT = "App.runAllGroomingStrategies";
        appLog("AVISO: Funcionalidade de Grooming/Busca de GAP está em desenvolvimento e pode não funcionar como esperado.", "warn", FNAME_STRAT);
        if (App.isCurrentlyRunningStrategies) {
            appLog("Estratégias de grooming já em execução.", "warn", FNAME_STRAT);
            return;
        }
        App.isCurrentlyRunningStrategies = true;
        const btn = document.getElementById('btnRunGroomingStrategies');
        if (btn) btn.disabled = true;

        // Lógica de grooming (placeholder ou a ser implementada/revisada)
        const victimSize = parseInt(document.getElementById('victim_object_size_groom').value) || 288;
        await Groomer.groomHeapForSameSize(100, victimSize, 20); // Exemplo de parâmetros
        // Após o grooming, tentar encontrar e corromper
        const gapStart = parseInt(document.getElementById('gap_start_input').value) || 0;
        const gapEnd = parseInt(document.getElementById('gap_end_input').value) || 1024;
        const gapStep = parseInt(document.getElementById('gap_step_input').value) || 8;
        await Corruptor.findAndCorruptVictimFields_Iterative(gapStart, gapEnd, gapStep, victimSize);

        if (btn) btn.disabled = false;
        App.isCurrentlyRunningStrategies = false;
        appLog("Todas as estratégias de grooming & busca de GAP (WIP) concluídas.", "test", FNAME_STRAT);
    },

    setupUIEventListeners: () => {
        // Testes de Módulos
        document.getElementById('btnTestInt64')?.addEventListener('click', () => Int64Lib.testModule(appLog));
        document.getElementById('btnTestUtils')?.addEventListener('click', () => { import('./utils.mjs').then(utils => utils.testModule()); });
        document.getElementById('btnTestCore')?.addEventListener('click', () => Core.testModule(appLog));

        // Passo 0
        document.getElementById('btnTriggerOOB')?.addEventListener('click', Core.triggerOOB_primitive);

        // Passos 1 & 2 (Grooming & Corruptor)
        document.getElementById('btnPrepareVictim')?.addEventListener('click', () => {
            const size = parseInt(document.getElementById('victim_object_size_groom').value) || 288;
            Groomer.prepareVictim(size);
        });
        // document.getElementById('btnRunGroomingStrategies')?.addEventListener('click', App.runAllGroomingStrategies); // Botão está desabilitado por padrão
        document.getElementById('btnFindAndCorrupt')?.addEventListener('click', () => {
            const gapStart = document.getElementById('gap_start_input').value;
            const gapEnd = document.getElementById('gap_end_input').value;
            const gapStep = document.getElementById('gap_step_input').value;
            const victimSize = document.getElementById('victim_object_size_groom').value;
            Corruptor.findAndCorruptVictimFields_Iterative(gapStart, gapEnd, gapStep, victimSize);
        });
        document.getElementById('btnTestCorruptKnownGap')?.addEventListener('click', Corruptor.testCorruptKnownGapButtonHandler);


        // Listener para o NOVO BOTÃO do VictimFinder
        const btnFindVictimEl = document.getElementById('btnFindVictim');
        if (btnFindVictimEl) {
            btnFindVictimEl.onclick = VictimFinder.findVictimButtonHandler;
        }

        // Passos 3 & 4 (PostExploit)
        document.getElementById('btnSetupAddrofFakeobj')?.addEventListener('click', PostExploit.setup_addrof_fakeobj_pair_conceptual);
        document.getElementById('btnTestAddrof')?.addEventListener('click', PostExploit.test_addrof_conceptual);
        document.getElementById('btnTestFakeObj')?.addEventListener('click', PostExploit.test_fakeobj_conceptual);
        
        // Passo 5 (JSON DoS)
        document.getElementById('btnRunJsonRecursionTest')?.addEventListener('click', () => {
            const scenario = document.getElementById('jsonRecursionScenario').value;
            JsonExploitTest.runJsonRecursionTest(scenario);
        });

        // Passo 6 (JSON OOB Trigger)
        document.getElementById('btnRunJsonOOBExploit')?.addEventListener('click', () => {
            const targetType = document.getElementById('jsonOobTargetObject').value;
            const relativeOffset = parseInt(document.getElementById('jsonOobRelativeOffset').value, 10);
            const valueHex = document.getElementById('jsonOobValueToWriteHex').value;
            const bytesToRead = parseInt(document.getElementById('jsonOobBytesToRead').value, 10);
            JsonExploitTest.jsonTriggeredOOBInteraction(targetType, relativeOffset, valueHex, bytesToRead);
        });
        
        // Log
        document.getElementById('btnClearLog')?.addEventListener('click', () => {
            const logOutputDiv = document.getElementById('logOutput');
            if (logOutputDiv) logOutputDiv.innerHTML = '';
            appLog("Log limpo.", "info", "App.ClearLog");
        });

        // Listeners para atualização de config OOB
        document.getElementById('oobAllocSize')?.addEventListener('change', updateGlobalOOBConfig);
        document.getElementById('baseOffset')?.addEventListener('change', updateGlobalOOBConfig);
        document.getElementById('initialBufSize')?.addEventListener('change', updateGlobalOOBConfig);
    },

    initialize: () => {
        if (uiInitialized) {
            appLog("App.initialize: UI já inicializada. Ignorando.", "warn", "App.Init");
            return;
        }
        updateGlobalOOBConfig(); // Lê valores iniciais da UI para config OOB
        App.setupUIEventListeners();
        App.exploitSuccessfulThisSession = false;
        App.isCurrentlyRunningStrategies = false;
        
        appLog("Laboratório Modular (v3.0.0 - Com VictimFinder) pronto.", "good", "App.Init");
        const addrofGapEl = document.getElementById('addrofGap');
        if (addrofGapEl) addrofGapEl.value = ""; 
        const gapToTestInputEl = document.getElementById('gap_to_test_input');
        if (gapToTestInputEl) gapToTestInputEl.value = "";

        uiInitialized = true;
    }
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', App.initialize);
} else {
    App.initialize();
}

appLog("app.mjs carregado e pronto.", "info", "Global");
