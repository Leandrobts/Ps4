// js/utils.mjs
import { AdvancedInt64 } from './int64.mjs'; // Precisa para toHexLab

let logOutputDiv = null; // Cache para o elemento de log

// Função de log principal
export function log(message, type = 'info', funcName = '') {
    if (!logOutputDiv) {
        logOutputDiv = document.getElementById('logOutput');
    }
    if (!logOutputDiv) { console.error("utils.log: Div de log 'logOutput' não encontrado:", message); return; }
    try {
        const timestamp = `[${new Date().toLocaleTimeString()}]`;
        const prefix = funcName ? `[${funcName}] ` : '';
        const sanitizedMessage = String(message).replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const logClass = ['info', 'test', 'subtest', 'vuln', 'good', 'warn', 'error', 'leak', 'ptr', 'critical', 'escalation', 'tool', 'analysis'].includes(type) ? type : 'info';
        if(logOutputDiv.innerHTML.length > 1200000){
            logOutputDiv.innerHTML = logOutputDiv.innerHTML.substring(logOutputDiv.innerHTML.length - 600000);
            logOutputDiv.innerHTML = `<span>[Log Truncado...]</span>\n` + logOutputDiv.innerHTML;
        }
        logOutputDiv.innerHTML += `<span class="log-${logClass}">${timestamp} ${prefix}${sanitizedMessage}\n</span>`;
        logOutputDiv.scrollTop = logOutputDiv.scrollHeight;
    } catch(e) {
        console.error(`Erro no utils.log:`, e);
        logOutputDiv.innerHTML += `[${new Date().toLocaleTimeString()}] [LOGGING ERROR] ${String(e)}\n`;
    }
}

export function toHexS1(val, bits = 32) {
    if (val instanceof AdvancedInt64) return val.toString(true);
    if (typeof val !== 'number' || !isFinite(val)) return 'NaN/Invalid';
    let num = Number(val);
    if (bits <= 32) { num = num >>> 0; }
    const pad = Math.ceil(bits / 4);
    return '0x' + num.toString(16).toUpperCase().padStart(pad, '0');
}

export function PAUSE_LAB(ms = 100) {
    return new Promise(r => setTimeout(r, ms));
}

export function testModule() {
    log("--- Testando Módulo Utils (utils.mjs) ---", "test", "Utils.test");
    log("Mensagem de log normal.", "info", "Utils.test");
    log("Mensagem de erro.", "error", "Utils.test");
    log(`toHexS1(12345): ${toHexS1(12345)}`, "info", "Utils.test");
    log("Teste Utils concluído.", "good", "Utils.test");
}
