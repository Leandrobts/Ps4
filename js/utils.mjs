// js/utils.mjs
import { AdvancedInt64 } from './int64.mjs'; // Precisa para toHexS1

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

        if(logOutputDiv.innerHTML.length > 1200000){ // Limita o tamanho do log para evitar travamentos
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
    if (val instanceof AdvancedInt64) return val.toString(true); // Garante que é a versão com "0x" e padding
    if (typeof val !== 'number' || !isFinite(val)) return 'NaN/Invalid';

    let num = Number(val);
    const isNegative = num < 0;

    if (bits <= 32) {
        num = num >>> 0; // Para números de 32 bits, trata como unsigned para representação hex
    } else if (bits === 64 && isNegative) {
        // Para 64 bits negativos, precisamos de uma abordagem diferente (ou usar AdvancedInt64)
        // Esta é uma simplificação e pode não ser perfeitamente representativa para todos os negativos de 64 bits
        // Convertendo para BigInt para lidar com o complemento de dois para 64 bits
        try {
            const bigIntValue = BigInt.asUintN(64, BigInt(val));
            return '0x' + bigIntValue.toString(16).toUpperCase().padStart(16, '0');
        } catch (e) {
            return 'ErrorIn64BitHex';
        }
    } else if (bits === 64) {
         return '0x' + num.toString(16).toUpperCase().padStart(16, '0');
    }
    // Para outros tamanhos de bits ou números positivos
    const pad = Math.ceil(bits / 4);
    return '0x' + num.toString(16).toUpperCase().padStart(pad, '0');
}

export function PAUSE_LAB(ms = 100) {
    return new Promise(r => setTimeout(r, ms));
}

export function testModule() {
    log("--- Testando Módulo Utils (utils.mjs) ---", "test", "Utils.test");
    log("Mensagem de log normal.", "info", "Utils.test");
    log("Mensagem de aviso.", "warn", "Utils.test");
    log("Mensagem de erro.", "error", "Utils.test");
    log("Mensagem de sucesso.", "good", "Utils.test");
    log("Mensagem de vulnerabilidade.", "vuln", "Utils.test");
    log("Mensagem de vazamento: " + toHexS1(0xDEADBEEF), "leak", "Utils.test");
    const ptrTest = new AdvancedInt64("0xCAFEBABE12345678");
    log("Mensagem de ponteiro: " + toHexS1(ptrTest, 64), "ptr", "Utils.test");
    log("Mensagem de análise.", "analysis", "Utils.test");
    log("--- Teste Utils Concluído ---", "test", "Utils.test");
}
