// js/int64.mjs

// Não importamos 'log' aqui diretamente para o corpo da classe,
// mas testModule pode recebê-lo como parâmetro.

export class AdvancedInt64 {
    constructor(low, high) {
        this.buffer = new Uint32Array(2); // [low, high]
        this.bytes = new Uint8Array(this.buffer.buffer); // Para acesso byte a byte se necessário

        if (arguments.length === 0) {
            this.buffer[0] = 0; // low
            this.buffer[1] = 0; // high
            return;
        }

        if (typeof low === 'string') {
            let hexstr = low.startsWith("0x") ? low.substring(2) : low;
            // Remove separadores comuns como '_'
            hexstr = hexstr.replace(/_/g, '');

            if (hexstr.length > 16) {
                // console.warn(`AdvancedInt64: String hexadecimal '${low}' truncada para os últimos 16 caracteres.`);
                hexstr = hexstr.substring(hexstr.length - 16);
            }
            hexstr = hexstr.padStart(16, '0'); // Garante 16 caracteres hex (8 bytes)

            const highHex = hexstr.substring(0, 8);
            const lowHex = hexstr.substring(8, 16);

            this.buffer[1] = parseInt(highHex, 16);
            this.buffer[0] = parseInt(lowHex, 16);

        } else if (typeof low === 'number') {
            this.buffer[0] = low & 0xFFFFFFFF; // Parte baixa
            if (arguments.length === 1) {
                // Se apenas 'low' é fornecido, e é negativo, estende o sinal para 'high'.
                this.buffer[1] = (low < 0 && Math.abs(low) > 0xFFFFFFFF) ? 0xFFFFFFFF : 0;
            } else if (typeof high === 'number') {
                this.buffer[1] = high & 0xFFFFFFFF; // Parte alta
            } else {
                 this.buffer[1] = 0; // Default para high se não fornecido ou tipo inválido
            }
        } else if (low instanceof AdvancedInt64) { // Copia de outra instância
            this.buffer[0] = low.buffer[0];
            this.buffer[1] = low.buffer[1];
        } else {
            // Fallback para tipos de entrada desconhecidos
            // console.warn(`AdvancedInt64: Tipo de construtor desconhecido: ${typeof low}. Inicializando como zero.`);
            this.buffer[0] = 0;
            this.buffer[1] = 0;
        }
    }

    low() { return this.buffer[0]; }
    high() { return this.buffer[1]; }

    toString(hex = false) {
        if (!hex) {
            // Para representação decimal, é complexo e pode perder precisão para números muito grandes.
            // Uma implementação completa de BigInt seria necessária.
            // Por agora, uma simplificação ou indicação de que é um valor de 64 bits.
            if (this.buffer[1] === 0 && this.buffer[0] >= 0) return String(this.buffer[0]);
            if (this.buffer[1] === 0xFFFFFFFF && (this.buffer[0] & 0x80000000)) return String(this.buffer[0] | 0); // Interpreta como int32
            return `(Int64: H:0x${this.buffer[1].toString(16)} L:0x${this.buffer[0].toString(16)})`;
        }
        const highHex = this.buffer[1].toString(16).padStart(8, '0');
        const lowHex = this.buffer[0].toString(16).padStart(8, '0');
        return `0x${highHex}_${lowHex}`;
    }

    toNumber() { // CUIDADO: Perde precisão para números maiores que 2^53 - 1
        const high = this.buffer[1];
        const low = this.buffer[0];
        
        const sign = high & 0x80000000; // Checa o bit de sinal da parte alta
        if (sign) { // Número negativo (requer complemento de dois para conversão para decimal)
            let twosCompLow = (~low + 1) >>> 0;
            let twosCompHigh = (~high + (twosCompLow === 0 ? 1 : 0)) >>> 0; // Propaga o carry do low
            if (twosCompLow === 0 && low !==0) twosCompHigh = (~high + 1) >>>0; // Caso especial para low = 0xFFFFFFFF e ~low+1 = 0

            // Converte para número, sabendo que é negativo
            // Esta conversão ainda pode ter problemas de precisão com Number.MAX_SAFE_INTEGER
            return -(twosCompHigh * Math.pow(2, 32) + twosCompLow);
        } else {
            return high * Math.pow(2, 32) + low;
        }
    }

    equals(other) {
        if (!(other instanceof AdvancedInt64)) return false; // Garante que 'other' é do tipo certo
        return this.buffer[0] === other.buffer[0] && this.buffer[1] === other.buffer[1];
    }
    
    isNullPtr() { return this.buffer[0] === 0 && this.buffer[1] === 0; }
    isNegativeOne() { return this.buffer[0] === 0xFFFFFFFF && this.buffer[1] === 0xFFFFFFFF; }

    add(other) {
        if (!(other instanceof AdvancedInt64)) other = AdvancedInt64.fromNumber(other);
        let low = (this.buffer[0] + other.buffer[0]); // Soma sem mascarar ainda para pegar o carry
        let high = (this.buffer[1] + other.buffer[1] + (low > 0xFFFFFFFF ? 1 : 0)) >>> 0; // Adiciona carry se low estourou
        low = low >>> 0; // Agora mascara low
        return new AdvancedInt64(low, high);
    }

    sub(other) {
        if (!(other instanceof AdvancedInt64)) other = AdvancedInt64.fromNumber(other);
        // a - b = a + (-b)
        // -b = ~b + 1
        const neg_other_low = (~other.buffer[0] + 1) >>> 0;
        const neg_other_high = (~other.buffer[1] + ((~other.buffer[0] + 1) > 0xFFFFFFFF ? 1 : 0)) >>> 0;
        
        let low = (this.buffer[0] + neg_other_low);
        let high = (this.buffer[1] + neg_other_high + (low > 0xFFFFFFFF ? 1 : 0)) >>> 0;
        low = low >>> 0;
        return new AdvancedInt64(low, high);
    }
    
    greaterThanOrEqual(other) {
        if (!(other instanceof AdvancedInt64)) other = AdvancedInt64.fromNumber(other);
        // Compara high primeiro (considerando sinal se for fazer comparação de inteiros com sinal)
        // Para unsigned comparison:
        if (this.buffer[1] > other.buffer[1]) return true;
        if (this.buffer[1] < other.buffer[1]) return false;
        return this.buffer[0] >= other.buffer[0];
    }

    lessThan(other) {
        if (!(other instanceof AdvancedInt64)) other = AdvancedInt64.fromNumber(other);
        // Para unsigned comparison:
        if (this.buffer[1] < other.buffer[1]) return true;
        if (this.buffer[1] > other.buffer[1]) return false;
        return this.buffer[0] < other.buffer[0];
    }

    static fromNumber(n) {
        if (typeof n !== 'number') throw new Error("fromNumber espera um número");
        const isNegative = n < 0;
        n = Math.abs(n);
        let low = n % Math.pow(2, 32);
        let high = Math.floor(n / Math.pow(2, 32));
        
        if (isNegative) {
            // Realiza complemento de dois
            let tempLow = (~low + 1) >>> 0;
            let tempHigh = ~high;
            if (tempLow === 0 && low !== 0) { // Se low era 0xFFFFFFFF, ~low+1 é 0, precisa propagar carry para high
                tempHigh = (tempHigh + 1) >>> 0;
            }
            low = tempLow;
            high = tempHigh;
        }
        return new AdvancedInt64(low, high);
    }

    static fromHex(hexStr) {
        return new AdvancedInt64(hexStr); // O construtor já lida com string hex
    }
}

// Função de verificação centralizada
export function isAdvancedInt64Object(obj) {
    return obj instanceof AdvancedInt64 && 
           typeof obj.isNullPtr === 'function' &&
           typeof obj.isNegativeOne === 'function' &&
           typeof obj.greaterThanOrEqual === 'function' &&
           typeof obj.equals === 'function' &&
           typeof obj.toString === 'function';
}

// Constantes estáticas (ou equivalentes)
AdvancedInt64.Zero = new AdvancedInt64(0,0);
AdvancedInt64.One = new AdvancedInt64(1,0);
AdvancedInt64.NegOne = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

export function testModule(logFnParam) {
    // Usa console.log como fallback se logFnParam não for uma função
    const log = (typeof logFnParam === 'function') ? logFnParam : (msg, type, func) => console.log(`${func ? '['+func+'] ' : ''}${type}: ${msg}`);

    log("--- Testando Módulo Int64 (int64.mjs) ---", "test", "Int64.test");
    const a = new AdvancedInt64("0x100000000"); // high=1, low=0
    const b = new AdvancedInt64(1,1); // high=1, low=1
    const c = AdvancedInt64.fromNumber(-1);
    log(`a = ${a.toString(true)}`, "info", "Int64.test");
    log(`b = ${b.toString(true)}`, "info", "Int64.test");
    log(`c = ${c.toString(true)} (isNegativeOne: ${c.isNegativeOne()})`, "info", "Int64.test");
    log(`a + b = ${a.add(b).toString(true)}`, "info", "Int64.test");
    
    const d = new AdvancedInt64("0x0000000000000000");
    log(`d = ${d.toString(true)}, isNullPtr: ${d.isNullPtr()}`, "info", "Int64.test");
    log(`isAdvancedInt64Object(d): ${isAdvancedInt64Object(d)}`, "info", "Int64.test"); // Deve ser true
    const plainObj = { low: 0, high: 0 };
    log(`isAdvancedInt64Object(plainObj): ${isAdvancedInt64Object(plainObj)}`, "info", "Int64.test"); // Deve ser false
    const numVal = 123;
    log(`isAdvancedInt64Object(numVal): ${isAdvancedInt64Object(numVal)}`, "info", "Int64.test"); // Deve ser false
    
    const fromNumPos = AdvancedInt64.fromNumber(10);
    log(`AdvancedInt64.fromNumber(10): ${fromNumPos.toString(true)}`, "info", "Int64.test");
    const fromNumNeg = AdvancedInt64.fromNumber(-10);
    log(`AdvancedInt64.fromNumber(-10): ${fromNumNeg.toString(true)}`, "info", "Int64.test");


    log("Teste Int64 concluído.", "test", "Int64.test");
}
