// js/int64.mjs

export class AdvancedInt64 {
    constructor(low, high) {
        // Adiciona uma propriedade distintiva, não enumerável
        Object.defineProperty(this, '_isAdvancedInt64', {
            value: true,
            writable: false,
            enumerable: false,
            configurable: false
        });

        this.buffer = new Uint32Array(2); // [low, high]
        this.bytes = new Uint8Array(this.buffer.buffer);

        if (arguments.length === 0) {
            this.buffer[0] = 0; this.buffer[1] = 0;
            return;
        }

        if (typeof low === 'string') {
            let hexstr = low.startsWith("0x") ? low.substring(2) : low;
            hexstr = hexstr.replace(/_/g, '');
            if (hexstr.length > 16) hexstr = hexstr.substring(hexstr.length - 16);
            hexstr = hexstr.padStart(16, '0');
            this.buffer[1] = parseInt(hexstr.substring(0, 8), 16); // High
            this.buffer[0] = parseInt(hexstr.substring(8, 16), 16); // Low
        } else if (typeof low === 'number') {
            this.buffer[0] = low & 0xFFFFFFFF;
            if (arguments.length === 1) {
                this.buffer[1] = (low < 0 && Math.abs(low) > 0xFFFFFFFF) ? 0xFFFFFFFF : 0;
            } else if (typeof high === 'number') {
                this.buffer[1] = high & 0xFFFFFFFF;
            } else {
                 this.buffer[1] = 0;
            }
        } else if (low instanceof AdvancedInt64 || (low && low._isAdvancedInt64 === true)) { // Verifica também a propriedade
            this.buffer[0] = low.buffer[0];
            this.buffer[1] = low.buffer[1];
        } else {
            this.buffer[0] = 0; this.buffer[1] = 0;
        }
    }

    low() { return this.buffer[0]; }
    high() { return this.buffer[1]; }

    toString(hex = false) {
        if (!hex) {
            if (this.buffer[1] === 0 && this.buffer[0] >= 0) return String(this.buffer[0]);
            if (this.buffer[1] === 0xFFFFFFFF && (this.buffer[0] & 0x80000000)) return String(this.buffer[0] | 0);
            return `(Int64: H:0x${this.buffer[1].toString(16).padStart(8,'0')} L:0x${this.buffer[0].toString(16).padStart(8,'0')})`;
        }
        const highHex = this.buffer[1].toString(16).padStart(8, '0');
        const lowHex = this.buffer[0].toString(16).padStart(8, '0');
        return `0x${highHex}_${lowHex}`;
    }

    toNumber() { /* ... (como antes) ... */ 
        const high = this.buffer[1];
        const low = this.buffer[0];
        const sign = high & 0x80000000;
        if (sign) {
            let twosCompLow = (~low + 1) >>> 0;
            let twosCompHigh = (~high + (twosCompLow === 0 ? 1 : 0)) >>> 0;
            if (twosCompLow === 0 && low !==0) twosCompHigh = (~high + 1) >>>0;
            return -(twosCompHigh * Math.pow(2, 32) + twosCompLow);
        } else {
            return high * Math.pow(2, 32) + low;
        }
    }

    equals(other) {
        // Verifica se 'other' é um AdvancedInt64 pela propriedade ou instanceof
        if (!isAdvancedInt64Object(other)) return false;
        return this.buffer[0] === other.buffer[0] && this.buffer[1] === other.buffer[1];
    }
    
    isNullPtr() { return this.buffer[0] === 0 && this.buffer[1] === 0; }
    isNegativeOne() { return this.buffer[0] === 0xFFFFFFFF && this.buffer[1] === 0xFFFFFFFF; }

    add(other) { /* ... (como antes, mas pode adicionar verificação isAdvancedInt64Object) ... */ 
        if (!isAdvancedInt64Object(other)) other = AdvancedInt64.fromNumber(other);
        let low = (this.buffer[0] + other.buffer[0]);
        let high = (this.buffer[1] + other.buffer[1] + (low > 0xFFFFFFFF ? 1 : 0)) >>> 0;
        low = low >>> 0;
        return new AdvancedInt64(low, high);
    }

    sub(other) { /* ... (como antes, mas pode adicionar verificação isAdvancedInt64Object) ... */ 
        if (!isAdvancedInt64Object(other)) other = AdvancedInt64.fromNumber(other);
        const neg_other_low = (~other.buffer[0] + 1) >>> 0;
        const neg_other_high = (~other.buffer[1] + ((~other.buffer[0] + 1) > 0xFFFFFFFF ? 1 : 0)) >>> 0;
        let low = (this.buffer[0] + neg_other_low);
        let high = (this.buffer[1] + neg_other_high + (low > 0xFFFFFFFF ? 1 : 0)) >>> 0;
        low = low >>> 0;
        return new AdvancedInt64(low, high);
    }
    
    greaterThanOrEqual(other) { /* ... (como antes, mas pode adicionar verificação isAdvancedInt64Object) ... */ 
        if (!isAdvancedInt64Object(other)) other = AdvancedInt64.fromNumber(other);
        if (this.buffer[1] > other.buffer[1]) return true;
        if (this.buffer[1] < other.buffer[1]) return false;
        return this.buffer[0] >= other.buffer[0];
    }
    lessThan(other) { /* ... (como antes, mas pode adicionar verificação isAdvancedInt64Object) ... */
        if (!isAdvancedInt64Object(other)) other = AdvancedInt64.fromNumber(other);
        if (this.buffer[1] < other.buffer[1]) return true;
        if (this.buffer[1] > other.buffer[1]) return false;
        return this.buffer[0] < other.buffer[0];
     }

    static fromNumber(n) { /* ... (como antes) ... */
        if (typeof n !== 'number') throw new Error("fromNumber espera um número");
        const isNegative = n < 0;
        n = Math.abs(n);
        let low = n % Math.pow(2, 32);
        let high = Math.floor(n / Math.pow(2, 32));
        if (isNegative) {
            let tempLow = (~low + 1) >>> 0;
            let tempHigh = ~high;
            if (tempLow === 0 && low !== 0) { tempHigh = (tempHigh + 1) >>> 0;}
            low = tempLow; high = tempHigh;
        }
        return new AdvancedInt64(low, high);
     }
    static fromHex(hexStr) { return new AdvancedInt64(hexStr); }
}

// Função de verificação centralizada agora verifica a propriedade distintiva E os métodos
export function isAdvancedInt64Object(obj) {
    return obj && obj._isAdvancedInt64 === true && // Checa a propriedade primeiro
           typeof obj.isNullPtr === 'function' &&
           typeof obj.isNegativeOne === 'function' &&
           typeof obj.greaterThanOrEqual === 'function' &&
           typeof obj.equals === 'function' &&
           typeof obj.toString === 'function';
}

AdvancedInt64.Zero = new AdvancedInt64(0,0);
AdvancedInt64.One = new AdvancedInt64(1,0);
AdvancedInt64.NegOne = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

export function testModule(logFnParam) {
    const log = (typeof logFnParam === 'function') ? logFnParam : (msg, type, func) => console.log(`${func ? '['+func+'] ' : ''}${type}: ${msg}`);
    log("--- Testando Módulo Int64 (int64.mjs) ---", "test", "Int64.test");
    // ... (testes como antes, isAdvancedInt64Object(d) deve continuar true)
    const a = new AdvancedInt64("0x100000000");
    const b = new AdvancedInt64(1,1);
    const c = AdvancedInt64.fromNumber(-1);
    log(`a = ${a.toString(true)}`, "info", "Int64.test");
    log(`b = ${b.toString(true)}`, "info", "Int64.test");
    log(`c = ${c.toString(true)} (isNegativeOne: ${c.isNegativeOne()})`, "info", "Int64.test");
    log(`a + b = ${a.add(b).toString(true)}`, "info", "Int64.test");
    
    const d = new AdvancedInt64("0x0000000000000000");
    log(`d = ${d.toString(true)}, isNullPtr: ${d.isNullPtr()}`, "info", "Int64.test");
    log(`isAdvancedInt64Object(d) [propriedade _isAdvancedInt64: ${d._isAdvancedInt64}]: ${isAdvancedInt64Object(d)}`, "info", "Int64.test");
    const plainObj = { low: 0, high: 0 };
    log(`isAdvancedInt64Object(plainObj) [propriedade _isAdvancedInt64: ${plainObj._isAdvancedInt64}]: ${isAdvancedInt64Object(plainObj)}`, "info", "Int64.test");
    
    log("Teste Int64 concluído.", "test", "Int64.test");
}
