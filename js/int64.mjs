// js/int64.mjs

export class AdvancedInt64 {
    constructor(low, high) {
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
        } else if (low && low._isAdvancedInt64 === true) { // Prioriza a propriedade para cópia
            this.buffer[0] = low.buffer[0];
            this.buffer[1] = low.buffer[1];
        } else if (low instanceof AdvancedInt64) { // Fallback
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
            if (this.buffer[1] === 0 && this.buffer[0] >= 0 && this.buffer[0] <= Number.MAX_SAFE_INTEGER) return String(this.buffer[0]);
            if (this.buffer[1] === 0xFFFFFFFF && (this.buffer[0] & 0x80000000)) {
                 const num = this.buffer[0] | 0;
                 if (num >= Number.MIN_SAFE_INTEGER) return String(num);
            }
            return `(Int64 H:0x${this.buffer[1].toString(16).padStart(8,'0')} L:0x${this.buffer[0].toString(16).padStart(8,'0')})`;
        }
        const highHex = this.buffer[1].toString(16).padStart(8, '0');
        const lowHex = this.buffer[0].toString(16).padStart(8, '0');
        return `0x${highHex}_${lowHex}`;
    }

    toNumber() { 
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
        if (!isAdvancedInt64Object(other)) return false;
        return this.buffer[0] === other.buffer[0] && this.buffer[1] === other.buffer[1];
    }
    
    isNullPtr() { return this.buffer[0] === 0 && this.buffer[1] === 0; }
    isNegativeOne() { return this.buffer[0] === 0xFFFFFFFF && this.buffer[1] === 0xFFFFFFFF; }

    add(other) { 
        if (!isAdvancedInt64Object(other)) other = AdvancedInt64.fromNumber(Number(other));
        let low = (this.buffer[0] + other.buffer[0]);
        let high = (this.buffer[1] + other.buffer[1] + (low > 0xFFFFFFFF ? 1 : 0)) >>> 0;
        low = low >>> 0;
        return new AdvancedInt64(low, high);
    }

    sub(other) { 
        if (!isAdvancedInt64Object(other)) other = AdvancedInt64.fromNumber(Number(other));
        const neg_other_low = (~other.buffer[0] + 1) >>> 0;
        const neg_other_high = (~other.buffer[1] + ((~other.buffer[0] + 1) > 0xFFFFFFFF ? 1 : 0)) >>> 0;
        let low = (this.buffer[0] + neg_other_low);
        let high = (this.buffer[1] + neg_other_high + (low > 0xFFFFFFFF ? 1 : 0)) >>> 0;
        low = low >>> 0;
        return new AdvancedInt64(low, high);
    }
    
    greaterThanOrEqual(other) { 
        if (!isAdvancedInt64Object(other)) other = AdvancedInt64.fromNumber(Number(other));
        if (this.buffer[1] > other.buffer[1]) return true;
        if (this.buffer[1] < other.buffer[1]) return false;
        return this.buffer[0] >= other.buffer[0];
    }
    lessThan(other) { 
        if (!isAdvancedInt64Object(other)) other = AdvancedInt64.fromNumber(Number(other));
        if (this.buffer[1] < other.buffer[1]) return true;
        if (this.buffer[1] > other.buffer[1]) return false;
        return this.buffer[0] < other.buffer[0];
     }

    static fromNumber(n) {
        if (typeof n !== 'number' || isNaN(n) || !isFinite(n)) {
            return new AdvancedInt64(0,0); // Retorna zero para NaN/Infinity
        }
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

export function isAdvancedInt64Object(obj) {
    const hasProp = obj && obj._isAdvancedInt64 === true;
    const hasIsNullPtr = obj && typeof obj.isNullPtr === 'function';
    const hasToString = obj && typeof obj.toString === 'function';
    // Se precisar de log aqui para depurar qual falha:
    // if (obj && (!hasProp || !hasIsNullPtr || !hasToString)) {
    //     console.log(`isAdvancedInt64Object check: obj exists, _isAdvInt64=${obj._isAdvancedInt64}, typeof isNullPtr=${typeof obj.isNullPtr}, typeof toString=${typeof obj.toString}`);
    // }
    return hasProp && hasIsNullPtr && hasToString;
}

AdvancedInt64.Zero = new AdvancedInt64(0,0);
AdvancedInt64.One = new AdvancedInt64(1,0);
AdvancedInt64.NegOne = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

export function testModule(logFnParam) {
    const log = (typeof logFnParam === 'function') ? logFnParam : (msg, type, func) => console.log(`${func ? '['+func+'] ' : ''}${type || 'info'}: ${msg}`);
    log("--- Testando Módulo Int64 (int64.mjs) ---", "test", "Int64.test");
    const a = new AdvancedInt64("0x100000000");
    log(`a = ${a.toString(true)}, isAdvInt64: ${isAdvancedInt64Object(a)}, _isProp: ${a._isAdvancedInt64}`, "info", "Int64.test");
    const d = new AdvancedInt64(0,0);
    log(`d = ${d.toString(true)}, isNullPtr: ${d.isNullPtr()}, isAdvInt64: ${isAdvancedInt64Object(d)}, _isProp: ${d._isAdvancedInt64}`, "info", "Int64.test");
    const plainObj = { _isAdvancedInt64: true, isNullPtr: () => false, toString: () => "fake" };
    log(`isAdvancedInt64Object(plainObj com _isAdvancedInt64=true e metodos): ${isAdvancedInt64Object(plainObj)}`, "info", "Int64.test");
    log("Teste Int64 concluído.", "test", "Int64.test");
}
