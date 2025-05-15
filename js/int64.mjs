// js/int64.mjs

// Não importamos 'log' aqui, esperamos que seja injetado em testModule

export class AdvancedInt64 {
    // ... (nenhuma alteração no construtor ou métodos da classe) ...
    constructor(low, high) {
        this.buffer = new Uint32Array(2);
        this.bytes = new Uint8Array(this.buffer.buffer);

        if (arguments.length === 0) { this.buffer[0] = 0; this.buffer[1] = 0; return; }

        if (typeof low === 'string') {
            let hexstr = low.startsWith("0x") ? low.substring(2) : low;
            if (hexstr.length % 2 !== 0) hexstr = '0' + hexstr;
            if (hexstr.length > 16) hexstr = hexstr.substring(hexstr.length - 16);
            else hexstr = hexstr.padStart(16, '0');
            for (let i = 0; i < 8; i++) { this.bytes[i] = parseInt(hexstr.slice(14 - i * 2, 16 - i * 2), 16); }
        } else if (typeof low === 'number') {
            this.buffer[0] = low;
            if (arguments.length === 1) { this.buffer[1] = (low < 0 && Math.abs(low) > 0xFFFFFFFF) ? -1 : 0; }
            else if (typeof high === 'number') { this.buffer[1] = high; }
            else { throw TypeError('High argument must be a number if provided and low is a number.'); }
        } else if (low instanceof AdvancedInt64) {
            this.buffer[0] = low.low(); this.buffer[1] = low.high();
        } else if (low instanceof Uint8Array && low.length === 8) {
            this.bytes.set(low);
        } else { throw TypeError('AdvancedInt64: Invalid constructor arguments.'); }
    }
    low() { return this.buffer[0]; }
    high() { return this.buffer[1]; }
    toString(pretty = false) { let hS = (this.high()>>>0).toString(16).padStart(8,'0'); let lS = (this.low()>>>0).toString(16).padStart(8,'0'); return pretty ? `0x${hS.substring(0,4)}_${hS.substring(4)}_${lS.substring(0,4)}_${lS.substring(4)}` : `0x${hS}${lS}`; }
    add(o) { o=!(o instanceof AdvancedInt64)?new AdvancedInt64(o):o; let nL=(this.low()+o.low())>>>0; let c=((this.low()&0xFFFFFFFF)+(o.low()&0xFFFFFFFF)>0xFFFFFFFF)?1:0; let nH=(this.high()+o.high()+c)>>>0; return new AdvancedInt64(nL,nH); }
    sub(o) { o=!(o instanceof AdvancedInt64)?new AdvancedInt64(o):o; return this.add(o.neg()); }
    neg() { const l=~this.low(); const h=~this.high(); return new AdvancedInt64(l,h).add(AdvancedInt64.One); }
    equals(o) { o=!(o instanceof AdvancedInt64)?new AdvancedInt64(o):o; return this.low()===o.low()&&this.high()===o.high(); }
    isZero() { return this.low() === 0 && this.high() === 0; }
    isNegativeOne() { return this.low() === 0xFFFFFFFF && this.high() === 0xFFFFFFFF; }
    static fromParts(l,h){return new AdvancedInt64(l,h);} static fromNumber(n){return new AdvancedInt64(n);}
}

AdvancedInt64.Zero = new AdvancedInt64(0,0);
AdvancedInt64.One = new AdvancedInt64(1,0);
AdvancedInt64.NegOne = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
AdvancedInt64.NullPtr = new AdvancedInt64(0,0);

export function testModule(logFn) {
    // Verifica se logFn foi passado e é uma função
    if (!logFn || typeof logFn !== 'function') {
        // Tenta usar console.error como fallback se o log da UI não estiver disponível
        const fallbackLog = (typeof console !== 'undefined' && console.error) ? console.error : (msg) => {};
        fallbackLog("Int64.testModule: Função de log não fornecida ou inválida!");
        // Ainda assim tenta executar os testes, mas sem log específico da UI se logFn falhar
        // Isso ajuda a ver se a lógica de Int64 em si está ok, mesmo que o logging falhe.
        if (!logFn) logFn = (msg, type, func) => fallbackLog(`${func}: ${type} - ${msg}`);
    }

    logFn("--- Testando Módulo Int64 (int64.mjs) ---", "test", "Int64.test");
    const a = new AdvancedInt64("0x100000000");
    const b = new AdvancedInt64(1,1);
    const c = AdvancedInt64.fromNumber(-1);
    logFn(`a = ${a.toString(true)}`, "info", "Int64.test");
    logFn(`b = ${b.toString(true)}`, "info", "Int64.test");
    logFn(`c = ${c.toString(true)} (isNegativeOne: ${c.isNegativeOne()})`, "info", "Int64.test");
    logFn(`a + b = ${a.add(b).toString(true)}`, "info", "Int64.test");
    logFn("Teste Int64 concluído.", "good", "Int64.test");
}
