var helpers = (() => {
    const malloc = (size) => {
        return p.malloc(size);
    };

    const write8 = (addr, val) => {
        p.write8(addr, val);
    };

    const writeUtf8String = (addr, str) => {
        p.writeUtf8String(addr, str);
    };

    const callFunction = (funcAddr, args) => {
        return p.call(funcAddr, args);
    };

    return {
        malloc,
        write8,
        writeUtf8String,
        callFunction
    };
})();