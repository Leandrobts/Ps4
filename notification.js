var notification = (() => {
    const STRUCT_SIZE = 0xC18;

    const createNotificationRequest = (messageText, iconUri = "") => {
        const req = helpers.malloc(STRUCT_SIZE);

        helpers.write8(req, 1);
        helpers.write8(req + 8, 0x1337);

        helpers.writeUtf8String(req + 0x10, messageText);
        helpers.writeUtf8String(req + 0x810, iconUri);

        return req;
    };

    const sendNotification = (requestAddr, sceNotificationRequestAddr) => {
        helpers.callFunction(sceNotificationRequestAddr, [0, requestAddr, STRUCT_SIZE, 0]);
    };

    return {
        createNotificationRequest,
        sendNotification
    };
})();