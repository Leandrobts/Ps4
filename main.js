function log(msg) {
    const d = document.getElementById('log');
    d.textContent += msg + "\n";
    d.scrollTop = d.scrollHeight;
}

async function startNotification() {
    log("Iniciando envio de notificação...");

    window.libkernel_base = 0xXXXXXXXX; // <- Substituir
    window.offset_sceNotificationRequest = 0xYYYYY; // <- Substituir

    if (typeof p === "undefined") {
        log("[ERRO] Exploit WebKit não foi inicializado.");
        return;
    }

    const notificationMessage = "Exploit executado!";
    const notificationIcon = "";

    const sceNotificationRequestAddr = libkernel_base + offset_sceNotificationRequest;

    const notifReq = notification.createNotificationRequest(notificationMessage, notificationIcon);

    notification.sendNotification(notifReq, sceNotificationRequestAddr);

    log("Notificação enviada com sucesso!");
}