const STRINGS = {
  en: {
    moderation: {
      alertTitle: "Suspicious image blocked",
      alertDescription: "A suspicious image was detected.",
      alertContent: (tag) => `Moderation alert: ${tag}`,
      user: "User",
      channel: "Channel",
      message: "Message",
      imageSource: "Image source",
      timeout: (minutes) => `Timeout (${minutes} min)`,
      messageDeleted: "Message deleted",
      recognizedText: "Recognized text",
      detectionMethod: "Detection method",
      visualMatch: (label, distance) =>
        `Visual match: ${label} (distance ${distance})`,
      knownScamImageChannel: (name, channelId) =>
        `Known scam-image source channel: ${name} (\`${channelId}\`)`,
      ocrMatch: (reasons) => `OCR + ${reasons.join(" + ")}`,
      ocrKeywords: "Keywords",
      ocrMrBeast: "Mr-beast keywords",
      ocrMaliciousDomain: "Malicious domains",
      ocrMaliciousServer: "Malicious servers",
      ocrSkipped: "(visual match, OCR skipped)",
      knownChannelOcrSkipped: "(known scam-image source channel, OCR skipped)",
      yes: "Yes",
      noPrefix: (reason) => `No: ${reason}`,
      emptyText: "(empty)",
      timeoutFailure:
        "The bot cannot apply a timeout because of permissions or role hierarchy.",
      raidAlertTitle: "Anti-raid triggered",
      raidAlertContent: (tag) => `Anti-raid alert: ${tag}`,
      raidMessage: "Deleted repeated message",
      spamAlertTitle: "Spam message blocked",
      spamAlertContent: (tag) => `Spam alert: ${tag}`,
      spamMessage: "Spam message",
      maliciousServerAlertTitle: "Malicious server invite blocked",
      maliciousServerAlertContent: (tag) => `Malicious server invite alert: ${tag}`,
      maliciousServer: "Blocked server ID",
      inviteCode: "Invite code",
      nsfwServerAlertTitle: "NSFW server invite blocked",
      nsfwServerAlertContent: (tag) => `NSFW server invite alert: ${tag}`,
      serverName: "Server name",
      matchedDetection: "Matched detection",
      keywordDetection: (keyword) => `Keyword: ${keyword}`,
      serverId: "Server ID",
      unknown: "(unknown)",
      feedbackTitle: "Help improve detection",
      falseDetection: "False detection",
      correctDetection: "Correct detection",
      feedbackExpired: "This feedback is no longer available.",
      feedbackWrongServer: "You can only rate this detection from its server.",
      feedbackDisabled: "Feedback sending is disabled.",
      feedbackFailed: "The feedback could not be sent.",
      feedbackReport: (value) => `OCR detection feedback: **${value}**`,
      feedbackFalse: "false detection",
      feedbackCorrect: "correct detection",
      manualSpamReport: "Manual spam report",
      spamReportNoPermission: "You need the Manage Messages permission to use `!spamreport`.",
      spamReportReplyRequired: "Reply to the message you want to report with `!spamreport`.",
      spamReportBotMessage: "Messages from bots cannot be reported.",
      spamReportTimedOut: (deleted) => `User timed out. Matching messages deleted: ${deleted}.`,
      spamReportTimeoutFailed: (deleted) => `The timeout could not be applied. Matching messages deleted: ${deleted}.`,
      spamReportFailed: "The report could not be processed. Check that the bot can view the channel, delete messages, and time out members.",
      reportedBy: "Reported by",
      originalServerChannel: "Original server/channel",
      recognizedText: "Text recognized by OCR",
    },
  },
  es: {
    moderation: {
      alertTitle: "Se bloqueó una imagen sospechosa",
      alertDescription: "Se detectó una imagen sospechosa.",
      alertContent: (tag) => `Aviso de moderación: ${tag}`,
      user: "Usuario",
      channel: "Canal",
      message: "Mensaje",
      imageSource: "Origen de la imagen",
      timeout: (minutes) => `Expulsión temporal (${minutes} min)`,
      messageDeleted: "Mensaje borrado",
      recognizedText: "Texto reconocido",
      detectionMethod: "Método de detección",
      visualMatch: (label, distance) =>
        `Coincidencia visual: ${label} (distancia ${distance})`,
      knownScamImageChannel: (name, channelId) =>
        `Canal fuente conocido de imágenes de estafa: ${name} (\`${channelId}\`)`,
      ocrMatch: (reasons) => `OCR + ${reasons.join(" + ")}`,
      ocrKeywords: "Palabras clave",
      ocrMrBeast: "Palabras de mr-beast",
      ocrMaliciousDomain: "Dominios maliciosos",
      ocrMaliciousServer: "Servidores maliciosos",
      ocrSkipped: "(coincidencia visual, OCR omitido)",
      knownChannelOcrSkipped: "(canal fuente conocido de imágenes de estafa, OCR omitido)",
      yes: "Sí",
      noPrefix: (reason) => `No: ${reason}`,
      emptyText: "(vacío)",
      timeoutFailure:
        "El bot no puede aplicar una expulsión temporal por permisos o jerarquía de roles.",
      raidAlertTitle: "Se activó la protección anti-raid",
      raidAlertContent: (tag) => `Aviso anti-raid: ${tag}`,
      raidMessage: "Mensaje repetido borrado",
      spamAlertTitle: "Se bloqueó un mensaje de spam",
      spamAlertContent: (tag) => `Aviso de spam: ${tag}`,
      spamMessage: "Mensaje de spam",
      maliciousServerAlertTitle: "Se bloqueó una invitación a un servidor malicioso",
      maliciousServerAlertContent: (tag) => `Aviso de servidor malicioso: ${tag}`,
      maliciousServer: "ID del servidor bloqueado",
      inviteCode: "Código de invitación",
      nsfwServerAlertTitle: "Se bloqueó una invitación a un servidor NSFW",
      nsfwServerAlertContent: (tag) => `Aviso de servidor NSFW: ${tag}`,
      serverName: "Nombre del servidor",
      matchedDetection: "Detección coincidente",
      keywordDetection: (keyword) => `Palabra clave: ${keyword}`,
      serverId: "ID del servidor",
      unknown: "(desconocido)",
      feedbackTitle: "Ayuda a mejorar la detección",
      falseDetection: "Falsa detección",
      correctDetection: "Detección correcta",
      feedbackExpired: "Este feedback ya no está disponible.",
      feedbackWrongServer: "Solo puedes valorar esta detección desde su servidor.",
      feedbackDisabled: "El envío de feedback está desactivado.",
      feedbackFailed: "No se pudo enviar el feedback.",
      feedbackReport: (value) => `Feedback de detección OCR: **${value}**`,
      feedbackFalse: "falsa detección",
      feedbackCorrect: "detección correcta",
      manualSpamReport: "Reporte manual de spam",
      spamReportNoPermission: "Necesitas el permiso Gestionar mensajes para usar `!spamreport`.",
      spamReportReplyRequired: "Debes responder al mensaje que quieres reportar usando `!spamreport`.",
      spamReportBotMessage: "No se pueden reportar mensajes de bots.",
      spamReportTimedOut: (deleted) => `Usuario puesto en timeout. Mensajes iguales eliminados: ${deleted}.`,
      spamReportTimeoutFailed: (deleted) => `No se pudo aplicar el timeout. Mensajes iguales eliminados: ${deleted}.`,
      spamReportFailed: "No se pudo procesar el reporte. Revisa que el bot pueda ver el canal, borrar mensajes y aplicar timeouts.",
      reportedBy: "Reportado por",
      originalServerChannel: "Servidor/canal original",
      recognizedText: "Texto reconocido por OCR",
    },
  },
};

function normalizeLocale(locale) {
  if (typeof locale !== "string") {
    return "en";
  }

  return locale.toLowerCase().startsWith("es") ? "es" : "en";
}

export function resolveLocale(source) {
  return normalizeLocale(
    source?.guildLocale ?? source?.preferredLocale ?? source?.locale,
  );
}

export function t(locale, namespace, key, ...args) {
  const lang = STRINGS[normalizeLocale(locale)] ?? STRINGS.en;
  const value = lang[namespace]?.[key] ?? STRINGS.en[namespace]?.[key];

  if (typeof value === "function") {
    return value(...args);
  }

  return value ?? "";
}
