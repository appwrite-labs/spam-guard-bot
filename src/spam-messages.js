import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const spamMessagesPath = fileURLToPath(new URL("../spam-messages.json", import.meta.url));
const spamDescriptionPatternsPath = fileURLToPath(new URL("../spam-description-patterns.json", import.meta.url));

// JSON does not officially allow literal line breaks inside strings. We accept
// them here so messages can be pasted into the file without escaping anything.
function escapeLiteralControlCharactersInStrings(source) {
  let result = "";
  let inString = false;
  let escaped = false;

  for (const character of source) {
    if (inString) {
      if (escaped) {
        result += character;
        escaped = false;
      } else if (character === "\\") {
        result += character;
        escaped = true;
      } else if (character === '"') {
        result += character;
        inString = false;
      } else if (character === "\n") {
        result += "\\n";
      } else if (character === "\r") {
        result += "\\r";
      } else if (character === "\t") {
        result += "\\t";
      } else {
        result += character;
      }
    } else {
      result += character;
      if (character === '"') {
        inString = true;
      }
    }
  }

  return result;
}

const spamConfig = JSON.parse(
  escapeLiteralControlCharactersInStrings(readFileSync(spamMessagesPath, "utf8")),
);
const spamDescriptionConfig = JSON.parse(readFileSync(spamDescriptionPatternsPath, "utf8"));

// Matching is case-insensitive and ignores accents and repeated whitespace.
export const SPAM_MESSAGES = Object.freeze(spamConfig);
export const SPAM_DESCRIPTION_PATTERNS = Object.freeze(spamDescriptionConfig);

export function normalizeSpamText(value) {
  return typeof value === "string"
    ? value.normalize("NFKD").replace(/\p{Diacritic}/gu, "").replace(/\s+/gu, " ").trim().toLowerCase()
    : "";
}

export function findSpamMessage(content, spamMessages = SPAM_MESSAGES, descriptionConfig = SPAM_DESCRIPTION_PATTERNS) {
  const normalizedContent = normalizeSpamText(content);

  if (!normalizedContent) {
    return null;
  }

  const messages = Array.isArray(spamMessages) ? spamMessages : spamMessages.messages;
  const descriptionPatterns = descriptionConfig.patterns ?? [];
  const descriptionExclusions = descriptionConfig.exclusions ?? [];

  for (const spamMessage of messages ?? []) {
    const normalizedSpamMessage = normalizeSpamText(spamMessage);

    if (normalizedSpamMessage && normalizedContent.includes(normalizedSpamMessage)) {
      return spamMessage;
    }
  }

  if (descriptionExclusions.some((pattern) => new RegExp(pattern, "u").test(normalizedContent))) {
    return null;
  }

  for (const pattern of descriptionPatterns) {
    const match = new RegExp(pattern, "u").exec(normalizedContent);

    if (match) {
      return `Blocked wording: "${match[0]}"`;
    }
  }

  return null;
}

export function getMessageText(message) {
  const parts = [];
  const visited = new Set();

  function add(value) {
    if (typeof value === "string" && value.trim()) {
      parts.push(value);
    }
  }

  function collect(currentMessage) {
    if (!currentMessage || typeof currentMessage !== "object" || visited.has(currentMessage)) {
      return;
    }

    visited.add(currentMessage);
    add(currentMessage.content);

    for (const embed of currentMessage.embeds ?? []) {
      add(embed?.title);
      add(embed?.description);
      add(embed?.url);
      add(embed?.author?.name);
      add(embed?.author?.url);
      add(embed?.footer?.text);

      for (const field of embed?.fields ?? []) {
        add(field?.name);
        add(field?.value);
      }
    }

    for (const attachment of currentMessage.attachments?.values?.() ?? []) {
      add(attachment?.description);
      add(attachment?.url);
    }

    for (const snapshot of currentMessage.messageSnapshots?.values?.() ?? []) {
      collect(snapshot);
    }
  }

  collect(message);
  return parts.join("\n");
}

export function getSpamText(message) {
  return getMessageText(message);
}
