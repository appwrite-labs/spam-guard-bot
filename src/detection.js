import { findBlockedDomain } from "./blocked-links.js";

const WITHDRAWAL_KEYWORDS = ["WITHDRAWAL"];
const SUCCESS_KEYWORDS = ["SUCCESS", "SUCCEEDED", "SUCCESSFUL", "SUCCESSFULLY"];
const USDT_KEYWORDS = ["USDT"];
const AMOUNT_KEYWORDS = ["AMOUNT"];
const COMPLETED_KEYWORDS = ["COMPLETED"];
const TRANSFER_KEYWORDS = ["TRANSFER"];
const EXTREME_KEYWORDS = [
  "WITHDRAWAL",
  "AMOUNT",
  "COMPLETED",
  "TRANSFER",
  "SUCCS",
  "TRX",
  "MONEY",
  "MR BEAST",
  "CRYPTOCURRENCY",
  "CASINO",
  "GIVEAWAY",
  "GIVING AWAY",
  "BETS",
  "BONUS",
  "BONUSES",
];
// A hiring or recruitment ad needs all three signals: recruitment intent, a
// tech role or stack, and a request to make contact. Plain "looking for" or
// "join" do not count as intent, so help requests and event invites pass.
const RECRUITMENT_GROUPS = [
  /\b(?:hiring|recruit(?:ing|ment|ers?)?|looking\s+for\s+(?:\S+\s+){0,3}?(?:developers?|devs?|engineers?|designers?|programmers?|freelancers?|team\s*mates?|team\s+members?|co-?founders?)|join\s+(?:my|our)\s+(?:team|startup)|(?:full|part)[- ]time\s+(?:role|position|job)|paid\s+(?:role|position|opportunity|collaboration|project)|long[- ]term\s+(?:collaboration|partnership|project|position|role)|job\s+(?:opening|opportunity|offer))\b/iu,
  /\b(?:developers?|devs?|engineers?|designers?|programmers?|hackathon|ai|artificial intelligence|full[- ]stack|frontend|backend|api|langgraph|crewai|react|next\.js|database|cloud|ui\/?ux|web3|blockchain)\b/iu,
  /\b(?:dms?|direct message|pm me|inbox me|message me|contact me|reach out|telegram|whatsapp|portfolio|linkedin|cv|resume)\b/iu,
];
export const PARANOIA_LEVELS = Object.freeze({
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  EXTREME: "extreme",
});

export const OCR_DETECTION_REASONS = Object.freeze({
  KEYWORDS: "keywords",
  MR_BEAST: "mrBeast",
  MALICIOUS_DOMAIN: "maliciousDomain",
  MALICIOUS_SERVER: "maliciousServer",
});

export const DEFAULT_PARANOIA_LEVEL = PARANOIA_LEVELS.HIGH;

export function normalizeParanoiaLevel(level) {
  if (typeof level !== "string") {
    return DEFAULT_PARANOIA_LEVEL;
  }

  const normalized = level.trim().toLowerCase();

  if (normalized === PARANOIA_LEVELS.LOW) {
    return PARANOIA_LEVELS.LOW;
  }

  if (normalized === PARANOIA_LEVELS.MEDIUM) {
    return PARANOIA_LEVELS.MEDIUM;
  }

  if (normalized === PARANOIA_LEVELS.HIGH) {
    return PARANOIA_LEVELS.HIGH;
  }

  if (normalized === PARANOIA_LEVELS.EXTREME) {
    return PARANOIA_LEVELS.EXTREME;
  }

  return DEFAULT_PARANOIA_LEVEL;
}

function containsWholeWord(text, word) {
  return new RegExp(`\\b${word}\\b`, "u").test(text);
}

function containsPhrase(text, phrase) {
  return text.includes(phrase);
}

function hasAnyKeyword(text, keywords) {
  return keywords.some((word) => containsWholeWord(text, word));
}

function hasAnyPhrase(text, phrases) {
  return phrases.some((phrase) => containsPhrase(text, phrase));
}

export function containsBlockedDomain(text) {
  return findBlockedDomain(text) !== null;
}

export function normalizeOcrText(text) {
  return text
    .normalize("NFKD")
    .replace(/\p{Diacritic}/gu, "")
    .toUpperCase();
}

export function findOcrDetectionReasons(
  text,
  paranoiaLevel = DEFAULT_PARANOIA_LEVEL,
) {
  const normalizedLevel = normalizeParanoiaLevel(paranoiaLevel);
  const reasons = [];

  if (containsBlockedDomain(text)) {
    reasons.push(OCR_DETECTION_REASONS.MALICIOUS_DOMAIN);
  }

  if (normalizedLevel === PARANOIA_LEVELS.LOW) {
    return reasons;
  }

  const rawText = text;
  const normalizedText = normalizeOcrText(text);

  const hasWithdrawalKeyword = hasAnyKeyword(normalizedText, WITHDRAWAL_KEYWORDS);
  const hasSuccessKeyword = hasAnyKeyword(normalizedText, SUCCESS_KEYWORDS);
  const hasUsdtKeyword = hasAnyKeyword(rawText, USDT_KEYWORDS);
  const hasAmountKeyword = hasAnyKeyword(normalizedText, AMOUNT_KEYWORDS);
  const hasCompletedKeyword = hasAnyKeyword(normalizedText, COMPLETED_KEYWORDS);
  const hasTransferKeyword = hasAnyKeyword(normalizedText, TRANSFER_KEYWORDS);
  const hasExtremeKeyword = hasAnyKeyword(normalizedText, EXTREME_KEYWORDS) ||
    hasAnyPhrase(normalizedText, EXTREME_KEYWORDS);

  if (normalizedLevel === PARANOIA_LEVELS.MEDIUM) {
    if (hasWithdrawalKeyword && hasSuccessKeyword && hasUsdtKeyword) {
      reasons.push(OCR_DETECTION_REASONS.KEYWORDS);
    }

    return reasons;
  }

  if (normalizedLevel === PARANOIA_LEVELS.EXTREME) {
    if (hasExtremeKeyword) {
      reasons.push(OCR_DETECTION_REASONS.MR_BEAST);
    }

    return reasons;
  }

  if (
    hasWithdrawalKeyword &&
    (hasSuccessKeyword ||
      hasUsdtKeyword ||
      (hasAmountKeyword && hasCompletedKeyword && hasTransferKeyword))
  ) {
    reasons.push(OCR_DETECTION_REASONS.KEYWORDS);
  }

  return reasons;
}

export function containsScamPhrase(text, paranoiaLevel = DEFAULT_PARANOIA_LEVEL) {
  return findOcrDetectionReasons(text, paranoiaLevel).length > 0;
}

/** Detects hiring and recruitment advertisements in message text. */
export function findSuspiciousText(text) {
  if (typeof text !== "string" || !text.trim()) return null;
  const normalizedText = normalizeOcrText(text);
  if (RECRUITMENT_GROUPS.every((pattern) => pattern.test(normalizedText))) {
    return "Hiring or recruitment advertisement requesting contact";
  }
  return null;
}

export function truncateText(text, maxLength = 900) {
  if (typeof text !== "string") {
    return "";
  }

  const compactText = text.replace(/\s+/gu, " ").trim();

  if (compactText.length <= maxLength) {
    return compactText;
  }

  return `${compactText.slice(0, maxLength - 1)}…`;
}
