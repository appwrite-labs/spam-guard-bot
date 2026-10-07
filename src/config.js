import { fileURLToPath } from "node:url";
import { PARANOIA_LEVELS } from "./detection.js";
import { RAID_LEVELS } from "./raid-protection.js";

const DISCORD_MAX_TIMEOUT_MINUTES = 28 * 24 * 60;
const DISCORD_ID_PATTERN = /^\d{17,20}$/u;

export const VISUAL_REFERENCE_MANIFEST_PATH = fileURLToPath(
  new URL("../generated/visual-reference-manifest.json", import.meta.url),
);

// Defaults for every optional setting. Keep them in sync with the README tables.
export const DEFAULT_CONFIG = Object.freeze({
  feedbackChannelId: null,
  excludedRoleIds: Object.freeze([]),
  excludeAdmins: true,
  moderateBots: false,
  timeoutMs: 1440 * 60_000,
  antiRaidEnabled: true,
  antiRaidLevel: RAID_LEVELS.MEDIUM,
  spamMessagesEnabled: true,
  blockedLinksEnabled: true,
  maliciousInvitesEnabled: true,
  nsfwInvitesEnabled: true,
  textScamEnabled: true,
  imageScanSensitivity: PARANOIA_LEVELS.HIGH,
  visualMatchThreshold: 6,
  maxImageBytes: 8 * 1024 * 1024,
  maxImagePixels: 16_000_000,
  imageDownloadTimeoutMs: 15_000,
  spamReportEnabled: false,
  spamReportTimeoutMs: 10 * 60_000,
  spamReportLookbackMs: 60 * 60_000,
  visualReferenceManifestPath: VISUAL_REFERENCE_MANIFEST_PATH,
});

function readRaw(name) {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

function readRequiredString(name) {
  const value = readRaw(name);

  if (!value) {
    throw new Error(`Missing required environment variable: ${name}.`);
  }

  return value;
}

function readDiscordId(name, { required = false } = {}) {
  const value = required ? readRequiredString(name) : readRaw(name);

  if (value === undefined) {
    return null;
  }

  if (!DISCORD_ID_PATTERN.test(value)) {
    throw new Error(`${name} must be a Discord ID (17 to 20 digits).`);
  }

  return value;
}

function readDiscordIdList(name) {
  const value = readRaw(name);

  if (value === undefined) {
    return [];
  }

  const ids = value.split(",").map((id) => id.trim()).filter(Boolean);
  const invalid = ids.find((id) => !DISCORD_ID_PATTERN.test(id));

  if (invalid) {
    throw new Error(`${name} contains "${invalid}", which is not a Discord ID.`);
  }

  return [...new Set(ids)];
}

function readBoolean(name, fallback) {
  const value = readRaw(name)?.toLowerCase();

  if (value === undefined) return fallback;
  if (value === "true") return true;
  if (value === "false") return false;

  throw new Error(`${name} must be either true or false.`);
}

function readChoice(name, choices, fallback) {
  const value = readRaw(name)?.toLowerCase();

  if (value === undefined) {
    return fallback;
  }

  if (!choices.includes(value)) {
    throw new Error(`${name} must be one of: ${choices.join(", ")}.`);
  }

  return value;
}

function readNumber(name, fallback, { integer = false, min = 0, minExclusive = true, max = Infinity } = {}) {
  const rawValue = readRaw(name);

  if (rawValue === undefined) {
    return fallback;
  }

  const value = Number(rawValue);
  const belowMin = minExclusive ? value <= min : value < min;

  if (!Number.isFinite(value) || (integer && !Number.isInteger(value)) || belowMin || value > max) {
    const kind = integer ? "a whole number" : "a number";
    const lower = minExclusive ? `greater than ${min}` : `at least ${min}`;
    const upper = Number.isFinite(max) ? ` and at most ${max}` : "";
    throw new Error(`${name} must be ${kind} ${lower}${upper}.`);
  }

  return value;
}

function readTimeoutMinutes(name, fallbackMs) {
  const minutes = readNumber(name, fallbackMs / 60_000, {
    max: DISCORD_MAX_TIMEOUT_MINUTES,
  });
  return minutes * 60_000;
}

export function loadConfig() {
  return {
    ...DEFAULT_CONFIG,
    discordToken: readRequiredString("DISCORD_TOKEN"),
    moderationChannelId: readDiscordId("MODERATION_CHANNEL_ID", { required: true }),
    feedbackChannelId: readDiscordId("FEEDBACK_CHANNEL_ID"),
    excludedRoleIds: readDiscordIdList("EXCLUDED_ROLE_IDS"),
    excludeAdmins: readBoolean("EXCLUDE_ADMINS", DEFAULT_CONFIG.excludeAdmins),
    moderateBots: readBoolean("MODERATE_BOTS", DEFAULT_CONFIG.moderateBots),
    timeoutMs: readTimeoutMinutes("TIMEOUT_MINUTES", DEFAULT_CONFIG.timeoutMs),
    antiRaidEnabled: readBoolean("ANTI_RAID_ENABLED", DEFAULT_CONFIG.antiRaidEnabled),
    antiRaidLevel: readChoice(
      "ANTI_RAID_LEVEL",
      Object.values(RAID_LEVELS),
      DEFAULT_CONFIG.antiRaidLevel,
    ),
    spamMessagesEnabled: readBoolean("SPAM_MESSAGES_ENABLED", DEFAULT_CONFIG.spamMessagesEnabled),
    blockedLinksEnabled: readBoolean("BLOCKED_LINKS_ENABLED", DEFAULT_CONFIG.blockedLinksEnabled),
    maliciousInvitesEnabled: readBoolean(
      "MALICIOUS_INVITES_ENABLED",
      DEFAULT_CONFIG.maliciousInvitesEnabled,
    ),
    nsfwInvitesEnabled: readBoolean("NSFW_INVITES_ENABLED", DEFAULT_CONFIG.nsfwInvitesEnabled),
    textScamEnabled: readBoolean("TEXT_SCAM_ENABLED", DEFAULT_CONFIG.textScamEnabled),
    imageScanSensitivity: readChoice(
      "IMAGE_SCAN_SENSITIVITY",
      Object.values(PARANOIA_LEVELS),
      DEFAULT_CONFIG.imageScanSensitivity,
    ),
    visualMatchThreshold: readNumber(
      "VISUAL_MATCH_THRESHOLD",
      DEFAULT_CONFIG.visualMatchThreshold,
      { integer: true, minExclusive: false, max: 64 },
    ),
    maxImageBytes: readNumber("MAX_IMAGE_SIZE_MB", 8) * 1024 * 1024,
    maxImagePixels: readNumber("MAX_IMAGE_PIXELS", DEFAULT_CONFIG.maxImagePixels, {
      integer: true,
    }),
    imageDownloadTimeoutMs: readNumber(
      "IMAGE_DOWNLOAD_TIMEOUT_MS",
      DEFAULT_CONFIG.imageDownloadTimeoutMs,
    ),
    spamReportEnabled: readBoolean("SPAM_REPORT_ENABLED", DEFAULT_CONFIG.spamReportEnabled),
    spamReportTimeoutMs: readTimeoutMinutes(
      "SPAM_REPORT_TIMEOUT_MINUTES",
      DEFAULT_CONFIG.spamReportTimeoutMs,
    ),
    spamReportLookbackMs: readNumber(
      "SPAM_REPORT_LOOKBACK_MINUTES",
      DEFAULT_CONFIG.spamReportLookbackMs / 60_000,
    ) * 60_000,
  };
}
