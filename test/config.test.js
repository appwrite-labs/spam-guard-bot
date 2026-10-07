import test from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_CONFIG, loadConfig } from "../src/config.js";

const REQUIRED_ENV = {
  DISCORD_TOKEN: "test-token",
  MODERATION_CHANNEL_ID: "123456789012345678",
};

function withEnv(values, run) {
  const previous = { ...process.env };

  for (const key of Object.keys(process.env)) {
    delete process.env[key];
  }
  Object.assign(process.env, values);

  try {
    return run();
  } finally {
    for (const key of Object.keys(process.env)) {
      delete process.env[key];
    }
    Object.assign(process.env, previous);
  }
}

test("requires DISCORD_TOKEN and MODERATION_CHANNEL_ID", () => {
  withEnv({ MODERATION_CHANNEL_ID: REQUIRED_ENV.MODERATION_CHANNEL_ID }, () => {
    assert.throws(() => loadConfig(), /DISCORD_TOKEN/);
  });
  withEnv({ DISCORD_TOKEN: REQUIRED_ENV.DISCORD_TOKEN }, () => {
    assert.throws(() => loadConfig(), /MODERATION_CHANNEL_ID/);
  });
  withEnv({ ...REQUIRED_ENV, MODERATION_CHANNEL_ID: "general" }, () => {
    assert.throws(() => loadConfig(), /MODERATION_CHANNEL_ID must be a Discord ID/);
  });
});

test("uses the documented defaults when only the required values are set", () => {
  withEnv(REQUIRED_ENV, () => {
    const config = loadConfig();

    assert.deepEqual(config, {
      ...DEFAULT_CONFIG,
      discordToken: "test-token",
      moderationChannelId: "123456789012345678",
      excludedRoleIds: [],
    });
    assert.equal(config.feedbackChannelId, null);
    assert.equal(config.antiRaidLevel, "medium");
    assert.equal(config.spamReportEnabled, false);
    assert.equal(config.timeoutMs, 24 * 60 * 60_000);
  });
});

test("parses every optional setting", () => {
  withEnv({
    ...REQUIRED_ENV,
    FEEDBACK_CHANNEL_ID: "223456789012345678",
    EXCLUDED_ROLE_IDS: "564164014339391498, 874574047910985750,564164014339391498",
    EXCLUDE_ADMINS: "false",
    MODERATE_BOTS: "TRUE",
    TIMEOUT_MINUTES: "60",
    ANTI_RAID_ENABLED: "false",
    ANTI_RAID_LEVEL: "High",
    SPAM_MESSAGES_ENABLED: "false",
    BLOCKED_LINKS_ENABLED: "false",
    MALICIOUS_INVITES_ENABLED: "false",
    NSFW_INVITES_ENABLED: "false",
    TEXT_SCAM_ENABLED: "false",
    IMAGE_SCAN_SENSITIVITY: "medium",
    VISUAL_MATCH_THRESHOLD: "0",
    MAX_IMAGE_SIZE_MB: "4",
    MAX_IMAGE_PIXELS: "1000000",
    IMAGE_DOWNLOAD_TIMEOUT_MS: "5000",
    SPAM_REPORT_ENABLED: "true",
    SPAM_REPORT_TIMEOUT_MINUTES: "5",
    SPAM_REPORT_LOOKBACK_MINUTES: "30",
  }, () => {
    const config = loadConfig();

    assert.equal(config.feedbackChannelId, "223456789012345678");
    assert.deepEqual(config.excludedRoleIds, ["564164014339391498", "874574047910985750"]);
    assert.equal(config.excludeAdmins, false);
    assert.equal(config.moderateBots, true);
    assert.equal(config.timeoutMs, 60 * 60_000);
    assert.equal(config.antiRaidEnabled, false);
    assert.equal(config.antiRaidLevel, "high");
    assert.equal(config.spamMessagesEnabled, false);
    assert.equal(config.blockedLinksEnabled, false);
    assert.equal(config.maliciousInvitesEnabled, false);
    assert.equal(config.nsfwInvitesEnabled, false);
    assert.equal(config.textScamEnabled, false);
    assert.equal(config.imageScanSensitivity, "medium");
    assert.equal(config.visualMatchThreshold, 0);
    assert.equal(config.maxImageBytes, 4 * 1024 * 1024);
    assert.equal(config.maxImagePixels, 1_000_000);
    assert.equal(config.imageDownloadTimeoutMs, 5000);
    assert.equal(config.spamReportEnabled, true);
    assert.equal(config.spamReportTimeoutMs, 5 * 60_000);
    assert.equal(config.spamReportLookbackMs, 30 * 60_000);
  });
});

test("rejects invalid values with the variable name in the error", () => {
  const cases = [
    ["FEEDBACK_CHANNEL_ID", "mod-log", /FEEDBACK_CHANNEL_ID must be a Discord ID/],
    ["EXCLUDED_ROLE_IDS", "564164014339391498,admins", /EXCLUDED_ROLE_IDS contains "admins"/],
    ["EXCLUDE_ADMINS", "yes", /EXCLUDE_ADMINS must be either true or false/],
    ["TIMEOUT_MINUTES", "40321", /TIMEOUT_MINUTES must be a number greater than 0 and at most 40320/],
    ["TIMEOUT_MINUTES", "0", /TIMEOUT_MINUTES must be a number greater than 0/],
    ["ANTI_RAID_LEVEL", "extreme", /ANTI_RAID_LEVEL must be one of: high, medium, low/],
    ["IMAGE_SCAN_SENSITIVITY", "paranoid", /IMAGE_SCAN_SENSITIVITY must be one of/],
    ["VISUAL_MATCH_THRESHOLD", "65", /VISUAL_MATCH_THRESHOLD must be a whole number at least 0 and at most 64/],
    ["SPAM_REPORT_LOOKBACK_MINUTES", "-5", /SPAM_REPORT_LOOKBACK_MINUTES must be a number greater than 0/],
  ];

  for (const [name, value, expected] of cases) {
    withEnv({ ...REQUIRED_ENV, [name]: value }, () => {
      assert.throws(() => loadConfig(), expected, `${name}=${value}`);
    });
  }
});
