import "dotenv/config";
import {
  ActivityType,
  Client,
  Events,
  GatewayIntentBits,
  MessageFlags,
} from "discord.js";
import { resolveAlertChannel } from "./alert-channels.js";
import { loadConfig } from "./config.js";
import { createMessageHandler } from "./moderation.js";
import { MALICIOUS_GUILD_IDS } from "./malicious-servers.js";
import { NSFW_SERVER_KEYWORDS } from "./nsfw-servers.js";
import { resolveLocale, t } from "./i18n.js";
import { OcrService } from "./ocr.js";
import {
  buildVisualReferenceMatcher,
  loadVisualReferenceManifest,
} from "./visual-matching.js";
import { handleDetectionFeedback } from "./detection-feedback.js";
import { handleSpamReportMessage } from "./spam-report.js";

const config = loadConfig();
const ocrService = new OcrService();

const visualReferenceHashes = await loadVisualReferenceManifest(
  config.visualReferenceManifestPath,
);
const visualMatcher = visualReferenceHashes.length > 0
  ? await buildVisualReferenceMatcher(
      visualReferenceHashes,
      config.visualMatchThreshold,
      { maxImagePixels: config.maxImagePixels },
    )
  : null;

if (visualReferenceHashes.length === 0) {
  console.warn(
    `[Visual matching] No reference hashes found at ${config.visualReferenceManifestPath}. ` +
      `Run "pnpm build:visual-references".`,
  );
} else {
  console.log(
    `[Visual matching] Loaded ${visualReferenceHashes.length} reference hash(es).`,
  );
}

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ],
});
const handleMessage = createMessageHandler({
  client,
  config,
  ocrService,
  visualMatcher,
  maliciousGuildIds: MALICIOUS_GUILD_IDS,
  nsfwServerKeywords: NSFW_SERVER_KEYWORDS,
});

// The bot only moderates the server that owns MODERATION_CHANNEL_ID, so
// alerts never mix content from another server. Set once the client is ready.
let moderatedGuildId = null;

client.once(Events.ClientReady, async (readyClient) => {
  console.log(`Bot connected as ${readyClient.user.tag}.`);
  readyClient.user.setPresence({
    activities: [{ name: "Protecting this server", type: ActivityType.Watching }],
    status: "online",
  });

  try {
    const moderationChannel = await resolveAlertChannel(
      readyClient,
      "MODERATION_CHANNEL_ID",
      config.moderationChannelId,
    );
    if (config.feedbackChannelId) {
      // Feedback and !spamreport copies attach the reported images.
      await resolveAlertChannel(readyClient, "FEEDBACK_CHANNEL_ID", config.feedbackChannelId, {
        withFiles: true,
      });
    }

    moderatedGuildId = moderationChannel.guild.id;
    console.log(
      `Moderating "${moderationChannel.guild.name}" (${moderatedGuildId}). ` +
        `Alerts go to #${moderationChannel.name}.`,
    );

    // A mistyped role ID means that role's members are moderated like anyone else.
    const roles = moderationChannel.guild.roles.cache;
    for (const roleId of config.excludedRoleIds) {
      if (roles.has(roleId)) {
        console.log(`[Startup] Excluded role: @${roles.get(roleId).name} (${roleId}).`);
      } else {
        console.warn(`[Startup] EXCLUDED_ROLE_IDS: role ${roleId} does not exist in this server.`);
      }
    }
  } catch (error) {
    console.error(`[Startup] ${error.message}`);
    await shutdown("startup check failure", 1);
  }
});

client.on(Events.MessageCreate, (message) => {
  if (!moderatedGuildId || message.guildId !== moderatedGuildId) return;

  void handleSpamReportMessage(message, config).catch((error) => console.error("[Spam report] Failed:", error));
  void handleMessage(message).catch((error) => {
    console.error(
      `[Moderation] Failed to process message ${message.id}:`,
      error,
    );
  });
});

client.on(Events.MessageUpdate, (_oldMessage, newMessage) => {
  if (!moderatedGuildId || newMessage.guildId !== moderatedGuildId) return;

  void handleMessage(newMessage).catch((error) => {
    console.error(
      `[Moderation] Failed to process updated message ${newMessage.id}:`,
      error,
    );
  });
});

client.on(Events.InteractionCreate, (interaction) => {
  if (!interaction.isButton() || !interaction.customId.startsWith("detection-feedback:")) return;

  void handleDetectionFeedback(interaction, config).catch((error) => {
    console.error("[Detection feedback] Failed to process feedback:", error);
    if (!interaction.replied && !interaction.deferred) {
      void interaction.reply({
        content: t(resolveLocale(interaction), "moderation", "feedbackFailed"),
        flags: MessageFlags.Ephemeral,
      }).catch(() => {});
    }
  });
});

client.on(Events.Error, (error) => {
  console.error("[Discord] Client error:", error);
});

async function shutdown(reason, exitCode = 0) {
  console.log(`Shutting down (${reason})...`);
  await client.destroy();
  await ocrService.terminate();
  process.exit(exitCode);
}

process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));

await client.login(config.discordToken);
