import test from "node:test";
import assert from "node:assert/strict";
import { PermissionFlagsBits, PermissionsBitField } from "discord.js";
import { resolveAlertChannel } from "../src/alert-channels.js";

const ALERT_PERMISSIONS = [
  PermissionFlagsBits.ViewChannel,
  PermissionFlagsBits.SendMessages,
  PermissionFlagsBits.EmbedLinks,
];

function createClient({ thread = false, granted = ALERT_PERMISSIONS } = {}) {
  const channel = {
    name: "mod-alerts",
    guild: { members: { me: { id: "bot" } } },
    isTextBased: () => true,
    isSendable: () => true,
    isThread: () => thread,
    permissionsFor: () => new PermissionsBitField(granted),
  };
  return { channel, client: { channels: { fetch: async () => channel } } };
}

test("accepts a text channel where the bot can post alerts", async () => {
  const { client, channel } = createClient();

  assert.equal(await resolveAlertChannel(client, "MODERATION_CHANNEL_ID", "1"), channel);
});

test("requires Attach Files for channels that receive image copies", async () => {
  const { client } = createClient();

  await assert.rejects(
    resolveAlertChannel(client, "FEEDBACK_CHANNEL_ID", "1", { withFiles: true }),
    /FEEDBACK_CHANNEL_ID 1: the bot is missing Attach Files in #mod-alerts/,
  );

  const withFiles = createClient({ granted: [...ALERT_PERMISSIONS, PermissionFlagsBits.AttachFiles] });
  await resolveAlertChannel(withFiles.client, "FEEDBACK_CHANNEL_ID", "1", { withFiles: true });
});

test("requires Send Messages in Threads when the alert channel is a thread", async () => {
  const { client } = createClient({ thread: true });

  await assert.rejects(
    resolveAlertChannel(client, "MODERATION_CHANNEL_ID", "1"),
    /missing Send Messages In Threads/,
  );

  const threadReady = createClient({
    thread: true,
    granted: [
      PermissionFlagsBits.ViewChannel,
      PermissionFlagsBits.SendMessagesInThreads,
      PermissionFlagsBits.EmbedLinks,
    ],
  });
  await resolveAlertChannel(threadReady.client, "MODERATION_CHANNEL_ID", "1");
});

test("lists every missing permission", async () => {
  const { client } = createClient({ granted: [PermissionFlagsBits.ViewChannel] });

  await assert.rejects(
    resolveAlertChannel(client, "MODERATION_CHANNEL_ID", "1"),
    /missing Send Messages, Embed Links in #mod-alerts/,
  );
});
