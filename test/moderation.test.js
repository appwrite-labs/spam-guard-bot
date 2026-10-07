import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import sharp from "sharp";
import { DEFAULT_CONFIG } from "../src/config.js";
import { createMessageHandler } from "../src/moderation.js";
import {
  buildVisualReferenceMatcher,
  loadVisualReferenceManifest,
  writeVisualReferenceManifest,
} from "../src/visual-matching.js";

function createHorizontalGradient(width, height, reversed = false) {
  const pixels = Buffer.alloc(width * height * 3);

  for (let row = 0; row < height; row += 1) {
    for (let column = 0; column < width; column += 1) {
      const value = reversed
        ? Math.round(255 * (1 - column / (width - 1)))
        : Math.round(255 * (column / (width - 1)));
      const offset = (row * width + column) * 3;
      pixels.fill(value, offset, offset + 3);
    }
  }

  return sharp(pixels, { raw: { width, height, channels: 3 } })
    .png()
    .toBuffer();
}

function createImageFetchResponse(buffer) {
  return {
    ok: true,
    status: 200,
    headers: {
      get(name) {
        return name.toLowerCase() === "content-length"
          ? String(buffer.length)
          : null;
      },
    },
    body: {
      getReader() {
        let done = false;
        return {
          async read() {
            if (done) {
              return { done: true, value: undefined };
            }

            done = true;
            return { done: false, value: buffer };
          },
          async cancel() {},
        };
      },
    },
  };
}

function testConfig(overrides = {}) {
  return { ...DEFAULT_CONFIG, moderationChannelId: "moderation-channel", ...overrides };
}

function createModerationClient(extra = {}) {
  const sent = [];
  const fetchedChannelIds = [];
  return {
    sent,
    fetchedChannelIds,
    channels: {
      fetch: async (channelId) => {
        fetchedChannelIds.push(channelId);
        return {
          isTextBased: () => true,
          isSendable: () => true,
          send: async (payload) => sent.push(payload),
        };
      },
    },
    ...extra,
  };
}

function imageUrl(name) {
  return `https://cdn.discordapp.com/attachments/${name}.png`;
}

for (const feedbackChannelId of [null, "123456789012345678"]) {
  test(`alerts the moderation channel only (feedback channel ${feedbackChannelId ? "set" : "unset"})`, async () => {
    const originalFetch = globalThis.fetch;
    const imageBuffer = await createHorizontalGradient(32, 32);
    globalThis.fetch = async () => createImageFetchResponse(imageBuffer);

    try {
      const channelMessages = [];
      let deleted = 0;
      const message = {
        id: "message-1",
        guildId: "guild-1",
        channelId: "channel-1",
        author: {
          id: "user-1",
          tag: "tester#0001",
          bot: false,
          displayAvatarURL: () => "https://example.com/avatar.png",
          toString: () => "<@user-1>",
        },
        channel: {
          isTextBased: () => true,
          isSendable: () => true,
          send: async (payload) => {
            channelMessages.push(payload);
          },
        },
        guild: {
          preferredLocale: "en-US",
          ownerId: "owner-1",
        },
        attachments: new Map([
          [
            "attachment-1",
            {
              id: "attachment-1",
              name: "proof.png",
              contentType: "image/png",
              size: imageBuffer.length,
              url: imageUrl("proof"),
            },
          ],
        ]),
        embeds: [],
        messageSnapshots: new Map(),
        member: {
          moderatable: true,
          permissions: {
            has: () => false,
          },
          timeout: async () => {},
        },
        delete: async () => {
          deleted += 1;
        },
        webhookId: null,
        inGuild: () => true,
      };
      const client = createModerationClient();

      const handleMessage = createMessageHandler({
        client,
        config: testConfig({
          maxImageBytes: 1024,
          imageDownloadTimeoutMs: 1000,
          timeoutMs: 60_000,
          feedbackChannelId,
        }),
        ocrService: {
          recognize: async () => "Withdrawal\nSucceeded",
        },
      });

      await handleMessage(message);

      assert.equal(deleted, 1);
      assert.equal(channelMessages.length, 0);
      assert.deepEqual(client.fetchedChannelIds, ["moderation-channel"]);
      assert.equal(client.sent.length, 1);
      assert.match(client.sent[0].content, /^Moderation alert: tester/);
      assert.deepEqual(client.sent[0].allowedMentions, { parse: [] });
      assert.equal(Boolean(client.sent[0].components), Boolean(feedbackChannelId));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
}

test("checks malicious image domains with the low paranoia OCR pass", async () => {
  const originalFetch = globalThis.fetch;
  const imageBuffer = await createHorizontalGradient(32, 32);
  globalThis.fetch = async () => createImageFetchResponse(imageBuffer);

  try {
    let deleted = 0;
    let ocrOptions;
    const message = {
      id: "low-paranoia-domain",
      guildId: "guild-1",
      channelId: "channel-1",
      content: "",
      author: {
        id: "user-low-paranoia",
        tag: "tester#0001",
        bot: false,
        displayAvatarURL: () => "https://example.com/avatar.png",
        toString: () => "<@user-low-paranoia>",
      },
      channel: {
        isTextBased: () => true,
        isSendable: () => true,
        send: async () => {},
      },
      guild: {
        preferredLocale: "en-US",
        ownerId: "owner-1",
      },
      attachments: new Map([
        [
          "attachment-1",
          {
            id: "attachment-1",
            name: "domain.png",
            contentType: "image/png",
            size: imageBuffer.length,
            url: imageUrl("domain"),
          },
        ],
      ]),
      embeds: [],
      messageSnapshots: new Map(),
      member: {
        moderatable: true,
        permissions: { has: () => false },
        timeout: async () => {},
      },
      delete: async () => {
        deleted += 1;
      },
      webhookId: null,
      inGuild: () => true,
    };

    const handleMessage = createMessageHandler({
      client: {},
      config: testConfig({
        maxImageBytes: 1024,
        maxImagePixels: 16_000_000,
        imageDownloadTimeoutMs: 1000,
        timeoutMs: 60_000,
        imageScanSensitivity: "low",
      }),
      ocrService: {
        recognize: async (_image, options) => {
          ocrOptions = options;
          return "Visit wenowin.com";
        },
      },
    });

    await handleMessage(message);

    assert.equal(ocrOptions.effort, "low");
    assert.equal(deleted, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("blocks a listed spam message without requiring an image", async () => {
  const channelMessages = [];
  let deleted = 0;
  let timeoutCalls = 0;
  const message = {
    id: "spam-message-1",
    guildId: "guild-1",
    channelId: "channel-1",
    content: "FREE CRYPTO GIVEAWAY!  Send crypto to receive double back.",
    author: {
      id: "user-spammer",
      tag: "spammer#0001",
      bot: false,
      displayAvatarURL: () => "https://example.com/avatar.png",
      toString: () => "<@user-spammer>",
    },
    channel: {
      isTextBased: () => true,
      isSendable: () => true,
      send: async (payload) => channelMessages.push(payload),
    },
    guild: { preferredLocale: "en-US", ownerId: "owner-1" },
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map(),
    member: {
      moderatable: true,
      bannable: false,
      permissions: { has: () => false },
      timeout: async () => { timeoutCalls += 1; },
    },
    delete: async () => { deleted += 1; },
    webhookId: null,
    inGuild: () => true,
  };

  const client = createModerationClient();
  const handleMessage = createMessageHandler({
    client,
    config: testConfig({ timeoutMs: 60_000, spamMessagesEnabled: true }),
    ocrService: { recognize: async () => "" },
  });

  await handleMessage(message);

  assert.equal(deleted, 1);
  assert.equal(timeoutCalls, 1);
  assert.equal(channelMessages.length, 0);
  assert.equal(client.sent.length, 1);
  assert.match(client.sent[0].content, /^Spam alert: spammer/);
});

test("ignores bot messages by default and detects them when MODERATE_BOTS is on", async () => {
  let deleted = 0;
  let timeoutCalls = 0;
  const channelMessages = [];
  const message = {
    id: "bot-spam-message",
    guildId: "guild-1",
    channelId: "channel-1",
    content: "FREE CRYPTO GIVEAWAY! Send crypto to receive double back.",
    author: {
      id: "spam-bot",
      tag: "spam-bot#0001",
      bot: true,
      displayAvatarURL: () => "https://example.com/avatar.png",
      toString: () => "<@spam-bot>",
    },
    channel: {
      isTextBased: () => true,
      isSendable: () => true,
      send: async (payload) => channelMessages.push(payload),
    },
    guild: { preferredLocale: "en-US", ownerId: "owner-1" },
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map(),
    member: {
      moderatable: true,
      permissions: { has: () => false },
      timeout: async () => { timeoutCalls += 1; },
    },
    delete: async () => { deleted += 1; },
    webhookId: null,
    inGuild: () => true,
  };
  const client = createModerationClient();
  const config = testConfig({ timeoutMs: 60_000 });
  const handleMessage = createMessageHandler({
    client,
    config,
    ocrService: { recognize: async () => "" },
  });

  await handleMessage(message);
  assert.equal(deleted, 0);
  assert.equal(timeoutCalls, 0);

  config.moderateBots = true;
  await handleMessage(message);

  assert.equal(deleted, 1);
  assert.equal(timeoutCalls, 1);
  assert.equal(channelMessages.length, 0);
  assert.equal(client.sent.length, 1);
});

test("times out before deleting spam and removes its single-message thread", async () => {
  const events = [];
  let threadDeleted = 0;
  const user = {
    id: "thread-spammer",
    tag: "thread-spammer#0001",
    bot: false,
    displayAvatarURL: () => "https://example.com/avatar.png",
    toString: () => "<@thread-spammer>",
  };
  const thread = {
    id: "thread-1",
    ownerId: user.id,
    isThread: () => true,
    isTextBased: () => true,
    isSendable: () => true,
    messages: {
      fetch: async () => new Map([["thread-spam-message", message]]),
    },
    delete: async () => {
      events.push("thread-delete");
      threadDeleted += 1;
    },
    send: async () => {},
  };
  const message = {
    id: "thread-spam-message",
    guildId: "guild-1",
    channelId: thread.id,
    content: "FREE CRYPTO GIVEAWAY!  Send crypto to receive double back.",
    author: user,
    channel: thread,
    guild: { preferredLocale: "en-US", ownerId: "owner-1" },
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map(),
    member: {
      moderatable: true,
      permissions: { has: () => false },
      timeout: async () => events.push("timeout"),
    },
    delete: async () => events.push("message-delete"),
    webhookId: null,
    inGuild: () => true,
  };

  const handleMessage = createMessageHandler({
    client: {},
    config: testConfig({ timeoutMs: 60_000, spamMessagesEnabled: true }),
    ocrService: { recognize: async () => "" },
  });

  await handleMessage(message);

  assert.deepEqual(events, ["timeout", "message-delete", "thread-delete"]);
  assert.equal(threadDeleted, 1);
});

test("detects a malicious forwarded image and moderates the outer message", async () => {
  const originalFetch = globalThis.fetch;
  const imageBuffer = await createHorizontalGradient(32, 32);
  globalThis.fetch = async () => {
    throw new Error("A prohibited source channel must not download the image.");
  };
  let deleted = 0;
  let timeoutCalls = 0;
  let ocrCalls = 0;
  const user = {
    id: "forwarding-user",
    tag: "forwarding-user#0001",
    bot: false,
    displayAvatarURL: () => "https://example.com/avatar.png",
    toString: () => "<@forwarding-user>",
  };
  const forwardedMessage = {
    attachments: new Map([
      ["forwarded-image", {
        id: "forwarded-image",
        name: "scam.png",
        contentType: "image/png",
        size: 100,
        url: "https://cdn.discordapp.com/attachments/111111111111111111/1540534318554677288/scam.png",
      }],
    ]),
    embeds: [],
    messageSnapshots: new Map(),
  };
  const message = {
    id: "forwarded-message",
    guildId: "guild-1",
    channelId: "channel-1",
    content: "",
    author: user,
    channel: {
      isTextBased: () => true,
      isSendable: () => true,
      send: async () => {},
    },
    guild: { preferredLocale: "en-US", ownerId: "owner-1" },
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map([["snapshot", forwardedMessage]]),
    member: {
      moderatable: true,
      permissions: { has: () => false },
      timeout: async () => { timeoutCalls += 1; },
    },
    delete: async () => { deleted += 1; },
    webhookId: null,
    inGuild: () => true,
  };

  try {
    const handleMessage = createMessageHandler({
      client: {},
      config: testConfig({ timeoutMs: 60_000, antiRaidEnabled: false, spamMessagesEnabled: false }),
      ocrService: {
        recognize: async () => {
          ocrCalls += 1;
          return "";
        },
      },
      visualMatcher: {
        match: async () => {
          throw new Error("A prohibited source channel must skip visual matching.");
        },
      },
      scamImageChannels: [{ channelId: "111111111111111111", name: "Test scam channel" }],
    });

    await handleMessage(message);

    assert.equal(ocrCalls, 0);
    assert.equal(deleted, 1);
    assert.equal(timeoutCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("deletes a forwarded image hash match without running OCR", async () => {
  const originalFetch = globalThis.fetch;
  const imageBuffer = await createHorizontalGradient(32, 32);
  globalThis.fetch = async () => createImageFetchResponse(imageBuffer);
  const sourceDirectory = await mkdtemp(join(tmpdir(), "forwarded-visual-"));
  await sharp(imageBuffer).toFile(join(sourceDirectory, "scam.png"));
  const manifest = await writeVisualReferenceManifest(
    sourceDirectory,
    join(sourceDirectory, "manifest.json"),
  );
  const visualMatcher = await buildVisualReferenceMatcher(manifest.references, 0);
  let deleted = 0;
  let timeoutCalls = 0;
  let ocrCalls = 0;
  const user = {
    id: "forwarded-visual-user",
    tag: "forwarded-visual-user#0001",
    bot: false,
    displayAvatarURL: () => "https://example.com/avatar.png",
    toString: () => "<@forwarded-visual-user>",
  };
  const message = {
    id: "forwarded-visual-message",
    guildId: "guild-1",
    channelId: "channel-1",
    content: "",
    author: user,
    channel: {
      isTextBased: () => true,
      isSendable: () => true,
      send: async () => {},
    },
    guild: { preferredLocale: "en-US", ownerId: "owner-1" },
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map([[
      "snapshot",
      {
        content: "forwarded scam image",
        attachments: new Map([[
          "forwarded-image",
          {
            id: "forwarded-image",
            name: "scam.png",
            contentType: "image/png",
            size: imageBuffer.length,
            url: "https://cdn.discordapp.com/attachments/123456789012345678/1540534318554677288/scam.png",
          },
        ]]),
        embeds: [],
        messageSnapshots: new Map(),
      },
    ]]),
    member: {
      moderatable: true,
      permissions: { has: () => false },
      timeout: async () => { timeoutCalls += 1; },
    },
    delete: async () => { deleted += 1; },
    webhookId: null,
    inGuild: () => true,
  };

  try {
    const handleMessage = createMessageHandler({
      client: {},
      config: testConfig({
        maxImageBytes: 1024,
        maxImagePixels: 16_000_000,
        imageDownloadTimeoutMs: 1000,
        timeoutMs: 60_000,
        antiRaidEnabled: false,
        spamMessagesEnabled: false,
      }),
      visualMatcher,
      ocrService: {
        recognize: async () => {
          ocrCalls += 1;
          return "";
        },
      },
    });

    await handleMessage(message);

    assert.equal(ocrCalls, 0);
    assert.equal(deleted, 1);
    assert.equal(timeoutCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("detects a malicious image sent in a recently created author-owned thread and deletes the thread", async () => {
  const events = [];
  const now = Date.now();
  const user = {
    id: "thread-image-user",
    tag: "thread-image-user#0001",
    bot: false,
    displayAvatarURL: () => "https://example.com/avatar.png",
    toString: () => "<@thread-image-user>",
  };
  const thread = {
    id: "thread-image-1",
    ownerId: user.id,
    createdTimestamp: now - 1_000,
    isThread: () => true,
    isTextBased: () => true,
    isSendable: () => true,
    messages: {
      fetch: async () => new Map([
        ["earlier-message", {}],
        ["thread-image-message", message],
      ]),
    },
    delete: async () => events.push("thread-delete"),
    send: async () => {},
  };
  const message = {
    id: "thread-image-message",
    guildId: "guild-1",
    channelId: thread.id,
    createdTimestamp: now,
    content: "",
    author: user,
    channel: thread,
    guild: { preferredLocale: "en-US", ownerId: "owner-1" },
    attachments: new Map([
      ["scam-image", {
        id: "scam-image",
        name: "scam.png",
        contentType: "image/png",
        size: 100,
        url: "https://cdn.discordapp.com/attachments/111111111111111111/1540534318554677288/scam.png",
      }],
    ]),
    embeds: [],
    messageSnapshots: new Map(),
    member: {
      moderatable: true,
      permissions: { has: () => false },
      timeout: async () => events.push("timeout"),
    },
    delete: async () => events.push("message-delete"),
    webhookId: null,
    inGuild: () => true,
  };

  const handleMessage = createMessageHandler({
    client: {},
    config: testConfig({ timeoutMs: 60_000, antiRaidEnabled: false, spamMessagesEnabled: false }),
    ocrService: { recognize: async () => "" },
    scamImageChannels: [{ channelId: "111111111111111111", name: "Test scam channel" }],
  });

  await handleMessage(message);

  assert.deepEqual(events, ["timeout", "message-delete", "thread-delete"]);
});

test("anti-raid deletes a message starter and the thread it created", async () => {
  const deletedMessages = [];
  const deletedThreads = [];
  const channelMessages = [];
  const user = {
    id: "raid-user",
    tag: "raid-user#0001",
    bot: false,
    displayAvatarURL: () => "https://example.com/avatar.png",
    toString: () => "<@raid-user>",
  };
  const member = {
    moderatable: true,
    permissions: { has: () => false },
    timeout: async () => {},
  };

  const startedThread = {
    id: "started-thread",
    ownerId: user.id,
    isThread: () => true,
    delete: async () => deletedThreads.push("started-thread"),
  };

  function raidMessage(id, channelId, thread = undefined) {
    const channel = {
      isThread: () => false,
      isTextBased: () => true,
      isSendable: () => true,
      send: async (payload) => channelMessages.push(payload),
    };
    return {
      id,
      guildId: "guild-raid",
      channelId,
      content: "discord.gg/example repeated raid message",
      author: user,
      channel,
      ...(thread ? { thread, hasThread: true } : {}),
      guild: { preferredLocale: "en-US", ownerId: "owner-1" },
      attachments: new Map(),
      embeds: [],
      messageSnapshots: new Map(),
      member,
      delete: async () => deletedMessages.push(id),
      webhookId: null,
      inGuild: () => true,
    };
  }

  const messages = [
    raidMessage("raid-message-1", "raid-channel-1", startedThread),
    raidMessage("raid-message-2", "raid-channel-2"),
    raidMessage("raid-message-3", "raid-channel-3"),
  ];

  const client = createModerationClient();
  const handleMessage = createMessageHandler({
    client,
    config: testConfig({ timeoutMs: 60_000, antiRaidLevel: "high", spamMessagesEnabled: false }),
    ocrService: { recognize: async () => "" },
  });

  for (const message of messages) {
    await handleMessage(message);
  }

  assert.deepEqual(deletedMessages.sort(), [
    "raid-message-1",
    "raid-message-2",
    "raid-message-3",
  ]);
  assert.deepEqual(deletedThreads, ["started-thread"]);
  assert.equal(channelMessages.length, 0);
  assert.equal(client.sent.length, 1);
  const timeoutField = client.sent[0].embeds[0].data.fields.find((field) => field.name.startsWith("Timeout"));
  assert.equal(timeoutField.value, "Yes");
});

test("deletes malicious server invites, times out the author, and alerts moderators", async () => {
  const moderationMessages = [];
  let deleted = 0;
  let threadDeleted = 0;
  let timeoutCalls = 0;
  const moderationChannel = {
    isTextBased: () => true,
    isSendable: () => true,
    send: async (payload) => moderationMessages.push(payload),
  };
  const message = {
    id: "malicious-invite-message",
    guildId: "guild-1",
    channelId: "channel-1",
    content: "Please read the details in this thread.",
    author: {
      id: "user-spammer",
      tag: "spammer#0001",
      bot: false,
      displayAvatarURL: () => "https://example.com/avatar.png",
      toString: () => "<@user-spammer>",
    },
    channel: {
      name: "discord.gg/malicious",
      ownerId: "user-spammer",
      isThread: () => true,
      messages: {
        fetch: async () => new Map([[message.id, message]]),
      },
      delete: async () => { threadDeleted += 1; },
      isTextBased: () => true,
      isSendable: () => true,
      send: async () => {},
      toString: () => "<#channel-1>",
    },
    guild: { preferredLocale: "es-ES", ownerId: "owner-1" },
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map(),
    member: {
      moderatable: true,
      permissions: { has: () => false },
      timeout: async () => { timeoutCalls += 1; },
    },
    delete: async () => { deleted += 1; },
    webhookId: null,
    inGuild: () => true,
  };

  const handleMessage = createMessageHandler({
    client: {
      fetchInvite: async () => ({ guild: { id: "123456789012345678" } }),
      channels: { fetch: async () => moderationChannel },
    },
    config: testConfig({ timeoutMs: 60_000 }),
    ocrService: { recognize: async () => "" },
    maliciousGuildIds: ["123456789012345678"],
  });

  await handleMessage(message);

  assert.equal(deleted, 1);
  assert.equal(threadDeleted, 1);
  assert.equal(timeoutCalls, 1);
  assert.equal(moderationMessages.length, 1);
  assert.match(moderationMessages[0].content, /servidor malicioso/i);
  assert.match(moderationMessages[0].embeds[0].data.fields[2].value, /123456789012345678/);
  assert.equal(moderationMessages[0].embeds[0].data.fields[4].value, "Sí");
  assert.equal(moderationMessages[0].embeds[0].data.fields[5].value, "Sí");
});

test("does not moderate malicious server invites when protection is disabled", async () => {
  let deleted = 0;
  let timeoutCalls = 0;
  const message = {
    id: "malicious-invite-disabled",
    guildId: "guild-1",
    channelId: "channel-1",
    content: "https://discord.gg/malicious",
    author: {
      id: "user-spammer",
      tag: "spammer#0001",
      bot: false,
      displayAvatarURL: () => "https://example.com/avatar.png",
      toString: () => "<@user-spammer>",
    },
    channel: {
      isTextBased: () => true,
      isSendable: () => true,
      send: async () => {},
    },
    guild: { preferredLocale: "en-US", ownerId: "owner-1" },
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map(),
    member: {
      moderatable: true,
      permissions: { has: () => false },
      timeout: async () => { timeoutCalls += 1; },
    },
    delete: async () => { deleted += 1; },
    webhookId: null,
    inGuild: () => true,
  };

  const handleMessage = createMessageHandler({
    client: { fetchInvite: async () => ({ guild: { id: "123456789012345678" } }) },
    config: testConfig({ timeoutMs: 60_000, maliciousInvitesEnabled: false }),
    ocrService: { recognize: async () => "" },
    maliciousGuildIds: ["123456789012345678"],
  });

  await handleMessage(message);

  assert.equal(deleted, 0);
  assert.equal(timeoutCalls, 0);
});

test("resolves malicious Discord invites found inside image OCR", async () => {
  const originalFetch = globalThis.fetch;
  const imageBuffer = await createHorizontalGradient(32, 32);
  globalThis.fetch = async () => createImageFetchResponse(imageBuffer);

  try {
    const moderationMessages = [];
    let deleted = 0;
    let timeoutCalls = 0;
    let ocrCalls = 0;
    let resolvedCode = null;
    const message = {
      id: "malicious-image-invite-message",
      guildId: "guild-1",
      channelId: "channel-1",
      content: "",
      author: {
        id: "image-spammer",
        tag: "image-spammer#0001",
        bot: false,
        displayAvatarURL: () => "https://example.com/avatar.png",
        toString: () => "<@image-spammer>",
      },
      channel: {
        isTextBased: () => true,
        isSendable: () => true,
        send: async () => {},
        toString: () => "<#channel-1>",
      },
      guild: { preferredLocale: "en-US", ownerId: "owner-1" },
      attachments: new Map([
        ["invite-image", {
          id: "invite-image",
          name: "invite.png",
          contentType: "image/png",
          size: imageBuffer.length,
          url: imageUrl("invite"),
        }],
      ]),
      embeds: [],
      messageSnapshots: new Map(),
      member: {
        moderatable: true,
        permissions: { has: () => false },
        timeout: async () => { timeoutCalls += 1; },
      },
      delete: async () => { deleted += 1; },
      webhookId: null,
      inGuild: () => true,
    };

    const handleMessage = createMessageHandler({
      client: {
        fetchInvite: async (code) => {
          if (code === "PIPER") {
            throw new Error("Invite codes are lower-case in this test.");
          }
          resolvedCode = code;
          return { guild: { id: "123456789012345678" } };
        },
        channels: {
          fetch: async () => ({
            isTextBased: () => true,
            isSendable: () => true,
            send: async (payload) => moderationMessages.push(payload),
          }),
        },
      },
      config: testConfig({
        maxImageBytes: 4096,
        maxImagePixels: 16_000_000,
        imageDownloadTimeoutMs: 1000,
        timeoutMs: 60_000,
      }),
      ocrService: {
        recognize: async () => {
          ocrCalls += 1;
          return "JOIN DISCORD.GG/PIPER FOR MORE";
        },
      },
      maliciousGuildIds: ["123456789012345678"],
    });

    await handleMessage(message);

    assert.equal(resolvedCode, "piper");
    assert.equal(ocrCalls, 1);
    assert.equal(deleted, 1);
    assert.equal(timeoutCalls, 1);
    assert.equal(moderationMessages.length, 1);
    assert.equal(moderationMessages[0].embeds[0].data.title, "Malicious server invite blocked");
    assert.match(moderationMessages[0].embeds[0].data.fields[2].value, /123456789012345678/);
    assert.match(moderationMessages[0].embeds[0].data.fields[7].value, /DISCORD\.GG\/PIPER/);
    assert.equal(
      moderationMessages[0].embeds[0].data.fields.find((field) => field.name === "Detection method").value,
      "OCR + Malicious servers",
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("applies blocked-link, NSFW-invite, and malicious-invite filters to image OCR", async () => {
  const originalFetch = globalThis.fetch;
  const imageBuffer = await createHorizontalGradient(32, 32);
  globalThis.fetch = async () => createImageFetchResponse(imageBuffer);

  try {
    const cases = [
      {
        id: "blocked-image-link",
        ocrText: "Visit https://zangi.com now",
        title: "Spam message blocked",
        fetchInvite: async () => {
          throw new Error("A blocked domain must not resolve an invite.");
        },
      },
      {
        id: "nsfw-image-invite",
        ocrText: "JOIN DISCORD.GG/nsfw-image",
        title: "NSFW server invite blocked",
        fetchInvite: async () => ({
          guild: { id: "987654321098765432", name: "NSFW Lounge" },
        }),
      },
      {
        id: "malicious-image-invite",
        ocrText: "JOIN DISCORD.GG/malicious-image",
        title: "Malicious server invite blocked",
        fetchInvite: async () => ({
          guild: { id: "123456789012345678", name: "Malicious server" },
        }),
      },
    ];

    for (const testCase of cases) {
      const moderationMessages = [];
      let deleted = 0;
      let timeoutCalls = 0;
      const message = {
        id: testCase.id,
        guildId: "guild-1",
        channelId: "channel-1",
        content: "",
        author: {
          id: `${testCase.id}-user`,
          tag: `${testCase.id}#0001`,
          bot: false,
          displayAvatarURL: () => "https://example.com/avatar.png",
          toString: () => `<@${testCase.id}-user>`,
        },
        channel: {
          isTextBased: () => true,
          isSendable: () => true,
          send: async () => {},
          toString: () => "<#channel-1>",
        },
        guild: { preferredLocale: "en-US", ownerId: "owner-1" },
        attachments: new Map([
          ["image", {
            id: "image",
            name: `${testCase.id}.png`,
            contentType: "image/png",
            size: imageBuffer.length,
            url: imageUrl(testCase.id),
          }],
        ]),
        embeds: [],
        messageSnapshots: new Map(),
        member: {
          moderatable: true,
          permissions: { has: () => false },
          timeout: async () => { timeoutCalls += 1; },
        },
        delete: async () => { deleted += 1; },
        webhookId: null,
        inGuild: () => true,
      };

      const handleMessage = createMessageHandler({
        client: {
          fetchInvite: testCase.fetchInvite,
          channels: {
            fetch: async () => ({
              isTextBased: () => true,
              isSendable: () => true,
              send: async (payload) => moderationMessages.push(payload),
            }),
          },
        },
        config: testConfig({
          maxImageBytes: 4096,
          maxImagePixels: 16_000_000,
          imageDownloadTimeoutMs: 1000,
          timeoutMs: 60_000,
          antiRaidEnabled: false,
          spamMessagesEnabled: false,
        }),
        ocrService: {
          singlePass: true,
          recognize: async () => testCase.ocrText,
        },
        maliciousGuildIds: ["123456789012345678"],
        nsfwServerKeywords: ["nsfw"],
      });

      await handleMessage(message);

      assert.equal(deleted, 1, testCase.id);
      assert.equal(timeoutCalls, 1, testCase.id);
      assert.equal(moderationMessages.length, 1, testCase.id);
      assert.equal(moderationMessages[0].embeds[0].data.title, testCase.title);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("blocks invites to servers with NSFW names and alerts moderators", async () => {
  const moderationMessages = [];
  let deleted = 0;
  let timeoutCalls = 0;
  const message = {
    id: "nsfw-invite-message",
    guildId: "guild-1",
    channelId: "channel-1",
    content: "Join: **mailto:/#@discord.gg/nsfw-server**",
    author: {
      id: "user-nsfw",
      tag: "user#0001",
      bot: false,
      displayAvatarURL: () => "https://example.com/avatar.png",
      toString: () => "<@user-nsfw>",
    },
    channel: {
      isTextBased: () => true,
      isSendable: () => true,
      send: async () => {},
      toString: () => "<#channel-1>",
    },
    guild: { preferredLocale: "en-US", ownerId: "owner-1" },
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map(),
    member: {
      moderatable: true,
      permissions: { has: () => false },
      timeout: async () => { timeoutCalls += 1; },
    },
    delete: async () => { deleted += 1; },
    webhookId: null,
    inGuild: () => true,
  };

  const handleMessage = createMessageHandler({
    client: {
      fetchInvite: async () => ({
        guild: { id: "123456789012345678", name: "Official NSFW +18" },
      }),
      channels: {
        fetch: async () => ({
          isTextBased: () => true,
          isSendable: () => true,
          send: async (payload) => moderationMessages.push(payload),
        }),
      },
    },
    config: testConfig({ timeoutMs: 60_000 }),
    ocrService: { recognize: async () => "" },
  });

  await handleMessage(message);

  assert.equal(deleted, 1);
  assert.equal(timeoutCalls, 1);
  assert.equal(moderationMessages.length, 1);
  assert.equal(moderationMessages[0].embeds[0].data.title, "NSFW server invite blocked");
  assert.match(moderationMessages[0].embeds[0].data.fields[2].value, /Official NSFW \+18/);
  assert.deepEqual(
    moderationMessages[0].embeds[0].data.fields.find((field) => field.name === "Matched detection"),
    { name: "Matched detection", value: "Keyword: nsfw", inline: true },
  );
});

test("ignores listed spam messages from members with excluded roles", async () => {
  let deleted = 0;
  let timeoutCalls = 0;
  const channelMessages = [];
  const message = {
    id: "spam-message-excluded-role",
    guildId: "guild-1",
    channelId: "channel-1",
    content: "FREE CRYPTO GIVEAWAY! Send crypto to receive double back.",
    author: {
      id: "user-role",
      tag: "role#0001",
      bot: false,
      displayAvatarURL: () => "https://example.com/avatar.png",
      toString: () => "<@user-role>",
    },
    channel: {
      isTextBased: () => true,
      isSendable: () => true,
      send: async (payload) => channelMessages.push(payload),
    },
    guild: { preferredLocale: "en-US", ownerId: "owner-1" },
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map(),
    member: {
      moderatable: true,
      permissions: { has: () => false },
      roles: { cache: new Map([["role-1", { id: "role-1" }]]) },
      timeout: async () => { timeoutCalls += 1; },
    },
    delete: async () => { deleted += 1; },
    webhookId: null,
    inGuild: () => true,
  };

  const handleMessage = createMessageHandler({
    client: {},
    config: testConfig({
      timeoutMs: 60_000,
      excludedRoleIds: ["role-1"],
      spamMessagesEnabled: true,
    }),
    ocrService: { recognize: async () => "" },
  });

  await handleMessage(message);

  assert.equal(deleted, 0);
  assert.equal(timeoutCalls, 0);
  assert.equal(channelMessages.length, 0);
});

test("ignores listed spam messages from administrators when configured", async () => {
  let deleted = 0;
  let timeoutCalls = 0;
  const channelMessages = [];
  const message = {
    id: "spam-message-admin",
    guildId: "guild-1",
    channelId: "channel-1",
    content: "FREE CRYPTO GIVEAWAY! Send crypto to receive double back.",
    author: {
      id: "user-admin",
      tag: "admin#0001",
      bot: false,
      displayAvatarURL: () => "https://example.com/avatar.png",
      toString: () => "<@user-admin>",
    },
    channel: {
      isTextBased: () => true,
      isSendable: () => true,
      send: async (payload) => channelMessages.push(payload),
    },
    guild: { preferredLocale: "en-US", ownerId: "owner-1" },
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map(),
    member: {
      moderatable: true,
      permissions: { has: () => true },
      timeout: async () => { timeoutCalls += 1; },
    },
    delete: async () => { deleted += 1; },
    webhookId: null,
    inGuild: () => true,
  };

  const handleMessage = createMessageHandler({
    client: {},
    config: testConfig({ timeoutMs: 60_000, spamMessagesEnabled: true }),
    ocrService: { recognize: async () => "" },
  });

  await handleMessage(message);

  assert.equal(deleted, 0);
  assert.equal(timeoutCalls, 0);
  assert.equal(channelMessages.length, 0);
});

test("respects spam protection and moderation settings", async () => {
  let deleted = 0;
  let timeoutValue = null;
  const sourceChannelMessages = [];
  const moderationChannelMessages = [];
  const message = {
    id: "spam-message-settings",
    guildId: "guild-1",
    channelId: "channel-1",
    content: "FREE CRYPTO GIVEAWAY! Send crypto to receive double back.",
    author: {
      id: "user-spammer",
      tag: "spammer#0001",
      bot: false,
      displayAvatarURL: () => "https://example.com/avatar.png",
      toString: () => "<@user-spammer>",
    },
    channel: {
      isTextBased: () => true,
      isSendable: () => true,
      send: async (payload) => sourceChannelMessages.push(payload),
    },
    guild: { preferredLocale: "en-US", ownerId: "owner-1" },
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map(),
    member: {
      moderatable: true,
      permissions: { has: () => false },
      timeout: async (value) => { timeoutValue = value; },
    },
    delete: async () => { deleted += 1; },
    webhookId: null,
    inGuild: () => true,
  };
  const moderationChannel = {
    isTextBased: () => true,
    isSendable: () => true,
    send: async (payload) => moderationChannelMessages.push(payload),
  };

  const handleMessage = createMessageHandler({
    client: { channels: { fetch: async () => moderationChannel } },
    config: testConfig({
      timeoutMs: 60_000,
      excludeAdmins: false,
      timeoutMs: 15 * 60_000,
      spamMessagesEnabled: true,
    }),
    ocrService: { recognize: async () => "" },
  });

  await handleMessage(message);

  assert.equal(deleted, 1);
  assert.equal(timeoutValue, 15 * 60_000);
  assert.equal(sourceChannelMessages.length, 0);
  assert.equal(moderationChannelMessages.length, 1);
});

test("does not moderate listed spam messages when spam protection is disabled", async () => {
  let deleted = 0;
  let timeoutCalls = 0;
  const message = {
    id: "spam-message-disabled",
    guildId: "guild-1",
    channelId: "channel-1",
    content: "FREE CRYPTO GIVEAWAY! Send crypto to receive double back.",
    author: {
      id: "user-spammer",
      tag: "spammer#0001",
      bot: false,
      displayAvatarURL: () => "https://example.com/avatar.png",
      toString: () => "<@user-spammer>",
    },
    channel: {
      isTextBased: () => true,
      isSendable: () => true,
      send: async () => {},
    },
    guild: { preferredLocale: "en-US", ownerId: "owner-1" },
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map(),
    member: {
      moderatable: true,
      permissions: { has: () => false },
      timeout: async () => { timeoutCalls += 1; },
    },
    delete: async () => { deleted += 1; },
    webhookId: null,
    inGuild: () => true,
  };

  const handleMessage = createMessageHandler({
    client: {},
    config: testConfig({ timeoutMs: 60_000, spamMessagesEnabled: false }),
    ocrService: { recognize: async () => "" },
  });

  await handleMessage(message);

  assert.equal(deleted, 0);
  assert.equal(timeoutCalls, 0);
});

test("deletes the whole message when only one image matches", async () => {
  const originalFetch = globalThis.fetch;

  const tempDirectory = await mkdtemp(join(tmpdir(), "visual-single-match-"));
  const referencePath = join(tempDirectory, "reference-gradient.png");
  const matchingBuffer = await createHorizontalGradient(32, 32);
  const safeBuffer = await createHorizontalGradient(32, 32, true);
  await sharp(matchingBuffer).toFile(referencePath);

  globalThis.fetch = async (url) => {
    const buffer = url.includes("matching") ? matchingBuffer : safeBuffer;

    return createImageFetchResponse(buffer);
  };

  try {
    const manifestPath = join(tempDirectory, "manifest.json");
    await writeVisualReferenceManifest(tempDirectory, manifestPath);
    const references = await loadVisualReferenceManifest(manifestPath);
    const visualMatcher = await buildVisualReferenceMatcher(references, 0);
    const channelMessages = [];
    let deleted = 0;
    let ocrCalls = 0;

    const message = {
      id: "message-2",
      guildId: "guild-1",
      channelId: "channel-1",
      author: {
        id: "user-1",
        tag: "tester#0001",
        bot: false,
        displayAvatarURL: () => "https://example.com/avatar.png",
        toString: () => "<@user-1>",
      },
      channel: {
        isTextBased: () => true,
        isSendable: () => true,
        send: async (payload) => {
          channelMessages.push(payload);
        },
      },
      guild: {
        preferredLocale: "en-US",
        ownerId: "owner-1",
      },
      attachments: new Map([
        [
          "attachment-1",
          {
            id: "attachment-1",
            name: "safe.png",
            contentType: "image/png",
            size: safeBuffer.length,
            url: imageUrl("safe"),
          },
        ],
        [
          "attachment-2",
          {
            id: "attachment-2",
            name: "matching.png",
            contentType: "image/png",
            size: matchingBuffer.length,
            url: imageUrl("matching"),
          },
        ],
      ]),
      embeds: [],
      messageSnapshots: new Map(),
      member: {
        moderatable: true,
        permissions: {
          has: () => false,
        },
        timeout: async () => {},
      },
      delete: async () => {
        deleted += 1;
      },
      webhookId: null,
      inGuild: () => true,
    };

    const client = createModerationClient();
    const handleMessage = createMessageHandler({
      client,
      config: testConfig({
        maxImageBytes: 1024,
        maxImagePixels: 16_000_000,
        imageDownloadTimeoutMs: 1000,
        timeoutMs: 60_000,
      }),
      ocrService: {
        singlePass: true,
        recognize: async () => {
          ocrCalls += 1;
          return "nothing useful";
        },
      },
      visualMatcher,
    });

    await handleMessage(message);

    assert.equal(deleted, 1);
    assert.equal(ocrCalls, 1);
    assert.equal(channelMessages.length, 0);
    assert.equal(client.sent.length, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("ignores guild administrators", async () => {
  const originalFetch = globalThis.fetch;
  const imageBuffer = await createHorizontalGradient(32, 32);
  globalThis.fetch = async () => createImageFetchResponse(imageBuffer);

  try {
    let deleted = 0;
    let ocrCalls = 0;
    const channelMessages = [];
    const message = {
      id: "message-admin",
      guildId: "guild-1",
      channelId: "channel-1",
      author: {
        id: "user-admin",
        tag: "admin#0001",
        bot: false,
        displayAvatarURL: () => "https://example.com/avatar.png",
        toString: () => "<@user-admin>",
      },
      channel: {
        isTextBased: () => true,
        isSendable: () => true,
        send: async (payload) => {
          channelMessages.push(payload);
        },
      },
      guild: {
        preferredLocale: "en-US",
        ownerId: "owner-1",
        members: {
          fetch: async () => {
            throw new Error("should not fetch");
          },
        },
      },
      attachments: new Map([
        [
          "attachment-1",
          {
            id: "attachment-1",
            name: "proof.png",
            contentType: "image/png",
            size: imageBuffer.length,
            url: imageUrl("proof"),
          },
        ],
      ]),
      embeds: [],
      messageSnapshots: new Map(),
      member: {
        moderatable: true,
        permissions: {
          has: () => true,
        },
        timeout: async () => {},
      },
      delete: async () => {
        deleted += 1;
      },
      webhookId: null,
      inGuild: () => true,
    };

    const handleMessage = createMessageHandler({
      client: {},
      config: testConfig({
        maxImageBytes: 1024,
        maxImagePixels: 16_000_000,
        imageDownloadTimeoutMs: 1000,
        timeoutMs: 60_000,
      }),
      ocrService: {
        recognize: async () => {
          ocrCalls += 1;
          return "Withdrawal\nSucceeded";
        },
      },
    });

    await handleMessage(message);

    assert.equal(deleted, 0);
    assert.equal(ocrCalls, 0);
    assert.equal(channelMessages.length, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("moderates guild administrators when administrator exclusion is disabled", async () => {
  const originalFetch = globalThis.fetch;
  const imageBuffer = await createHorizontalGradient(32, 32);
  globalThis.fetch = async () => createImageFetchResponse(imageBuffer);

  try {
    let deleted = 0;
    let timeoutValue = null;
    const channelMessages = [];
    const message = {
      id: "message-admin-enabled",
      guildId: "guild-1",
      channelId: "channel-1",
      author: {
        id: "user-admin-enabled",
        tag: "admin#0001",
        bot: false,
        displayAvatarURL: () => "https://example.com/avatar.png",
        toString: () => "<@user-admin-enabled>",
      },
      channel: {
        isTextBased: () => true,
        isSendable: () => true,
        send: async (payload) => {
          channelMessages.push(payload);
        },
      },
      guild: {
        preferredLocale: "en-US",
        ownerId: "owner-1",
      },
      attachments: new Map([
        [
          "attachment-1",
          {
            id: "attachment-1",
            name: "proof.png",
            contentType: "image/png",
            size: imageBuffer.length,
            url: imageUrl("proof"),
          },
        ],
      ]),
      embeds: [],
      messageSnapshots: new Map(),
      member: {
        moderatable: true,
        permissions: {
          has: () => true,
        },
        timeout: async (value) => {
          timeoutValue = value;
        },
      },
      delete: async () => {
        deleted += 1;
      },
      webhookId: null,
      inGuild: () => true,
    };

    const client = createModerationClient();
    const handleMessage = createMessageHandler({
      client,
      config: testConfig({
        maxImageBytes: 1024,
        maxImagePixels: 16_000_000,
        imageDownloadTimeoutMs: 1000,
        timeoutMs: 60_000,
        excludeAdmins: false,
      }),
      ocrService: {
        recognize: async () => "Withdrawal\nSucceeded",
      },
    });

    await handleMessage(message);

    assert.equal(deleted, 1);
    assert.equal(timeoutValue, 60_000);
    assert.equal(channelMessages.length, 0);
    assert.equal(client.sent.length, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("moderates the guild owner when administrator exclusion is disabled", async () => {
  const originalFetch = globalThis.fetch;
  const imageBuffer = await createHorizontalGradient(32, 32);
  globalThis.fetch = async () => createImageFetchResponse(imageBuffer);

  try {
    let deleted = 0;
    let timeoutValue = null;
    const channelMessages = [];
    const message = {
      id: "message-owner-enabled",
      guildId: "guild-1",
      channelId: "channel-1",
      author: {
        id: "owner-1",
        tag: "owner#0001",
        bot: false,
        displayAvatarURL: () => "https://example.com/avatar.png",
        toString: () => "<@owner-1>",
      },
      channel: {
        isTextBased: () => true,
        isSendable: () => true,
        send: async (payload) => {
          channelMessages.push(payload);
        },
      },
      guild: {
        preferredLocale: "en-US",
        ownerId: "owner-1",
      },
      attachments: new Map([
        [
          "attachment-1",
          {
            id: "attachment-1",
            name: "proof.png",
            contentType: "image/png",
            size: imageBuffer.length,
            url: imageUrl("proof"),
          },
        ],
      ]),
      embeds: [],
      messageSnapshots: new Map(),
      member: {
        moderatable: true,
        permissions: {
          has: () => true,
        },
        timeout: async (value) => {
          timeoutValue = value;
        },
      },
      delete: async () => {
        deleted += 1;
      },
      webhookId: null,
      inGuild: () => true,
    };

    const client = createModerationClient();
    const handleMessage = createMessageHandler({
      client,
      config: testConfig({
        maxImageBytes: 1024,
        maxImagePixels: 16_000_000,
        imageDownloadTimeoutMs: 1000,
        timeoutMs: 60_000,
        excludeAdmins: false,
      }),
      ocrService: {
        recognize: async () => "Withdrawal\nSucceeded",
      },
    });

    await handleMessage(message);

    assert.equal(deleted, 1);
    assert.equal(timeoutValue, 60_000);
    assert.equal(channelMessages.length, 0);
    assert.equal(client.sent.length, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("ignores members with excluded roles", async () => {
  const originalFetch = globalThis.fetch;
  const imageBuffer = await createHorizontalGradient(32, 32);
  globalThis.fetch = async () => createImageFetchResponse(imageBuffer);

  try {
    let deleted = 0;
    let ocrCalls = 0;
    const message = {
      id: "message-role-excluded",
      guildId: "guild-1",
      channelId: "channel-1",
      author: {
        id: "user-role",
        tag: "role#0001",
        bot: false,
        displayAvatarURL: () => "https://example.com/avatar.png",
        toString: () => "<@user-role>",
      },
      channel: {
        isTextBased: () => true,
        isSendable: () => true,
        send: async () => {},
      },
      guild: {
        preferredLocale: "en-US",
        ownerId: "owner-1",
      },
      attachments: new Map([
        [
          "attachment-1",
          {
            id: "attachment-1",
            name: "proof.png",
            contentType: "image/png",
            size: imageBuffer.length,
            url: imageUrl("proof"),
          },
        ],
      ]),
      embeds: [],
      messageSnapshots: new Map(),
      member: {
        moderatable: true,
        permissions: {
          has: () => false,
        },
        roles: {
          cache: new Map([["role-1", { id: "role-1" }]]),
        },
        timeout: async () => {},
      },
      delete: async () => {
        deleted += 1;
      },
      webhookId: null,
      inGuild: () => true,
    };

    const handleMessage = createMessageHandler({
      client: {},
      config: testConfig({
        maxImageBytes: 1024,
        maxImagePixels: 16_000_000,
        imageDownloadTimeoutMs: 1000,
        timeoutMs: 60_000,
        excludedRoleIds: ["role-1"],
      }),
      ocrService: {
        recognize: async () => {
          ocrCalls += 1;
          return "Withdrawal\nSucceeded";
        },
      },
    });

    await handleMessage(message);

    assert.equal(deleted, 0);
    assert.equal(ocrCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("uses the server timeout setting when timing out a user", async () => {
  const originalFetch = globalThis.fetch;
  const imageBuffer = await createHorizontalGradient(32, 32);
  globalThis.fetch = async () => createImageFetchResponse(imageBuffer);

  try {
    let timeoutMs = null;
    const message = {
      id: "message-timeout",
      guildId: "guild-1",
      channelId: "channel-1",
      author: {
        id: "user-timeout",
        tag: "timeout#0001",
        bot: false,
        displayAvatarURL: () => "https://example.com/avatar.png",
        toString: () => "<@user-timeout>",
      },
      channel: {
        isTextBased: () => true,
        isSendable: () => true,
        send: async () => {},
      },
      guild: {
        preferredLocale: "en-US",
        ownerId: "owner-1",
      },
      attachments: new Map([
        [
          "attachment-1",
          {
            id: "attachment-1",
            name: "proof.png",
            contentType: "image/png",
            size: imageBuffer.length,
            url: imageUrl("proof"),
          },
        ],
      ]),
      embeds: [],
      messageSnapshots: new Map(),
      member: {
        moderatable: true,
        permissions: {
          has: () => false,
        },
        timeout: async (value) => {
          timeoutMs = value;
        },
      },
      delete: async () => {},
      webhookId: null,
      inGuild: () => true,
    };

    const handleMessage = createMessageHandler({
      client: {},
      config: testConfig({
        maxImageBytes: 1024,
        maxImagePixels: 16_000_000,
        imageDownloadTimeoutMs: 1000,
        timeoutMs: 60_000,
        timeoutMs: 15 * 60_000,
      }),
      ocrService: {
        recognize: async () => "Withdrawal\nSucceeded",
      },
    });

    await handleMessage(message);

    assert.equal(timeoutMs, 15 * 60_000);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

function createTextMessage({ id, authorId, content }) {
  const events = { deleted: 0, timeouts: 0 };
  const message = {
    id,
    guildId: "guild-1",
    channelId: "channel-1",
    content,
    author: {
      id: authorId,
      tag: `${authorId}#0001`,
      bot: false,
      displayAvatarURL: () => "https://example.com/avatar.png",
      toString: () => `<@${authorId}>`,
    },
    channel: {
      isTextBased: () => true,
      isSendable: () => true,
      send: async () => {},
    },
    guild: { preferredLocale: "en-US", ownerId: "owner-1" },
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map(),
    member: {
      moderatable: true,
      permissions: { has: () => false },
      timeout: async () => { events.timeouts += 1; },
    },
    delete: async () => { events.deleted += 1; },
    webhookId: null,
    inGuild: () => true,
  };
  return { message, events };
}

test("TEXT_SCAM_ENABLED switches hiring-ad detection on and off", async () => {
  for (const textScamEnabled of [true, false]) {
    const { message, events } = createTextMessage({
      id: `hiring-${textScamEnabled}`,
      authorId: "recruiter",
      content: "We're hiring a senior React developer for a paid long-term project. DM me your portfolio.",
    });
    const client = createModerationClient();
    const handleMessage = createMessageHandler({
      client,
      config: testConfig({ textScamEnabled }),
      ocrService: { recognize: async () => "" },
    });

    await handleMessage(message);

    assert.equal(events.deleted, textScamEnabled ? 1 : 0);
    assert.equal(events.timeouts, textScamEnabled ? 1 : 0);
    assert.equal(client.sent.length, textScamEnabled ? 1 : 0);
  }
});

test("known spammer IDs are only enforced while SPAM_MESSAGES_ENABLED is on", async () => {
  for (const spamMessagesEnabled of [true, false]) {
    const { message, events } = createTextMessage({
      id: `known-spammer-${spamMessagesEnabled}`,
      // Listed in spam-users.json.
      authorId: "1537410283688169583",
      content: "hello there",
    });
    const handleMessage = createMessageHandler({
      client: createModerationClient(),
      config: testConfig({ spamMessagesEnabled }),
      ocrService: { recognize: async () => "" },
    });

    await handleMessage(message);

    assert.equal(events.deleted, spamMessagesEnabled ? 1 : 0);
  }
});

test("acts once when Discord sends an update while the message is still being handled", async () => {
  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const { message, events } = createTextMessage({
    id: "link-spam",
    authorId: "link-spammer",
    content: "free bonus https://wenowin.com/promo",
  });
  message.member.timeout = async () => { await delay(30); events.timeouts += 1; };
  message.delete = async () => { await delay(30); events.deleted += 1; };
  const client = createModerationClient();
  const handleMessage = createMessageHandler({
    client,
    config: testConfig(),
    ocrService: { recognize: async () => "" },
  });

  // MessageCreate, then MessageUpdate (link preview added) for the same message.
  await Promise.all([handleMessage(message), delay(10).then(() => handleMessage(message))]);
  await handleMessage(message);

  assert.equal(events.timeouts, 1);
  assert.equal(events.deleted, 1);
  assert.equal(client.sent.length, 1);
});
