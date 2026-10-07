import test from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_CONFIG } from "../src/config.js";
import { handleSpamReportMessage } from "../src/spam-report.js";

const ENABLED = { ...DEFAULT_CONFIG, moderationChannelId: "moderation-channel", spamReportEnabled: true };

function createCollection(messages) {
  const entries = messages.map((message) => [message.id, message]);
  const collection = new Map(entries);

  return {
    size: collection.size,
    values: () => collection.values(),
    last: () => [...collection.values()].at(-1),
    has: (id) => collection.has(id),
    filter: (predicate) => createCollection([...collection.values()].filter(predicate)),
  };
}

test("!spamreport does nothing unless SPAM_REPORT_ENABLED is on", async () => {
  const events = [];
  const reporter = {
    id: "command-message",
    author: { id: "reporter", bot: false, tag: "reporter#0001" },
    content: "!spamreport",
    member: { permissions: { has: () => true } },
    inGuild: () => true,
    reply: async () => events.push("reply"),
    delete: async () => events.push("command-delete"),
  };

  assert.equal(await handleSpamReportMessage(reporter), false);
  assert.equal(await handleSpamReportMessage(reporter, { ...ENABLED, spamReportEnabled: false }), false);
  assert.deepEqual(events, []);
});

test("!spamreport deletes the reported message and its single-message thread", async () => {
  const events = [];
  const replies = [];
  const user = { id: "reported-user", tag: "reported-user#0001", bot: false };
  const timeouts = [];
  let targetMessage;

  const thread = {
    id: "thread-1",
    name: "spam thread",
    ownerId: user.id,
    isThread: () => true,
    isTextBased: () => true,
    isSendable: () => true,
    messages: {
      fetch: async (options) => {
        if (typeof options === "string") return targetMessage;
        return createCollection([targetMessage]);
      },
    },
    delete: async () => events.push("thread-delete"),
  };

  targetMessage = {
    id: "target-message",
    author: user,
    content: "same spam",
    createdTimestamp: Date.now(),
    channel: thread,
    channelId: thread.id,
    attachments: new Map(),
    embeds: [],
    delete: async () => events.push("message-delete"),
  };

  const reporter = {
    author: { id: "reporter", bot: false, tag: "reporter#0001" },
    content: "!spamreport",
    reference: { messageId: targetMessage.id },
    member: { permissions: { has: () => true } },
    guild: {
      preferredLocale: "en-US",
      members: {
        fetch: async () => ({ timeout: async (duration) => { timeouts.push(duration); } }),
      },
      channels: {
        cache: createCollection([thread]),
      },
    },
    channel: thread,
    client: {
      channels: {
        fetch: async () => {
          throw new Error("No feedback channel is configured.");
        },
      },
    },
    inGuild: () => true,
    reply: async (payload) => replies.push(payload),
  };

  await handleSpamReportMessage(reporter, ENABLED);

  assert.deepEqual(events, ["message-delete", "thread-delete"]);
  assert.deepEqual(timeouts, [10 * 60_000]);
  assert.equal(replies.length, 1);
  assert.equal(replies[0].content, "User timed out. Matching messages deleted: 1.");
});

test("!spamreport only deletes copies inside the lookback window and stops paging there", async () => {
  const user = { id: "reported-user", tag: "reported-user#0001", bot: false };
  const deleted = [];
  const fetchCalls = [];
  const now = Date.now();
  const spam = (id, minutesAgo) => ({
    id,
    author: user,
    content: "same spam",
    createdTimestamp: now - minutesAgo * 60_000,
    channel: { isThread: () => false },
    channelId: "channel-1",
    attachments: new Map(),
    embeds: [],
    delete: async () => deleted.push(id),
  });
  const targetMessage = spam("target", 1);
  const filler = (index, minutesAgo) => ({
    id: `filler-${index}`,
    author: { id: "someone-else" },
    content: "hello",
    createdTimestamp: now - minutesAgo * 60_000,
  });
  // A full page of 100 messages that ends just inside the window, then a page
  // that is entirely older than the window.
  const firstPage = [spam("recent-copy", 5), ...Array.from({ length: 98 }, (_, i) => filler(i, 10)), spam("edge-copy", 50)];
  const secondPage = [spam("old-copy", 120), ...Array.from({ length: 99 }, (_, i) => filler(100 + i, 130))];
  const channel = {
    id: "channel-1",
    isTextBased: () => true,
    isSendable: () => true,
    messages: {
      fetch: async (options) => {
        fetchCalls.push(options);
        if (typeof options === "string") return targetMessage;
        if (!options.before) return createCollection(firstPage);
        if (options.before === "edge-copy") return createCollection(secondPage);
        throw new Error("The scan must stop once it is past the lookback window.");
      },
    },
  };

  const reporter = {
    author: { id: "reporter", bot: false, tag: "reporter#0001" },
    content: "!spamreport",
    reference: { messageId: targetMessage.id },
    member: { permissions: { has: () => true } },
    guild: {
      preferredLocale: "en-US",
      members: { fetch: async () => ({ timeout: async () => {} }) },
      channels: { cache: createCollection([channel]) },
    },
    channel,
    client: { channels: { fetch: async () => null } },
    inGuild: () => true,
    reply: async () => {},
    delete: async () => {},
  };

  await handleSpamReportMessage(reporter, { ...ENABLED, spamReportLookbackMs: 60 * 60_000 });

  assert.deepEqual(deleted.sort(), ["edge-copy", "recent-copy", "target"]);
  // The target lookup, the first page, and the page that crossed the window.
  assert.equal(fetchCalls.length, 3);
});

test("!spamreport sends a copy to the feedback channel only when one is configured", async () => {
  for (const feedbackChannelId of [null, "223456789012345678"]) {
    const fetchedChannelIds = [];
    const feedbackMessages = [];
    const user = { id: "reported-user", tag: "reported-user#0001", bot: false };
    const targetMessage = {
      id: "target-message",
      author: user,
      content: "same spam",
      createdTimestamp: Date.now(),
      channel: { isThread: () => false },
      channelId: "channel-1",
      attachments: new Map(),
      embeds: [],
      delete: async () => {},
    };
    const reporter = {
      author: { id: "reporter", bot: false, tag: "reporter#0001" },
      content: "!spamreport",
      reference: { messageId: targetMessage.id },
      member: { permissions: { has: () => true } },
      guild: {
        id: "guild-1",
        preferredLocale: "en-US",
        members: { fetch: async () => ({ timeout: async () => {} }) },
        channels: { cache: createCollection([]) },
      },
      channel: { messages: { fetch: async () => targetMessage } },
      client: {
        channels: {
          fetch: async (channelId) => {
            fetchedChannelIds.push(channelId);
            return {
              isTextBased: () => true,
              isSendable: () => true,
              send: async (payload) => feedbackMessages.push(payload),
            };
          },
        },
      },
      inGuild: () => true,
      reply: async () => {},
      delete: async () => {},
    };

    await handleSpamReportMessage(reporter, { ...ENABLED, feedbackChannelId });

    assert.deepEqual(fetchedChannelIds, feedbackChannelId ? [feedbackChannelId] : []);
    assert.equal(feedbackMessages.length, feedbackChannelId ? 1 : 0);
  }
});

test("!spamreport deletes its command message and rejects non-moderators", async () => {
  const events = [];
  const replies = [];
  const reporter = {
    id: "command-message",
    author: { id: "reporter", bot: false, tag: "reporter#0001" },
    content: "!spamreport",
    member: { permissions: { has: () => false } },
    guild: { preferredLocale: "en-US" },
    inGuild: () => true,
    reply: async (payload) => replies.push(payload),
    delete: async () => events.push("command-delete"),
  };

  const handled = await handleSpamReportMessage(reporter, ENABLED);

  assert.equal(handled, true);
  assert.deepEqual(events, ["command-delete"]);
  assert.equal(replies.length, 1);
  assert.equal(replies[0].content, "You need the Manage Messages permission to use `!spamreport`.");
});
