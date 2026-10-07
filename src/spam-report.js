import { PermissionFlagsBits } from "discord.js";
import { DEFAULT_CONFIG } from "./config.js";
import { getTrustedImageUrls } from "./images.js";
import { resolveLocale, t } from "./i18n.js";
import { escapeDiscordMarkdown, sanitizeLogText } from "./security.js";

export async function handleSpamReportMessage(message, config = DEFAULT_CONFIG) {
  if (!config.spamReportEnabled) return false;
  if (message.author.bot || !message.inGuild() || message.content.trim().toLowerCase() !== "!spamreport") return false;

  const locale = resolveLocale(message.guild);
  const reply = (key, ...args) => message.reply({
    content: t(locale, "moderation", key, ...args),
    allowedMentions: { repliedUser: false },
  });

  try {
    const member = message.member ?? await message.guild.members.fetch(message.author.id);

    if (!member.permissions?.has?.(PermissionFlagsBits.ManageMessages)) {
      await reply("spamReportNoPermission");
      return true;
    }

    if (!message.reference?.messageId) {
      await reply("spamReportReplyRequired");
      return true;
    }

    if (typeof message.channel?.messages?.fetch !== "function") {
      throw new Error("The channel cannot fetch the reported message.");
    }

    const targetMessage = await message.channel.messages.fetch(message.reference.messageId);

    if (!targetMessage?.author || targetMessage.author.bot) {
      await reply("spamReportBotMessage");
      return true;
    }

    const result = await reportSpamMessage(
      message.client,
      message.guild,
      targetMessage,
      message.author.tag,
      message.author.id,
      config,
    );
    await reply(result.timedOut ? "spamReportTimedOut" : "spamReportTimeoutFailed", result.deleted);
  } catch (error) {
    console.error("[Spam report] Failed:", error);
    try {
      await reply("spamReportFailed");
    } catch (replyError) {
      console.error("[Spam report] Could not send the error response:", replyError);
    }
  } finally {
    try {
      await message.delete?.();
    } catch (error) {
      console.warn(`[Spam report] Could not delete command message ${message.id}:`, error);
    }
  }

  return true;
}

async function reportSpamMessage(client, guild, targetMessage, reporterTag, reporterId, config) {
  const locale = resolveLocale(guild);
  const user = targetMessage.author;
  const content = targetMessage.content;
  let timedOut = false;

  try {
    const member = await guild.members.fetch(user.id);
    await member.timeout(config.spamReportTimeoutMs, `Spam reported by ${sanitizeLogText(reporterTag, 128)}`);
    timedOut = true;
  } catch (error) {
    console.warn(`[Spam report] Could not timeout member ${user.id}:`, error);
  }

  let deleted = 0;
  const deletedMessageIds = new Set();
  const deleteIfNeeded = async (message) => {
    if (!message?.id || deletedMessageIds.has(message.id)) return;
    deletedMessageIds.add(message.id);

    try {
      await deleteReportedMessage(message);
      deleted += 1;
    } catch (error) {
      console.warn(`[Spam report] Could not delete message ${message.id}:`, error);
    }
  };

  // Always process the reported message itself, including messages in threads
  // that are not present in the guild channel cache.
  await deleteIfNeeded(targetMessage);

  // Only look back as far as the configured window. Scanning a channel's full
  // history costs one API request per 100 messages.
  const cutoff = Date.now() - config.spamReportLookbackMs;
  const isRecent = (message) => !Number.isFinite(message.createdTimestamp) || message.createdTimestamp >= cutoff;
  const channels = guild.channels.cache.filter((channel) =>
    channel.isTextBased() &&
    channel.isSendable() &&
    typeof channel.messages?.fetch === "function",
  );
  for (const channel of channels.values()) {
    try {
      let before;
      for (;;) {
        const messages = await channel.messages.fetch({ limit: 100, ...(before ? { before } : {}) });
        if (!messages.size) break;
        const matches = messages.filter((message) =>
          message.author.id === user.id && message.content === content && isRecent(message),
        );
        await Promise.all([...matches.values()].map(deleteIfNeeded));
        const oldest = messages.last();
        before = oldest?.id;
        if (messages.size < 100 || !oldest || !isRecent(oldest)) break;
      }
    } catch (error) {
      console.warn(`[Spam report] Could not scan channel ${channel.id}:`, error);
    }
  }

  if (config.feedbackChannelId) {
    try {
      const reportChannel = await client.channels.fetch(config.feedbackChannelId);
      if (reportChannel?.isTextBased() && reportChannel.isSendable()) {
        await reportChannel.send({
          content: t(locale, "moderation", "manualSpamReport"),
          embeds: [{ color: 0xed4245, title: t(locale, "moderation", "feedbackTitle"), fields: [
            { name: t(locale, "moderation", "user"), value: escapeDiscordMarkdown(user.tag, 128) + " (" + user.id + ")" },
            { name: t(locale, "moderation", "originalServerChannel"), value: `${guild.id} / ${targetMessage.channelId}` },
            { name: t(locale, "moderation", "message"), value: escapeDiscordMarkdown(content, 1024) || "(empty)" },
            { name: t(locale, "moderation", "reportedBy"), value: escapeDiscordMarkdown(reporterTag, 128) + " (" + reporterId + ")" },
          ] }],
          files: [
            ...getTrustedImageUrls([
              ...[...(targetMessage.attachments?.values?.() ?? [])].map((attachment) => attachment.url),
              ...(targetMessage.embeds ?? []).flatMap((embed) => [embed.image?.url, embed.thumbnail?.url]),
            ]).map((url) => ({ attachment: url })),
          ],
          allowedMentions: { parse: [] },
        });
      }
    } catch (error) {
      console.warn("[Spam report] Could not send the feedback report:", error);
    }
  }

  return { deleted, timedOut };
}

async function deleteReportedMessage(message) {
  const startedThread = !message.channel?.isThread?.()
    ? message.thread ?? message.channel?.threads?.cache?.get?.(message.id)
    : null;
  const thread = message.channel?.isThread?.() &&
    message.channel.ownerId === message.author.id &&
    typeof message.channel.messages?.fetch === "function"
    ? message.channel
    : null;
  let shouldDeleteThread = false;

  if (thread) {
    try {
      const threadMessages = await thread.messages.fetch({ limit: 2 });
      shouldDeleteThread = threadMessages.size === 1 && threadMessages.has(message.id);
    } catch (error) {
      console.warn(`[Spam report] Could not inspect thread ${thread.id} before deletion:`, error);
    }
  }

  if (startedThread?.isThread?.() &&
      startedThread.ownerId === message.author.id &&
      typeof startedThread.delete === "function") {
    try {
      await startedThread.delete("Reported spam message and its thread.");
    } catch (error) {
      console.warn(`[Spam report] Could not delete thread ${startedThread.id}:`, error);
    }
  }

  await message.delete();

  if (shouldDeleteThread) {
    try {
      await thread.delete("Reported spam thread contained only the offending message.");
    } catch (error) {
      console.warn(`[Spam report] Could not delete thread ${thread.id}:`, error);
    }
  }
}
