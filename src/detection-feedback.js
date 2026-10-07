import { randomUUID } from "node:crypto";
import { ActionRowBuilder, ButtonBuilder, ButtonStyle } from "discord.js";
import { resolveLocale, t } from "./i18n.js";
import { getTrustedImageUrls } from "./images.js";
import { escapeDiscordMarkdown, sanitizeLogText, sanitizeText } from "./security.js";

const feedbacks = new Map();
const FEEDBACK_TTL_MS = 15 * 60_000;
const MAX_FEEDBACKS = 1_000;

function pruneFeedbacks(now = Date.now()) {
  for (const [id, feedback] of feedbacks) {
    if (feedback.expiresAt <= now) {
      feedbacks.delete(id);
    }
  }

  while (feedbacks.size > MAX_FEEDBACKS) {
    const oldestId = feedbacks.keys().next().value;
    if (oldestId === undefined) break;
    feedbacks.delete(oldestId);
  }
}

export function createDetectionFeedback(match, message, locale = resolveLocale(message.guild)) {
  const id = randomUUID();
  pruneFeedbacks();
  feedbacks.set(id, {
    messageId: message.id,
    guildId: message.guildId,
    channelId: message.channelId,
    authorTag: sanitizeLogText(message.author?.tag, 128),
    content: sanitizeText(message.content || "(empty)", 2_000),
    recognizedText: sanitizeText(match.text || "(empty)", 4_000),
    imageUrls: getTrustedImageUrls([
      match.source?.url,
      ...[...(message.attachments?.values?.() ?? [])].map((attachment) => attachment.url),
      ...(message.embeds ?? []).flatMap((embed) => [embed.image?.url, embed.thumbnail?.url]),
    ]),
    expiresAt: Date.now() + FEEDBACK_TTL_MS,
  });
  pruneFeedbacks();

  return {
    id,
    components: [new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId(`detection-feedback:false:${id}`).setLabel(t(locale, "moderation", "falseDetection")).setStyle(ButtonStyle.Danger),
      new ButtonBuilder().setCustomId(`detection-feedback:true:${id}`).setLabel(t(locale, "moderation", "correctDetection")).setStyle(ButtonStyle.Success),
    )],
  };
}

export async function handleDetectionFeedback(interaction, { feedbackChannelId = null } = {}) {
  if (!interaction.isButton()) return false;
  const match = /^detection-feedback:(true|false):([0-9a-f-]{36})$/u.exec(interaction.customId);
  if (!match) return false;
  const [, value, id] = match;
  const locale = resolveLocale(interaction);

  if (!feedbackChannelId) {
    await interaction.reply({ content: t(locale, "moderation", "feedbackDisabled"), ephemeral: true });
    return true;
  }

  pruneFeedbacks();
  const feedback = feedbacks.get(id);
  if (!feedback) {
    await interaction.reply({ content: t(locale, "moderation", "feedbackExpired"), ephemeral: true });
    return true;
  }

  if (interaction.guildId !== feedback.guildId) {
    await interaction.reply({ content: t(locale, "moderation", "feedbackWrongServer"), ephemeral: true });
    return true;
  }

  const channel = await interaction.client.channels.fetch(feedbackChannelId);
  if (!channel?.isTextBased() || !channel.isSendable()) {
    throw new Error("The detection feedback channel is unavailable or cannot receive messages.");
  }

  await channel.send({
    content: t(locale, "moderation", "feedbackReport", value === "true" ? t(locale, "moderation", "feedbackCorrect") : t(locale, "moderation", "feedbackFalse")),
    embeds: [{
      color: value === "true" ? 0x57f287 : 0xed4245,
      title: t(locale, "moderation", "feedbackTitle"),
      fields: [
        { name: t(locale, "moderation", "originalServerChannel"), value: `${feedback.guildId} / ${feedback.channelId}` },
        { name: t(locale, "moderation", "user"), value: escapeDiscordMarkdown(feedback.authorTag, 128) + " (" + feedback.messageId + ")" },
        { name: t(locale, "moderation", "recognizedText"), value: escapeDiscordMarkdown(feedback.recognizedText, 1024) || "(empty)" },
        { name: t(locale, "moderation", "message"), value: escapeDiscordMarkdown(feedback.content, 1024) || "(empty)" },
        { name: t(locale, "moderation", "reportedBy"), value: escapeDiscordMarkdown(interaction.user.tag, 128) + " (" + interaction.user.id + ")" },
      ],
    }],
    files: feedback.imageUrls.map((url) => ({ attachment: url })),
    allowedMentions: { parse: [] },
  });
  feedbacks.delete(id);
  await interaction.update({ components: [] });
  return true;
}
