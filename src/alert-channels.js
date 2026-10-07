import { PermissionFlagsBits, PermissionsBitField } from "discord.js";

function readablePermission(name) {
  return name.replace(/([a-z])([A-Z])/gu, "$1 $2");
}

/**
 * Permissions the bot needs to post alerts in a channel. Threads use Send
 * Messages in Threads instead of Send Messages, and channels that receive
 * image copies (feedback and !spamreport reports) also need Attach Files.
 */
export function getRequiredAlertPermissions(channel, { withFiles = false } = {}) {
  return [
    PermissionFlagsBits.ViewChannel,
    channel.isThread?.()
      ? PermissionFlagsBits.SendMessagesInThreads
      : PermissionFlagsBits.SendMessages,
    PermissionFlagsBits.EmbedLinks,
    ...(withFiles ? [PermissionFlagsBits.AttachFiles] : []),
  ];
}

/**
 * Fetches an alert channel and checks the bot can post there. Throws an error
 * naming the variable, the channel, and any missing permissions.
 */
export async function resolveAlertChannel(client, name, channelId, options = {}) {
  let channel;

  try {
    channel = await client.channels.fetch(channelId);
  } catch (error) {
    throw new Error(`${name} ${channelId} could not be fetched: ${error.message}`);
  }

  if (!channel?.isTextBased() || !channel.isSendable() || !channel.guild) {
    throw new Error(`${name} ${channelId} is not a server text channel.`);
  }

  const required = getRequiredAlertPermissions(channel, options);
  const botMember = channel.guild.members.me ?? await channel.guild.members.fetchMe();
  const permissions = channel.permissionsFor(botMember);
  const missing = permissions
    ? permissions.missing(required)
    : new PermissionsBitField(required).toArray();

  if (missing.length > 0) {
    throw new Error(
      `${name} ${channelId}: the bot is missing ${missing.map(readablePermission).join(", ")} in #${channel.name}.`,
    );
  }

  return channel;
}
