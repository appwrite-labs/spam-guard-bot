import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { extractDiscordInviteCodes } from "./invite-protection.js";

const nsfwKeywordsPath = fileURLToPath(
  new URL("../nsfw-server-keywords.json", import.meta.url),
);

const nsfwKeywords = JSON.parse(readFileSync(nsfwKeywordsPath, "utf8"));

export function normalizeNsfwServerText(value) {
  return typeof value === "string"
    ? value
        .normalize("NFKC")
        .normalize("NFD")
        .replace(/\p{Diacritic}/gu, "")
        .toLocaleLowerCase()
        .replace(/\s+/gu, " ")
        .trim()
    : "";
}

export function normalizeNsfwKeywords(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  return [
    ...new Set(
      value
        .filter((keyword) => typeof keyword === "string")
        .map((keyword) => keyword.trim())
        .filter(Boolean),
    ),
  ];
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function findKeywordMatches(text, keyword) {
  const normalizedKeyword = normalizeNsfwServerText(keyword);

  if (!normalizedKeyword) {
    return [];
  }

  const pattern = new RegExp(
    `(?<![\\p{L}\\p{N}])${escapeRegExp(normalizedKeyword)}(?![\\p{L}\\p{N}])`,
    "gu",
  );
  return [...text.matchAll(pattern)];
}

function isNegatedNsfwMatch(text, match) {
  const before = text.slice(Math.max(0, match.index - 32), match.index);
  const after = text.slice(
    match.index + match[0].length,
    match.index + match[0].length + 64,
  );

  return (
    /(?:^|\b)(?:no|without|not)\s*$/u.test(before) ||
    /^\s+(?:(?:is|are)\s+)?(?:not\s+allowed|prohibited|forbidden|banned)\b/u.test(after)
  );
}

export function findNsfwServerKeyword(serverName, keywords = nsfwKeywords) {
  const normalizedName = normalizeNsfwServerText(serverName);

  if (!normalizedName) {
    return null;
  }

  for (const keyword of normalizeNsfwKeywords(keywords)) {
    const matches = findKeywordMatches(normalizedName, keyword);

    if (matches.some((match) => !isNegatedNsfwMatch(normalizedName, match))) {
      return keyword;
    }
  }

  return null;
}

// Discord's Guild NSFW level 3 means the server is age-restricted. Keep this
// check independent from names and descriptions because those fields are not
// always included in an invite response.
function hasDiscordNsfwLevel(invite) {
  return invite?.guildNsfwLevel === 3 || invite?.guildNsfwLevel === "AGE_RESTRICTED";
}

function getNsfwServerMetadata(invite) {
  const metadata = [
    invite?.guildName,
    invite?.guildDescription,
    invite?.guildTag,
    invite?.guildTagEmoji,
    invite?.guildServerTag,
    invite?.guildServerTagEmoji,
    invite?.guildTags,
    invite?.guildFeatures,
    invite?.guildWelcomeScreen,
    invite?.guild,
  ];
  const textValues = [];
  // discord.js structures point back at each other (a welcome screen holds
  // its guild, which holds the welcome screen), so skip objects already seen.
  const seen = new WeakSet();

  const visit = (value) => {
    if (typeof value === "string") {
      textValues.push(value);
      return;
    }

    if (!value || typeof value !== "object" || seen.has(value)) {
      return;
    }
    seen.add(value);

    if (Array.isArray(value)) {
      for (const item of value) visit(item);
      return;
    }

    // The selected roots above are already limited to server metadata.
    // Discord may nest tag/emoji text under generic keys such as `value`,
    // so inspect every nested value instead of relying on field names.
    for (const item of Object.values(value)) visit(item);
  };

  for (const value of metadata) visit(value);
  return textValues.join("\n");
}

export async function findNsfwInvite(
  content,
  resolveInvite,
  keywords = nsfwKeywords,
) {
  for (const code of extractDiscordInviteCodes(content)) {
    const invite = await resolveInvite(code);
    const keyword = findNsfwServerKeyword(getNsfwServerMetadata(invite), keywords);

    if (keyword || hasDiscordNsfwLevel(invite)) {
      return {
        code,
        ...invite,
        keyword: keyword ?? "Discord age-restricted server",
      };
    }
  }

  return null;
}

export const NSFW_SERVER_KEYWORDS = Object.freeze(
  normalizeNsfwKeywords(nsfwKeywords),
);
