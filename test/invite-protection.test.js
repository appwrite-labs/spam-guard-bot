import test from "node:test";
import assert from "node:assert/strict";
import {
  createInviteResolver,
  extractDiscordInviteCodes,
  findMaliciousInvite,
} from "../src/invite-protection.js";
import { MALICIOUS_GUILD_IDS } from "../src/malicious-servers.js";
import {
  findNsfwInvite,
  findNsfwServerKeyword,
  NSFW_SERVER_KEYWORDS,
} from "../src/nsfw-servers.js";

test("loads the global malicious server list from JSON", () => {
  assert.ok(Array.isArray(MALICIOUS_GUILD_IDS));
  assert.ok(MALICIOUS_GUILD_IDS.every((guildId) => /^\d{17,20}$/u.test(guildId)));
});

test("extracts Discord invite codes from supported link formats", () => {
  assert.deepEqual(
    extractDiscordInviteCodes(
      "https://discord.gg/alpha discord.com/invite/beta https://discordapp.com/invite/alpha",
    ),
    ["alpha", "beta"],
  );
});

test("limits invite extraction to avoid API and cache abuse", () => {
  const content = Array.from(
    { length: 32 },
    (_, index) => "https://discord.gg/unique-" + index,
  ).join(" ");
  const codes = extractDiscordInviteCodes(content);

  assert.equal(codes.length, 16);
  assert.deepEqual(extractDiscordInviteCodes("https://discord.gg/" + "a".repeat(65)), []);
});

test("extracts obfuscated and URL-encoded invite codes", () => {
  assert.deepEqual(
    extractDiscordInviteCodes(
      "CREATE_A_TICKET (discord:/#@discord.gg/Vv6a4My6he)",
    ),
    ["Vv6a4My6he"],
  );

  assert.deepEqual(
    extractDiscordInviteCodes(
      [
        "(<ht",
        "> tp",
        "s:////\\@di",
        "sco",
        "rd.",
        "gg/%56%76%36%61%34%4D%79%36%68%65>)",
      ].join("\n"),
    ),
    ["Vv6a4My6he"],
  );
});

test("extracts invites wrapped in mailto, Markdown, brackets, and Unicode text", () => {
  const messages = [
    "**mailto:/%7CŽdiscord.gg/Vv6a4My6he**",
    "(**discord:/#@discord.gg/Vv6a4My6he**)",
    "**mailto:/#@discord.gg/Vv6a4My6he**",
    "[   **mailto:/#@discord.gg/Vv6a4My6he**  ]",
  ];

  for (const message of messages) {
    assert.deepEqual(extractDiscordInviteCodes(message), ["Vv6a4My6he"]);
  }
});

test("finds a malicious invite by resolving its guild ID", async () => {
  const resolver = async (code) =>
    code === "malicious"
      ? { guildId: "123456789012345678", guildName: "Safe server" }
      : { guildId: "987654321098765432", guildName: "Other server" };

  assert.deepEqual(
    await findMaliciousInvite(
      "Join us: https://discord.gg/malicious",
      ["123456789012345678"],
      resolver,
    ),
    {
      code: "malicious",
      guildId: "123456789012345678",
      guildName: "Safe server",
    },
  );
});

test("detects NSFW keywords in an invite destination server name", async () => {
  assert.equal(findNsfwServerKeyword("🔞 SquirT +18", NSFW_SERVER_KEYWORDS), "+18");

  const invite = await findNsfwInvite(
    "https://discord.gg/nsfw-server",
    async () => ({
      guildId: "123456789012345678",
      guildName: "Official +18 Squirt Lounge",
    }),
    ["+18", "squirt"],
  );

  assert.deepEqual(invite, {
    code: "nsfw-server",
    guildId: "123456789012345678",
    guildName: "Official +18 Squirt Lounge",
    keyword: "+18",
  });
});

test("ignores negated NSFW labels and generic adults-only labels", async () => {
  assert.equal(findNsfwServerKeyword("No NSFW content here", NSFW_SERVER_KEYWORDS), null);
  assert.equal(findNsfwServerKeyword("NSFW is not allowed", NSFW_SERVER_KEYWORDS), null);
  assert.equal(findNsfwServerKeyword("No NSFW here, NSFW content is welcome", NSFW_SERVER_KEYWORDS), "nsfw");
  assert.equal(findNsfwServerKeyword("Adults only", NSFW_SERVER_KEYWORDS), null);
  assert.equal(findNsfwServerKeyword("Adult education community", NSFW_SERVER_KEYWORDS), null);

  const invite = await findNsfwInvite(
    "https://discord.gg/safe-community",
    async () => ({
      guildId: "123456789012345678",
      guildName: "Adults only",
      guildDescription: "No NSFW content here",
    }),
    NSFW_SERVER_KEYWORDS,
  );

  assert.equal(invite, null);
});

test("detects NSFW keywords in the invite destination description, tags, and emoji", async () => {
  const invite = await findNsfwInvite(
    "https://discord.gg/roblox-external",
    async () => ({
      guildId: "123456789012345678",
      guildName: "BEST ROBLOX EXTERNAL!",
      guildDescription: "FREE cheats, cracks, leaks, AI Jailbreaks AND NSFW content including 3000+ NSFW GIFs & Memes!",
      guildTags: ["NSFW"],
      guildTagEmoji: "+18",
    }),
    NSFW_SERVER_KEYWORDS,
  );

  assert.equal(invite.code, "roblox-external");
  assert.equal(invite.keyword, "nsfw");
});

test("detects NSFW keywords in the server description paragraph", async () => {
  const invite = await findNsfwInvite(
    "https://discord.gg/A6vxFEq4Tz",
    async () => ({
      guildId: "123456789012345678",
      guildName: "The Crystalline Hideout",
      guildDescription:
        "Welcome to The Crystalline Hideout 18+ 🌙✨! Chill & Chat. Exclusive 18+ Spaces.",
    }),
    NSFW_SERVER_KEYWORDS,
  );

  assert.equal(invite.code, "A6vxFEq4Tz");
  assert.equal(invite.keyword, "18+");
});

test("detects emoji-labelled NSFW servers and ID-verified 18+ descriptions", async () => {
  const emojiLabelInvite = await findNsfwInvite(
    "https://discord.gg/emoji-label",
    async () => ({
      guildId: "123456789012345678",
      guildName: "Community",
      guildTags: [{ value: "emoji_berenjena NSFW" }],
    }),
    NSFW_SERVER_KEYWORDS,
  );
  assert.equal(emojiLabelInvite.keyword, "nsfw");

  const verifiedInvite = await findNsfwInvite(
    "https://discord.gg/id-verified",
    async () => ({
      guildId: "123456789012345678",
      guildName: "Community",
      guildDescription: "18+ ID verified only",
    }),
    NSFW_SERVER_KEYWORDS,
  );
  assert.equal(verifiedInvite.keyword, "18+");
});

test("detects NSFW emoji labels, leetspeak, and promotional descriptions", async () => {
  for (const [code, metadata, expectedKeyword] of [
    ["emoji-18", { guildTagEmoji: "emoji 18 NSFW" }, "nsfw"],
    ["h3ntai", { guildTags: ["h3ntai"] }, "h3ntai"],
    ["p0rn", { guildTags: ["P0rn"] }, "p0rn"],
    ["nsfw-gifs", { guildDescription: "NSFW GIFs and NSFW Memes" }, "nsfw"],
    ["adult-nsfw", { guildDescription: "Adult NSFW community" }, "nsfw"],
  ]) {
    const invite = await findNsfwInvite(
      `https://discord.gg/${code}`,
      async () => ({ guildId: "123456789012345678", guildName: "Community", ...metadata }),
      NSFW_SERVER_KEYWORDS,
    );
    assert.equal(invite.keyword, expectedKeyword);
  }
});

test("detects Discord age-restricted invites when invite text is unavailable", async () => {
  const invite = await findNsfwInvite(
    "https://discord.gg/A6vxFEq4Tz",
    async () => ({
      guildId: "123456789012345678",
      guildName: "The Crystalline Hideout",
      guildNsfwLevel: 3,
    }),
    NSFW_SERVER_KEYWORDS,
  );

  assert.equal(invite.code, "A6vxFEq4Tz");
  assert.equal(invite.keyword, "Discord age-restricted server");
});

test("caches invite lookups", async () => {
  let fetches = 0;
  const resolveInvite = createInviteResolver({
    fetchInvite: async () => {
      fetches += 1;
      return { guild: { id: "123456789012345678" } };
    },
  });

  assert.deepEqual(await resolveInvite("same-code"), {
    guildId: "123456789012345678",
    guildName: null,
  });
  assert.deepEqual(await resolveInvite("same-code"), {
    guildId: "123456789012345678",
    guildName: null,
  });
  assert.equal(fetches, 1);
});

test("keeps invite guild descriptions and tag metadata available to moderation", async () => {
  const resolveInvite = createInviteResolver({
    fetchInvite: async () => ({
      guild: {
        id: "123456789012345678",
        name: "BEST ROBLOX EXTERNAL!",
        description: "FREE cheats and NSFW content",
        features: ["GUILD_TAGS"],
        nsfwLevel: 3,
        tag: "NSFW",
        tagEmoji: "+18",
      },
    }),
  });

  assert.deepEqual(await resolveInvite("roblox-external"), {
    guildId: "123456789012345678",
    guildName: "BEST ROBLOX EXTERNAL!",
    guildDescription: "FREE cheats and NSFW content",
    guildFeatures: ["GUILD_TAGS"],
    guildNsfwLevel: 3,
    guildTag: "NSFW",
    guildTagEmoji: "+18",
  });
});

test("falls back to the invite welcome-screen description", async () => {
  const resolveInvite = createInviteResolver({
    fetchInvite: async () => ({
      guild: {
        id: "123456789012345678",
        name: "The Crystalline Hideout",
        welcomeScreen: {
          description: "Exclusive 18+ Spaces",
        },
      },
    }),
  });

  assert.equal(
    (await resolveInvite("A6vxFEq4Tz")).guildDescription,
    "Exclusive 18+ Spaces",
  );
});

test("checks invites to servers with a welcome screen without recursing forever", async () => {
  const { Client, Invite } = await import("discord.js");
  const client = new Client({ intents: [] });
  const inviteFor = (description) => new Invite(client, {
    code: "community",
    type: 0,
    guild: {
      id: "123456789012345678",
      name: "Some Community Server",
      description,
      features: ["COMMUNITY", "WELCOME_SCREEN_ENABLED"],
      nsfw_level: 0,
      welcome_screen: {
        description: "Welcome!",
        welcome_channels: [{ channel_id: "223456789012345678", description: "Rules", emoji_id: null, emoji_name: "📜" }],
      },
    },
    channel: { id: "223456789012345678", name: "general", type: 0 },
  });

  try {
    for (const [description, expectedKeyword] of [["A friendly dev community", null], ["18+ NSFW memes", "nsfw"]]) {
      client.fetchInvite = async () => inviteFor(description);
      const result = await findNsfwInvite("https://discord.gg/community", createInviteResolver(client));
      assert.equal(result?.keyword ?? null, expectedKeyword, description);
    }
  } finally {
    await client.destroy();
  }
});
