import test from "node:test";
import assert from "node:assert/strict";
import { findSpamMessage, getMessageText, getSpamText, normalizeSpamText } from "../src/spam-messages.js";

test("normalizes spam text and matches a listed phrase", () => {
  assert.equal(normalizeSpamText("  ¡PREMIO!  "), "¡premio!");
  assert.equal(findSpamMessage("Congratulations!   You have won a PRIZE. Click here to claim it."), "Congratulations! You have won a prize. Click here to claim it.");
});

test("does not match messages outside the list", () => {
  assert.equal(findSpamMessage("This is a normal conversation."), null);
  assert.equal(findSpamMessage("Free crypto giveaway!", ["free crypto giveaway now"]), null);
});

test("removes porn-related wording but allows the word NSFW", () => {
  const blocked = [
    "Free porn here, check my bio",
    "best p0rn collection dm me",
    "Hot hentai server, join now",
    "My OnlyFans link is in bio",
    "send nudes",
    "Leaked sex tape of a celebrity",
    "xxx videos for free",
    "naked pics in my profile",
    "cam girls online now",
  ];
  const allowed = [
    "How can I block NSFW content uploads in Appwrite Storage?",
    "We need to filter nsfw memes from our community app",
    "APPWRITE_API_KEY=xxx and project id xxx-xxx",
    "My users collection has a sex attribute (male/female)",
    "I live in Sussex, anyone else in the UK?",
    "The design uses a nude color palette",
    "Only fans of Svelte will get this joke",
  ];

  for (const message of blocked) {
    assert.match(findSpamMessage(message) ?? "", /^Blocked wording: "/, message);
  }
  for (const message of allowed) {
    assert.equal(findSpamMessage(message), null, message);
  }
});

test("includes embed and forwarded snapshot descriptions", () => {
  const message = {
    content: "",
    embeds: [{ description: "server description" }],
    messageSnapshots: new Map([
      ["snapshot", { embeds: [{ description: "forwarded description" }] }],
    ]),
  };

  assert.equal(getSpamText(message), "server description\nforwarded description");
});

test("includes forwarded message content and embed URLs in the shared text", () => {
  const message = {
    content: "outer message",
    embeds: [],
    messageSnapshots: new Map([
      ["snapshot", {
        content: "forwarded message https://surveybuilder.io/c/capture/mhnkqthus3a",
        embeds: [{ url: "https://agentrouter.org/register?aff=qaiK" }],
        messageSnapshots: new Map(),
      }],
    ]),
  };

  const text = getMessageText(message);
  assert.match(text, /forwarded message/);
  assert.match(text, /surveybuilder\.io/);
  assert.match(text, /agentrouter\.org/);
});
