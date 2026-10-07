import test from "node:test";
import assert from "node:assert/strict";
import {
  containsScamPhrase,
  containsBlockedDomain,
  findOcrDetectionReasons,
  findSuspiciousText,
  DEFAULT_PARANOIA_LEVEL,
  OCR_DETECTION_REASONS,
  PARANOIA_LEVELS,
  normalizeOcrText,
  normalizeParanoiaLevel,
  truncateText,
} from "../src/detection.js";

test("detects Withdrawal and Success regardless of case or line breaks", () => {
  assert.equal(containsScamPhrase("Withdrawal\nSUCCESS"), true);
});

test("defaults paranoia to high", () => {
  assert.equal(DEFAULT_PARANOIA_LEVEL, PARANOIA_LEVELS.HIGH);
  assert.equal(normalizeParanoiaLevel(), PARANOIA_LEVELS.HIGH);
  assert.equal(normalizeParanoiaLevel("invalid"), PARANOIA_LEVELS.HIGH);
});

test("detects the words when they appear in reverse order", () => {
  assert.equal(containsScamPhrase("Success confirmed: withdrawal complete"), true);
});

test("detects supported success status variants", () => {
  assert.equal(containsScamPhrase("Withdrawal\nSucceeded"), true);
  assert.equal(containsScamPhrase("Successful payment\nWithdrawal"), true);
  assert.equal(containsScamPhrase("Withdrawal\nSuccess!"), true);
  assert.equal(containsScamPhrase("Withdrawal\nSuccessfully!"), true);
  assert.equal(containsScamPhrase("Withdrawal\nUSDT"), true);
  assert.equal(
    containsScamPhrase("Withdrawal\nAmount\nCompleted\nTransfer"),
    true,
  );
});

test("requires all OCR keywords at medium paranoia", () => {
  assert.equal(
    containsScamPhrase("Withdrawal\nSucceeded", PARANOIA_LEVELS.MEDIUM),
    false,
  );
  assert.equal(
    containsScamPhrase("Withdrawal\nSucceeded\nUSDT", PARANOIA_LEVELS.MEDIUM),
    true,
  );
});

test("does not use regular OCR keywords at low paranoia", () => {
  assert.equal(
    containsScamPhrase("Withdrawal\nSUCCESS", PARANOIA_LEVELS.LOW),
    false,
  );
});

test("detects blocked domains in OCR at every paranoia level", () => {
  for (const level of Object.values(PARANOIA_LEVELS)) {
    assert.equal(
      containsScamPhrase("Promoción: https://www.wenowin.com/bonus", level),
      true,
      `expected a match at ${level} paranoia`,
    );
  }

  assert.equal(containsBlockedDomain("betchoco.com"), true);
  assert.equal(containsBlockedDomain("safe.example"), false);
});

test("reports the category that caused an OCR detection", () => {
  assert.deepEqual(
    findOcrDetectionReasons("Visit wenowin.com", PARANOIA_LEVELS.LOW),
    [OCR_DETECTION_REASONS.MALICIOUS_DOMAIN],
  );
  assert.deepEqual(
    findOcrDetectionReasons("mr beast giveaway", PARANOIA_LEVELS.EXTREME),
    [OCR_DETECTION_REASONS.MR_BEAST],
  );
  assert.deepEqual(
    findOcrDetectionReasons("Withdrawal\nSucceeded"),
    [OCR_DETECTION_REASONS.KEYWORDS],
  );
});

test("allows the required keywords to be far apart", () => {
  assert.equal(
    containsScamPhrase(
      `Withdrawal
      Transaction ID: 123456789
      Network: Example
      Amount: 500.00
      Date: 2026-06-19
      Status: Succeeded`,
    ),
    true,
  );
});

test("requires a withdrawal keyword and a complete success keyword", () => {
  assert.equal(containsScamPhrase("Withdrawal pending"), false);
  assert.equal(containsScamPhrase("Succeeded deposit"), false);
  assert.equal(containsScamPhrase("Withdrawal unsuccessfully"), false);
  assert.equal(containsScamPhrase("Withdrawal USDC"), false);
  assert.equal(containsScamPhrase("USDT"), false);
  assert.equal(containsScamPhrase("Withdrawal usdt"), false);
});

test("supports extreme paranoia triggers", () => {
  assert.equal(containsScamPhrase("succs", PARANOIA_LEVELS.EXTREME), true);
  assert.equal(containsScamPhrase("TRX", PARANOIA_LEVELS.EXTREME), true);
  assert.equal(containsScamPhrase("money", PARANOIA_LEVELS.EXTREME), true);
  assert.equal(containsScamPhrase("mr beast", PARANOIA_LEVELS.EXTREME), true);
  assert.equal(containsScamPhrase("cryptocurrency", PARANOIA_LEVELS.EXTREME), true);
  assert.equal(containsScamPhrase("casino!", PARANOIA_LEVELS.EXTREME), true);
  assert.equal(containsScamPhrase("giveaway", PARANOIA_LEVELS.EXTREME), true);
  assert.equal(containsScamPhrase("giving away", PARANOIA_LEVELS.EXTREME), true);
  assert.equal(containsScamPhrase("bets", PARANOIA_LEVELS.EXTREME), true);
  assert.equal(containsScamPhrase("bonus", PARANOIA_LEVELS.EXTREME), true);
  assert.equal(containsScamPhrase("bonuses", PARANOIA_LEVELS.EXTREME), true);
});

test("normalizes OCR text", () => {
  assert.equal(normalizeOcrText("Succéss"), "SUCCESS");
});

test("limits the text included in the moderation alert", () => {
  assert.equal(truncateText(" a \n b "), "a b");
  assert.equal(truncateText("123456", 5), "1234…");
});

test("detects hiring and recruitment advertisements", () => {
  const ads = [
    "We're hiring a frontend developer, check our LinkedIn",
    "Looking for a senior full-stack developer for a long-term project, DM me",
    "Hiring React devs, paid, message me",
    "We are recruiting AI engineers. Send your CV",
    "Looking for team members for an AI startup, DM me",
    "Join our team! We need a backend engineer, contact me",
    "Hello everyone, I'm looking for an experienced blockchain developer. Please DM me",
    "Looking for highly skilled, experienced Web3 developers. DM me",
    "looking for 2 React Native devs, telegram me",
  ];

  for (const ad of ads) {
    assert.match(findSuspiciousText(ad) ?? "", /recruitment/i, ad);
  }
});

test("does not flag help requests, event invites, or other community messages", () => {
  const messages = [
    "Hey, I'm looking for help with my React app auth flow, can someone DM me?",
    "I'm looking for help from a developer with React auth, can someone DM me?",
    "Looking for advice from an engineer about Appwrite cloud, DM me",
    "Looking for feedback from frontend devs on my AI app, message me",
    "Looking for someone who knows the Appwrite database API, can you DM me?",
    "Join us for the hackathon this weekend! Building with React + Appwrite cloud, DM me if you want to team up",
    "Join our Appwrite office hours, we'll cover the database and cloud functions. DM me questions",
    "Can you help us? Phone number login fails after GitHub OAuth",
    "I'm a developer, my portfolio site uses Appwrite, account recovery emails never arrive. Asked on discord too",
    "My team members can't access the database, DM me if you know why",
    "Giving away a Sony camera and lens. First-come, first-served. DM if interested.",
  ];

  for (const message of messages) {
    assert.equal(findSuspiciousText(message), null, message);
  }
});
