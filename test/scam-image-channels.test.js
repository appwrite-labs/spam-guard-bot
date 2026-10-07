import test from "node:test";
import assert from "node:assert/strict";
import {
  findKnownScamImageChannel,
  getDiscordAttachmentChannelId,
  SCAM_IMAGE_CHANNELS,
} from "../src/scam-image-channels.js";

const TEST_CHANNELS = [{ channelId: "111111111111111111", name: "Test scam channel" }];

test("extracts a Discord attachment source channel", () => {
  const url =
    "https://media.discordapp.net/attachments/111111111111111111/1540534318554677288/image.jpg?format=webp";

  assert.equal(getDiscordAttachmentChannelId(url), "111111111111111111");
  assert.equal(findKnownScamImageChannel(url, TEST_CHANNELS)?.channelId, "111111111111111111");
});

test("extracts the channel from an encoded attachment URL inside a Discord proxy URL", () => {
  const url =
    "https://images-ext-1.discordapp.net/external/hash/hash/https%3A%2F%2Fcdn.discordapp.com%2Fattachments%2F111111111111111111%2F1540534318554677288%2Fimage.jpg";

  assert.equal(getDiscordAttachmentChannelId(url), "111111111111111111");
  assert.equal(findKnownScamImageChannel(url, TEST_CHANNELS)?.channelId, "111111111111111111");
});

test("does not flag an unknown or non-attachment URL", () => {
  assert.equal(
    findKnownScamImageChannel(
      "https://media.discordapp.net/attachments/123456789012345678/1540534318554677288/image.jpg",
      TEST_CHANNELS,
    ),
    null,
  );
  assert.equal(
    findKnownScamImageChannel("https://example.com/attachments/111111111111111111/image.jpg", TEST_CHANNELS),
    null,
  );
});

test("loads the known-channel list from scam-image-channels.json", () => {
  assert.ok(Array.isArray(SCAM_IMAGE_CHANNELS));
  for (const channel of SCAM_IMAGE_CHANNELS) {
    assert.match(channel.channelId, /^\d{17,20}$/u);
  }
});
