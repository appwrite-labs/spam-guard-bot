import test from "node:test";
import assert from "node:assert/strict";
import sharp from "sharp";
import {
  assertSafeImageDimensions,
  getMessageImageSources,
  isTrustedImageUrl,
} from "../src/images.js";

test("extracts image attachments", () => {
  const message = {
    attachments: new Map([
      [
        "attachment-1",
        {
          id: "attachment-1",
          name: "proof.png",
          contentType: "image/png",
          size: 1234,
          url: "https://cdn.discordapp.com/attachments/proof.png",
        },
      ],
    ]),
    embeds: [],
  };

  assert.deepEqual(getMessageImageSources(message), [
    {
      url: "https://cdn.discordapp.com/attachments/proof.png",
      label: "proof.png",
      size: 1234,
      forwarded: false,
    },
  ]);
});

test("extracts images and thumbnails from link embeds", () => {
  const message = {
    attachments: new Map(),
    embeds: [
      {
        url: "https://example.com/post",
        image: {
          url: "https://example.com/image.png",
          proxyURL: "https://media.discordapp.net/image.png",
        },
        thumbnail: {
          url: "https://example.com/thumb.png",
          proxyURL: "https://media.discordapp.net/thumb.png",
        },
      },
    ],
  };

  assert.deepEqual(getMessageImageSources(message), [
    {
      url: "https://media.discordapp.net/image.png",
      label: "https://example.com/post",
      size: null,
      forwarded: false,
    },
    {
      url: "https://media.discordapp.net/thumb.png",
      label: "https://example.com/post",
      size: null,
      forwarded: false,
    },
  ]);
});

test("recognizes forwarded image attachments with only dimensions", () => {
  const forwardedMessage = {
    attachments: new Map([
      ["forwarded-photo", {
        id: "forwarded-photo",
        name: "photo",
        contentType: null,
        size: 100,
        width: 1200,
        height: 800,
        url: "https://cdn.discordapp.com/attachments/forwarded/photo",
      }],
    ]),
    embeds: [],
    messageSnapshots: new Map(),
  };

  const message = {
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map([["snapshot", forwardedMessage]]),
  };

  assert.equal(getMessageImageSources(message)[0].forwarded, true);
});

test("keeps trusted alternate URLs for proxied images", () => {
  const message = {
    attachments: new Map(),
    embeds: [
      {
        image: {
          url: "https://cdn.discordapp.com/attachments/111111111111111111/123456789012345678/scam.png",
          proxyURL: "https://images-ext-1.discordapp.net/external/proxy/scam.png",
        },
      },
    ],
  };

  assert.deepEqual(getMessageImageSources(message), [
    {
      url: "https://images-ext-1.discordapp.net/external/proxy/scam.png",
      label: "https://cdn.discordapp.com/attachments/111111111111111111/123456789012345678/scam.png",
      size: null,
      forwarded: false,
      alternateUrls: [
        "https://cdn.discordapp.com/attachments/111111111111111111/123456789012345678/scam.png",
      ],
    },
  ]);
});

test("deduplicates repeated image URLs", () => {
  const message = {
    attachments: new Map(),
    embeds: [
      {
        image: {
          url: "https://example.com/image.png",
          proxyURL: "https://media.discordapp.net/image.png",
        },
        thumbnail: {
          url: "https://example.com/image.png",
          proxyURL: "https://media.discordapp.net/image.png",
        },
      },
    ],
  };

  assert.equal(getMessageImageSources(message).length, 1);
});

test("extracts all images from forwarded message snapshots", () => {
  const forwardedMessage = {
    attachments: new Map([
      [
        "forwarded-1",
        {
          id: "forwarded-1",
          name: "first.png",
          contentType: "image/png",
          size: 100,
          url: "https://cdn.discordapp.com/attachments/first.png",
        },
      ],
      [
        "forwarded-2",
        {
          id: "forwarded-2",
          name: "second.png",
          contentType: "image/png",
          size: 200,
          url: "https://cdn.discordapp.com/attachments/second.png",
        },
      ],
    ]),
    embeds: [
      {
        image: {
          url: "https://example.com/forwarded-embed.png",
          proxyURL: "https://images-ext-1.discordapp.net/external/forwarded-embed.png",
        },
      },
    ],
    messageSnapshots: new Map(),
  };
  const message = {
    attachments: new Map(),
    embeds: [],
    messageSnapshots: new Map([["snapshot-1", forwardedMessage]]),
  };

  assert.deepEqual(getMessageImageSources(message), [
    {
      url: "https://cdn.discordapp.com/attachments/first.png",
      label: "Forwarded: first.png",
      size: 100,
      forwarded: true,
    },
    {
      url: "https://cdn.discordapp.com/attachments/second.png",
      label: "Forwarded: second.png",
      size: 200,
      forwarded: true,
    },
    {
      url: "https://images-ext-1.discordapp.net/external/forwarded-embed.png",
      label: "Forwarded: https://example.com/forwarded-embed.png",
      size: null,
      forwarded: true,
    },
  ]);
});

test("extracts every image from a multi-image message", () => {
  const message = {
    attachments: new Map([
      [
        "image-1",
        {
          id: "image-1",
          name: "safe.png",
          contentType: "image/png",
          size: 100,
          url: "https://cdn.discordapp.com/attachments/safe.png",
        },
      ],
      [
        "image-2",
        {
          id: "image-2",
          name: "matching.png",
          contentType: "image/png",
          size: 200,
          url: "https://cdn.discordapp.com/attachments/matching.png",
        },
      ],
      [
        "image-3",
        {
          id: "image-3",
          name: "other.png",
          contentType: "image/png",
          size: 300,
          url: "https://cdn.discordapp.com/attachments/other.png",
        },
      ],
    ]),
    embeds: [],
    messageSnapshots: new Map(),
  };

  assert.deepEqual(
    getMessageImageSources(message).map((source) => source.url),
    [
      "https://cdn.discordapp.com/attachments/safe.png",
      "https://cdn.discordapp.com/attachments/matching.png",
      "https://cdn.discordapp.com/attachments/other.png",
    ],
  );
});

test("skips untrusted image URLs that are not proxied by Discord", () => {
  const message = {
    attachments: new Map([
      [
        "attachment-1",
        {
          id: "attachment-1",
          name: "proof.png",
          contentType: "image/png",
          size: 1234,
          url: "https://example.com/proof.png",
        },
      ],
    ]),
    embeds: [
      {
        image: {
          url: "https://example.com/image.png",
        },
      },
    ],
  };

  assert.deepEqual(getMessageImageSources(message), []);
});

test("recognizes only trusted Discord image hosts", () => {
  assert.equal(
    isTrustedImageUrl("https://cdn.discordapp.com/attachments/proof.png"),
    true,
  );
  assert.equal(
    isTrustedImageUrl("https://media.discordapp.net/attachments/proof.png"),
    true,
  );
  assert.equal(
    isTrustedImageUrl("https://images-ext-2.discordapp.net/external/proof.png"),
    true,
  );
  assert.equal(isTrustedImageUrl("http://cdn.discordapp.com/proof.png"), false);
  assert.equal(isTrustedImageUrl("https://example.com/proof.png"), false);
});

test("rejects images above the configured pixel limit", async () => {
  const image = await sharp({
    create: {
      width: 4,
      height: 4,
      channels: 3,
      background: "#ffffff",
    },
  })
    .png()
    .toBuffer();

  await assert.rejects(
    assertSafeImageDimensions(image, 15),
    /dimensions exceed/,
  );
});
