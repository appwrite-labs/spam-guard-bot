import { PaddleOcrService, V6_SMALL_MODEL } from "ppu-paddle-ocr";

export const OCR_EFFORTS = Object.freeze({
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
});

// Kept for configuration compatibility. PP-OCRv6 Small performs one complete
// detection + recognition pass, so it does not need Tesseract-style variants.
export const DEFAULT_OCR_EFFORT = OCR_EFFORTS.HIGH;

export function normalizeOcrEffort(effort) {
  if (typeof effort !== "string") {
    return DEFAULT_OCR_EFFORT;
  }

  const normalized = effort.trim().toLowerCase();

  if (normalized === OCR_EFFORTS.LOW) {
    return OCR_EFFORTS.LOW;
  }

  if (normalized === OCR_EFFORTS.MEDIUM) {
    return OCR_EFFORTS.MEDIUM;
  }

  if (normalized === OCR_EFFORTS.HIGH) {
    return OCR_EFFORTS.HIGH;
  }

  return DEFAULT_OCR_EFFORT;
}

function toArrayBuffer(image) {
  if (image instanceof ArrayBuffer) {
    return image;
  }

  if (ArrayBuffer.isView(image)) {
    return image.buffer.slice(
      image.byteOffset,
      image.byteOffset + image.byteLength,
    );
  }

  throw new TypeError("OCR input must be an ArrayBuffer or a typed array.");
}

export class OcrService {
  // Moderation uses this to avoid running the same PP-OCR model twice when
  // the first pass is negative.
  singlePass = true;

  #servicePromise;
  #queue = Promise.resolve();

  constructor() {}

  async recognize(image, options = {}) {
    const task = this.#queue.then(async () => {
      const service = await this.#getService();
      const result = await service.recognize(toArrayBuffer(image), {
        flatten: true,
      });
      const text = typeof result.text === "string" ? result.text : "";

      options.shouldStop?.(text);
      return text;
    });

    this.#queue = task.catch(() => undefined);
    return task;
  }

  async recognizeWithFallback(image, options = {}) {
    return this.recognize(image, options);
  }

  async terminate() {
    await this.#queue;

    if (this.#servicePromise) {
      const service = await this.#servicePromise;
      await service.destroy();
    }
  }

  #getService() {
    this.#servicePromise ??= Promise.resolve().then(async () => {
      const service = new PaddleOcrService({
        model: V6_SMALL_MODEL,
        // ONNX Runtime's memory pool keeps its peak allocation forever. Without
        // it the process returns memory between images: about 1.6 GB instead
        // of 3.1 GB after 160 images, at the same speed and accuracy.
        session: { enableCpuMemArena: false, enableMemPattern: false },
      });
      await service.initialize();
      return service;
    });

    return this.#servicePromise;
  }
}
