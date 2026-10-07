import { fileURLToPath } from "node:url";
import { VISUAL_REFERENCE_MANIFEST_PATH } from "../src/config.js";
import { writeVisualReferenceManifest } from "../src/visual-matching.js";

const referencePath = fileURLToPath(new URL("../visual-references", import.meta.url));

const manifest = await writeVisualReferenceManifest(
  referencePath,
  VISUAL_REFERENCE_MANIFEST_PATH,
);

console.log(
  `[Visual matching] Wrote ${manifest.references.length} reference hash(es) to ${VISUAL_REFERENCE_MANIFEST_PATH}.`,
);
