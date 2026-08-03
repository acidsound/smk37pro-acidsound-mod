import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  CHECKSUM_OFFSET,
  PAD_TO_NOTE,
  SMK_RUNTIME_FLAG,
  createPatchSetDocument,
  parsePatchSetDocument,
  patchName,
  toSmkRuntimePacket,
  transmissionOrder,
  validateEditorSysEx,
  yamahaChecksum,
} from "../public/sysex.mjs";

const sampleRoot = fileURLToPath(new URL("../public/samples/bank-d-demo/", import.meta.url));
const manifest = JSON.parse(await readFile(`${sampleRoot}/manifest.json`, "utf8"));

async function loadSlots() {
  const slots = Array(16).fill(null);
  for (const item of manifest.patches) {
    const bytes = new Uint8Array(await readFile(`${sampleRoot}/${item.file}`));
    slots[item.pad - 1] = { ...validateEditorSysEx(bytes), fileName: item.file };
  }
  return slots;
}

test("all 16 sample files are valid editor SysEx", async () => {
  const slots = await loadSlots();
  assert.equal(slots.filter(Boolean).length, 16);
  for (const slot of slots) {
    assert.equal(slot.bytes.length, 163);
    assert.equal(slot.bytes[CHECKSUM_OFFSET], yamahaChecksum(slot.bytes));
    assert.equal(slot.name, patchName(slot.bytes));
  }
});

test("editor SysEx converts to SMK runtime flag without changing voice data", async () => {
  const [slot] = await loadSlots();
  const runtime = toSmkRuntimePacket(slot.bytes);
  assert.equal(runtime[CHECKSUM_OFFSET], SMK_RUNTIME_FLAG);
  assert.deepEqual(runtime.slice(0, CHECKSUM_OFFSET), slot.bytes.slice(0, CHECKSUM_OFFSET));
  assert.equal(runtime.at(-1), 0xf7);
});

test("transmission order is note 36..51 and maps to physical Pads", async () => {
  const queue = transmissionOrder(await loadSlots());
  assert.deepEqual(queue.map((item) => item.note), Array.from({ length: 16 }, (_, index) => index + 36));
  assert.deepEqual(queue.map((item) => item.pad), [9, 10, 11, 12, 1, 2, 3, 4, 13, 14, 15, 16, 5, 6, 7, 8]);
  assert.deepEqual(PAD_TO_NOTE, [40, 41, 42, 43, 48, 49, 50, 51, 36, 37, 38, 39, 44, 45, 46, 47]);
});

test("patch-set JSON round-trips all slots", async () => {
  const slots = await loadSlots();
  const document = createPatchSetDocument(slots, "Round Trip");
  const restored = parsePatchSetDocument(JSON.parse(JSON.stringify(document)));
  assert.equal(restored.title, "Round Trip");
  for (let index = 0; index < 16; index += 1) {
    assert.equal(restored.slots[index].name, slots[index].name);
    assert.deepEqual(restored.slots[index].bytes, slots[index].bytes);
  }
});

test("checksum corruption is rejected", async () => {
  const [slot] = await loadSlots();
  const corrupt = Uint8Array.from(slot.bytes);
  corrupt[20] ^= 1;
  assert.throws(() => validateEditorSysEx(corrupt), /checksum mismatch/);
});
