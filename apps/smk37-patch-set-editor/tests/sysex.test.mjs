import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  CHECKSUM_OFFSET,
  PAD_TO_NOTE,
  RESET_PACKET,
  SMK_RUNTIME_FLAG,
  createPatchSetDocument,
  effectivePlaybackNote,
  midiNoteName,
  midiNoteOnFromMessage,
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

test("S1-C6 reset packet framing and impossible signature", () => {
  assert.equal(RESET_PACKET.length, 163);
  assert.deepEqual([...RESET_PACKET.slice(0, 6)], [0xf0, 0x43, 0x00, 0x00, 0x01, 0x1b]);
  assert.equal(RESET_PACKET[6], 0x64);
  assert.equal(RESET_PACKET[7], 0x65);
  assert.equal(RESET_PACKET[161], 0x00);
  assert.equal(RESET_PACKET[162], 0xf7);
  for (let index = 1; index < RESET_PACKET.length - 1; index += 1) assert.ok(RESET_PACKET[index] <= 0x7f, "all SysEx data bytes are 7-bit");
  // The reset packet is a firmware control packet, not a voice: the fixed
  // byte 161 (0x00) is never a valid Yamaha checksum, so the voice validator
  // must reject it.
  assert.throws(() => validateEditorSysEx(RESET_PACKET), /checksum/);
});

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
  const playbackNotes = Array(16).fill(60);
  playbackNotes[0] = null;
  playbackNotes[15] = 36;
  const document = createPatchSetDocument(slots, "Round Trip", playbackNotes);
  const restored = parsePatchSetDocument(JSON.parse(JSON.stringify(document)));
  assert.equal(restored.title, "Round Trip");
  assert.deepEqual(restored.playbackNotes, playbackNotes);
  for (let index = 0; index < 16; index += 1) {
    assert.equal(restored.slots[index].name, slots[index].name);
    assert.deepEqual(restored.slots[index].bytes, slots[index].bytes);
  }
});

test("Playback Note changes never alter Trigger Note mapping", async () => {
  const slots = await loadSlots();
  const playbackNotes = Array(16).fill(60);
  const queue = transmissionOrder(slots, playbackNotes);
  assert.deepEqual(queue.map((item) => item.triggerNote), Array.from({ length: 16 }, (_, index) => index + 36));
  assert.deepEqual(queue.map((item) => item.playbackNote), Array(16).fill(60));
  assert.equal(effectivePlaybackNote(Array(16).fill(null), 1), 40);
  assert.equal(effectivePlaybackNote(playbackNotes, 1), 60);
  assert.equal(midiNoteName(60), "C4");
});

test("MIDI Learn accepts Note On only and ignores release messages", () => {
  assert.equal(midiNoteOnFromMessage(Uint8Array.from([0x90, 60, 100])), 60);
  assert.equal(midiNoteOnFromMessage(Uint8Array.from([0x99, 36, 1])), 36);
  assert.equal(midiNoteOnFromMessage(Uint8Array.from([0x90, 60, 0])), null);
  assert.equal(midiNoteOnFromMessage(Uint8Array.from([0x80, 60, 64])), null);
  assert.equal(midiNoteOnFromMessage(Uint8Array.from([0xb0, 1, 127])), null);
});

test("S1-C3 keeps 0x3f while S1-C4 encodes Playback Note in each patch packet", async () => {
  const slots = await loadSlots();
  const playbackNotes = Array(16).fill(60);
  const legacyQueue = transmissionOrder(slots, playbackNotes);
  const playbackQueue = transmissionOrder(slots, playbackNotes, { encodePlayback: true });
  assert.deepEqual(legacyQueue.map((item) => item.bytes[CHECKSUM_OFFSET]), Array(16).fill(SMK_RUNTIME_FLAG));
  assert.deepEqual(playbackQueue.map((item) => item.bytes[CHECKSUM_OFFSET]), Array(16).fill(60));
  assert.deepEqual(playbackQueue.map((item) => item.triggerNote), legacyQueue.map((item) => item.triggerNote));
});

test("v1 patch-set imports with Original Playback Notes", async () => {
  const slots = await loadSlots();
  const legacy = createPatchSetDocument(slots, "Legacy");
  legacy.format = "smk37-v15-s1c3-web-patch-set-v1";
  delete legacy.playbackNotes;
  for (const patch of legacy.patches) delete patch.playbackNote;
  assert.deepEqual(parsePatchSetDocument(legacy).playbackNotes, Array(16).fill(null));
});

test("checksum corruption is rejected", async () => {
  const [slot] = await loadSlots();
  const corrupt = Uint8Array.from(slot.bytes);
  corrupt[20] ^= 1;
  assert.throws(() => validateEditorSysEx(corrupt), /checksum mismatch/);
});
