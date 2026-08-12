import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  PAD_TO_NOTE,
  parsePatchSetDocument,
  transmissionOrder,
  validateEditorSysEx,
} from "../public/sysex.mjs";

const root = fileURLToPath(new URL("../public/samples/fm-drum-kit/", import.meta.url));
const manifest = JSON.parse(await readFile(`${root}/manifest.json`, "utf8"));

async function loadSlots() {
  const slots = Array(16).fill(null);
  for (const item of manifest.patches) {
    const bytes = new Uint8Array(await readFile(`${root}/${item.file}`));
    slots[item.pad - 1] = { ...validateEditorSysEx(bytes), fileName: item.file };
  }
  return slots;
}

test("FM Drum manifest contains all 16 fixed Trigger Notes and identity-safe Original Playback", () => {
  assert.equal(manifest.patches.length, 16);
  assert.deepEqual(manifest.patches.map((item) => item.note), PAD_TO_NOTE);
  assert.deepEqual(manifest.patches.map((item) => item.playbackNote), Array(16).fill(null));
  assert.deepEqual(manifest.patches.map((item) => item.requestedPlaybackNote), Array.from({ length: 16 }, (_, i) => i + 36));
  assert.ok(manifest.patches.every((item) => item.source === "patches.fm"));
});

test("all FM Drum files are valid 163-byte Yamaha single-voice SysEx", async () => {
  const slots = await loadSlots();
  assert.equal(slots.filter(Boolean).length, 16);
  for (const slot of slots) {
    assert.equal(slot.bytes.length, 163);
    assert.match(slot.name, /\S/);
  }
});

test("FM Drum transmission keeps Trigger Notes and preserves slot identity", async () => {
  const queue = transmissionOrder(await loadSlots(), manifest.patches.map((item) => item.playbackNote), { encodePlayback: true });
  assert.deepEqual(queue.map((item) => item.note), Array.from({ length: 16 }, (_, i) => i + 36));
  assert.deepEqual(queue.map((item) => item.triggerNote), Array.from({ length: 16 }, (_, i) => i + 36));
  assert.deepEqual(queue.map((item) => item.playbackNote), Array.from({ length: 16 }, (_, i) => i + 36));
  assert.deepEqual(queue.map((item) => item.pad), [9, 10, 11, 12, 1, 2, 3, 4, 13, 14, 15, 16, 5, 6, 7, 8]);
});

test("FM Drum identity-safe patch-set JSON imports with Original Playback", async () => {
  const document = JSON.parse(await readFile(`${root}/FM-Drum-Kit-patches.fm.smkpatchset.json`, "utf8"));
  const parsed = parsePatchSetDocument(document);
  assert.equal(parsed.slots.length, 16);
  assert.deepEqual(parsed.playbackNotes, Array(16).fill(null));
});
