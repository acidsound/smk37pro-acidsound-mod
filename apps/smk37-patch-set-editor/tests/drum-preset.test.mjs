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

test("FM Drum manifest contains all 16 fixed Trigger Notes and explicit requested-map Playback", () => {
  assert.equal(manifest.patches.length, 16);
  assert.deepEqual(manifest.patches.map((item) => item.note), PAD_TO_NOTE);
  assert.deepEqual(manifest.patches.map((item) => item.playbackNote), Array.from({ length: 16 }, (_, i) => i + 36));
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

test("FM Drum transmission keeps Trigger Notes and sends explicit requested-map Playback", async () => {
  const queue = transmissionOrder(await loadSlots(), manifest.patches.map((item) => item.playbackNote), { encodePlayback: true });
  assert.deepEqual(queue.map((item) => item.note), Array.from({ length: 16 }, (_, i) => i + 36));
  assert.deepEqual(queue.map((item) => item.triggerNote), Array.from({ length: 16 }, (_, i) => i + 36));
  // transmission order is note 36..51 -> pad -> playbackNotes[pad - 1]; with the explicit
  // requested map this is the pad-ordered permutation [44,45,46,47,36,37,38,39,48,49,50,51,40,41,42,43]
  // (identical to the byte-161 values live-verified on S1C6 via direct USB).
  assert.deepEqual(queue.map((item) => item.playbackNote), [44, 45, 46, 47, 36, 37, 38, 39, 48, 49, 50, 51, 40, 41, 42, 43]);
  assert.deepEqual(queue.map((item) => item.pad), [9, 10, 11, 12, 1, 2, 3, 4, 13, 14, 15, 16, 5, 6, 7, 8]);
});

test("FM Drum S1C6 explicit-playback patch-set JSON imports with requested map (36..51)", async () => {
  const document = JSON.parse(await readFile(`${root}/FM-Drum-Kit-patches.fm.smkpatchset.json`, "utf8"));
  assert.equal(document.format, "smk37-v15-s1c6-explicit-playback-patch-set-v1");
  const parsed = parsePatchSetDocument(document);
  assert.equal(parsed.slots.length, 16);
  assert.deepEqual(parsed.playbackNotes, Array.from({ length: 16 }, (_, i) => i + 36));
});
