export const PACKET_SIZE = 163;
export const DATA_START = 6;
export const DATA_END = 161;
export const CHECKSUM_OFFSET = 161;
export const SMK_RUNTIME_FLAG = 0x3f;
export const HEADER = Uint8Array.from([0xf0, 0x43, 0x00, 0x00, 0x01, 0x1b]);
export const PAD_TO_NOTE = Object.freeze([40, 41, 42, 43, 48, 49, 50, 51, 36, 37, 38, 39, 44, 45, 46, 47]);
export const NOTE_TO_PAD = new Map(PAD_TO_NOTE.map((note, index) => [note, index + 1]));

export class SysExError extends Error {}

export function yamahaChecksum(bytes) {
  let sum = 0;
  for (let index = DATA_START; index < DATA_END; index += 1) sum += bytes[index];
  return (-sum) & 0x7f;
}

export function patchName(bytes) {
  return new TextDecoder("ascii").decode(bytes.slice(151, 161)).replace(/[\u0000-\u001f\u007f]/g, " ").trimEnd();
}

export function midiNoteName(note) {
  if (!Number.isInteger(note) || note < 0 || note > 127) throw new SysExError(`MIDI note must be 0..127, received ${note}`);
  const names = ["C", "C♯", "D", "D♯", "E", "F", "F♯", "G", "G♯", "A", "A♯", "B"];
  return `${names[note % 12]}${Math.floor(note / 12) - 1}`;
}

export function midiNoteOnFromMessage(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input ?? []);
  if (bytes.length < 3 || (bytes[0] & 0xf0) !== 0x90 || bytes[2] === 0) return null;
  return bytes[1] <= 127 ? bytes[1] : null;
}

export function validatePlaybackNotes(input = Array(16).fill(null)) {
  if (!Array.isArray(input) || input.length !== 16) throw new SysExError("16 Playback Note values are required");
  return input.map((note, index) => {
    if (note === null || note === undefined || note === "original") return null;
    const parsed = Number(note);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > 127) {
      throw new SysExError(`Pad ${index + 1} Playback Note must be Original or 0..127`);
    }
    return parsed;
  });
}

export function effectivePlaybackNote(playbackNotes, pad) {
  const validated = validatePlaybackNotes(playbackNotes);
  return validated[pad - 1] ?? PAD_TO_NOTE[pad - 1];
}

export function validateEditorSysEx(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length !== PACKET_SIZE) throw new SysExError(`163 bytes required, received ${bytes.length}`);
  if (bytes[0] !== 0xf0 || bytes[1] !== 0x43 || (bytes[2] & 0xf0) !== 0 || bytes[3] !== 0 || bytes[4] !== 1 || bytes[5] !== 0x1b) {
    throw new SysExError("Yamaha DX7 single-voice header F0 43 0n 00 01 1B required");
  }
  if (bytes.at(-1) !== 0xf7) throw new SysExError("F7 terminator required");
  for (let index = 1; index < bytes.length - 1; index += 1) {
    if (bytes[index] > 0x7f) throw new SysExError(`non-7-bit data at byte ${index}`);
  }
  const expected = yamahaChecksum(bytes);
  if (bytes[CHECKSUM_OFFSET] !== expected) {
    throw new SysExError(`checksum mismatch: stored 0x${bytes[CHECKSUM_OFFSET].toString(16).padStart(2, "0")}, expected 0x${expected.toString(16).padStart(2, "0")}`);
  }
  return {
    bytes: Uint8Array.from(bytes),
    name: patchName(bytes),
    checksum: expected,
    channel: bytes[2] & 0x0f,
  };
}

export function toSmkRuntimePacket(editorBytes, transportByte = SMK_RUNTIME_FLAG) {
  const { bytes } = validateEditorSysEx(editorBytes);
  if (!Number.isInteger(transportByte) || transportByte < 0 || transportByte > 127) {
    throw new SysExError(`SMK transport byte must be 0..127, received ${transportByte}`);
  }
  const runtime = Uint8Array.from(bytes);
  runtime[CHECKSUM_OFFSET] = transportByte;
  return runtime;
}

export function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function createPatchSetDocument(slots, title = "Untitled Patch Set", playbackNotes = Array(16).fill(null)) {
  if (slots.length !== 16 || slots.some((slot) => !slot)) throw new SysExError("all 16 Pads must contain a valid patch");
  const validatedPlaybackNotes = validatePlaybackNotes(playbackNotes);
  return {
    format: "smk37-v15-s1c3-web-patch-set-v2",
    title,
    createdAt: new Date().toISOString(),
    physicalPadNoteSequence: PAD_TO_NOTE,
    playbackNotes: validatedPlaybackNotes,
    patches: slots.map((slot, index) => ({
      pad: index + 1,
      note: PAD_TO_NOTE[index],
      playbackNote: validatedPlaybackNotes[index],
      name: slot.name,
      sourceFile: slot.fileName,
      syxBase64: bytesToBase64(slot.bytes),
    })),
  };
}

export function parsePatchSetDocument(document) {
  const supported = document?.format === "smk37-v15-s1c3-web-patch-set-v1" || document?.format === "smk37-v15-s1c3-web-patch-set-v2" || document?.format === "smk37-v15-s1c5-identity-safe-patch-set-v1";
  if (!supported || !Array.isArray(document.patches) || document.patches.length !== 16) {
    throw new SysExError("unsupported or incomplete patch-set document");
  }
  const embeddedPlaybackNotes = document.patches.map((item) => item.playbackNote ?? null);
  const playbackNotes = validatePlaybackNotes(document.playbackNotes ?? embeddedPlaybackNotes);
  const slots = Array(16).fill(null);
  for (const item of document.patches) {
    if (!Number.isInteger(item.pad) || item.pad < 1 || item.pad > 16 || item.note !== PAD_TO_NOTE[item.pad - 1]) {
      throw new SysExError("patch-set Pad/note mapping mismatch");
    }
    const parsed = validateEditorSysEx(base64ToBytes(item.syxBase64));
    slots[item.pad - 1] = { ...parsed, fileName: item.sourceFile || `pad${String(item.pad).padStart(2, "0")}.syx` };
  }
  if (slots.some((slot) => !slot)) throw new SysExError("patch-set has duplicate or missing Pads");
  return { title: String(document.title || "Imported Patch Set"), slots, playbackNotes };
}

export function transmissionOrder(slots, playbackNotes = Array(16).fill(null), options = {}) {
  if (slots.length !== 16 || slots.some((slot) => !slot)) throw new SysExError("all 16 Pads are required before transmission");
  const validatedPlaybackNotes = validatePlaybackNotes(playbackNotes);
  return Array.from({ length: 16 }, (_, slot) => {
    const note = slot + 36;
    const pad = NOTE_TO_PAD.get(note);
    const patch = slots[pad - 1];
    const playbackNote = validatedPlaybackNotes[pad - 1] ?? note;
    return {
      order: slot + 1,
      slot,
      note,
      triggerNote: note,
      playbackNote,
      pad,
      name: patch.name,
      bytes: toSmkRuntimePacket(patch.bytes, options.encodePlayback ? playbackNote : SMK_RUNTIME_FLAG),
    };
  });
}
