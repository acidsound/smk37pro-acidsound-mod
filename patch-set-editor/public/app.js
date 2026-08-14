import {
  PAD_TO_NOTE,
  RESET_PACKET,
  createPatchSetDocument,
  midiNoteName,
  midiNoteOnFromMessage,
  parsePatchSetDocument,
  transmissionOrder,
  validateEditorSysEx,
} from "./sysex.mjs";

const slots = Array(16).fill(null);
const playbackNotes = Array(16).fill(null);
let midiAccess = null;
let midiDevices = new Map();
let sending = false;
let focusedPadIndex = null;
const padElements = [];

function portDetails(port) {
  if (!port) return null;
  return {
    id: port.id,
    name: port.name,
    manufacturer: port.manufacturer,
    type: port.type,
    state: port.state,
    connection: port.connection,
  };
}

function diagnose(event, detail = {}) {
  fetch("/__diagnostics", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ at: new Date().toISOString(), event, detail }),
    keepalive: true,
  }).catch(() => {});
}

const elements = {
  grid: document.querySelector("#pad-grid"),
  template: document.querySelector("#pad-template"),
  title: document.querySelector("#set-title"),
  validCount: document.querySelector("#valid-count"),
  setState: document.querySelector("#set-state"),
  connect: document.querySelector("#connect-midi"),
  midiState: document.querySelector("#midi-state"),
  midiLearnState: document.querySelector("#midi-learn-state"),
  device: document.querySelector("#midi-device"),
  send: document.querySelector("#send-all"),
  progress: document.querySelector("#send-progress"),
  log: document.querySelector("#activity-log"),
  filePicker: document.querySelector("#file-picker"),
  setPicker: document.querySelector("#set-picker"),
};

function log(message, level = "INFO") {
  const timestamp = new Date().toLocaleTimeString();
  elements.log.textContent += `\n[${timestamp}] ${level} ${message}`;
  elements.log.scrollTop = elements.log.scrollHeight;
}

function download(name, bytes, type = "application/octet-stream") {
  const blob = new Blob([bytes], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function updateHealth() {
  const count = slots.filter(Boolean).length;
  elements.validCount.textContent = `${count} / 16`;
  elements.setState.textContent = count === 16 ? "전송 준비 완료" : `${16 - count}개 Pad가 비어 있습니다`;
  elements.send.disabled = sending || count !== 16 || !selectedOutput();
}

function renderPad(index, error = "") {
  const card = padElements[index];
  const slot = slots[index];
  card.classList.toggle("loaded", Boolean(slot));
  card.classList.toggle("error", Boolean(error));
  card.querySelector(".patch-name").textContent = error || slot?.name || "Empty";
  card.querySelector(".patch-file").textContent = slot?.fileName || "Drop a 163-byte .syx";
  card.querySelector(".playback-note").value = playbackNotes[index] === null ? "" : String(playbackNotes[index]);
  card.querySelector(".download-patch").disabled = !slot;
  card.querySelector(".clear-patch").disabled = !slot;
  updateHealth();
}

function focusPad(index) {
  focusedPadIndex = index;
  padElements.forEach((card, cardIndex) => card.classList.toggle("midi-learn-focus", cardIndex === index));
  const pad = index + 1;
  elements.midiLearnState.textContent = `MIDI Learn 대상: Pad ${pad} · Note를 입력하세요`;
}

function clearFocusedPad() {
  focusedPadIndex = null;
  padElements.forEach((card) => card.classList.remove("midi-learn-focus"));
  elements.midiLearnState.textContent = selectedInput()
    ? "Playback Note를 선택한 뒤 MIDI Note를 입력하세요"
    : "MIDI Input을 선택하세요";
}

function applyLearnedNote(note) {
  if (focusedPadIndex === null) return;
  playbackNotes[focusedPadIndex] = note;
  renderPad(focusedPadIndex);
  const pad = focusedPadIndex + 1;
  log(`Pad ${String(pad).padStart(2, "0")} Playback Note ← MIDI IN ${midiNoteName(note)} (${note})`, "PASS");
}

function handleMidiMessage(event) {
  const note = midiNoteOnFromMessage(event.data);
  if (note !== null) applyLearnedNote(note);
}

async function loadFileIntoPad(file, pad) {
  try {
    const parsed = validateEditorSysEx(new Uint8Array(await file.arrayBuffer()));
    slots[pad - 1] = { ...parsed, fileName: file.name };
    renderPad(pad - 1);
    log(`Pad ${String(pad).padStart(2, "0")} ← ${parsed.name || "Unnamed"} (${file.name})`);
  } catch (error) {
    renderPad(pad - 1);
    log(`Pad ${pad}: ${error.message}`, "ERROR");
  }
}

function inferPad(fileName) {
  const match = /^pad(0[1-9]|1[0-6])-/i.exec(fileName);
  return match ? Number.parseInt(match[1], 10) : null;
}

async function loadMany(files) {
  const unassigned = [];
  for (const file of files) {
    const pad = inferPad(file.name);
    if (pad) await loadFileIntoPad(file, pad);
    else unassigned.push(file);
  }
  const emptyPads = slots.map((slot, index) => slot ? null : index + 1).filter(Boolean);
  for (let index = 0; index < unassigned.length; index += 1) {
    if (!emptyPads[index]) {
      log(`${unassigned[index].name}: 배치할 빈 Pad가 없습니다`, "ERROR");
      continue;
    }
    await loadFileIntoPad(unassigned[index], emptyPads[index]);
  }
}

function buildPads() {
  for (let index = 0; index < 16; index += 1) {
    const pad = index + 1;
    const fragment = elements.template.content.cloneNode(true);
    const card = fragment.querySelector(".pad");
    card.dataset.pad = String(pad);
    card.querySelector(".pad-number").textContent = `PAD ${pad}`;
    card.querySelector(".pad-note").textContent = `NOTE ${midiNoteName(PAD_TO_NOTE[index])}/${PAD_TO_NOTE[index]}`;
    const playbackSelect = card.querySelector(".playback-note");
    playbackSelect.add(new Option(`* ${midiNoteName(PAD_TO_NOTE[index])}/${PAD_TO_NOTE[index]}`, ""));
    for (let note = 0; note <= 127; note += 1) {
      playbackSelect.add(new Option(`${midiNoteName(note)}/${note}`, String(note)));
    }
    playbackSelect.addEventListener("change", () => {
      playbackNotes[index] = playbackSelect.value === "" ? null : Number(playbackSelect.value);
      const effective = playbackNotes[index] ?? PAD_TO_NOTE[index];
      log(`Pad ${String(pad).padStart(2, "0")} Playback Note → ${midiNoteName(effective)} (${effective})${playbackNotes[index] === null ? " · Original" : ""}`);
    });
    card.addEventListener("focusin", () => focusPad(index));
    card.addEventListener("pointerdown", () => focusPad(index));
    const input = card.querySelector(".pad-file-input");
    card.querySelector(".choose-patch").addEventListener("click", () => input.click());
    input.addEventListener("change", () => input.files?.[0] && loadFileIntoPad(input.files[0], pad));
    card.querySelector(".clear-patch").addEventListener("click", () => {
      slots[index] = null;
      renderPad(index);
    });
    card.querySelector(".download-patch").addEventListener("click", () => {
      const slot = slots[index];
      if (slot) download(slot.fileName || `pad${String(pad).padStart(2, "0")}.syx`, slot.bytes);
    });
    for (const eventName of ["dragenter", "dragover"]) {
      card.addEventListener(eventName, (event) => { event.preventDefault(); card.classList.add("drag-over"); });
    }
    for (const eventName of ["dragleave", "drop"]) {
      card.addEventListener(eventName, (event) => { event.preventDefault(); card.classList.remove("drag-over"); });
    }
    card.addEventListener("drop", (event) => event.dataTransfer?.files?.[0] && loadFileIntoPad(event.dataTransfer.files[0], pad));
    elements.grid.append(fragment);
    padElements.push(elements.grid.lastElementChild);
  }
}

function refreshMidiPorts() {
  const previous = elements.device.value;
  const outputs = midiAccess ? [...midiAccess.outputs.values()] : [];
  const inputs = midiAccess ? [...midiAccess.inputs.values()] : [];
  midiDevices = new Map();
  const addPort = (port, kind) => {
    const name = port.name || "Unnamed";
    const manufacturer = port.manufacturer || "Unknown";
    const key = `${manufacturer}\u0000${name}`.toLowerCase();
    const device = midiDevices.get(key) || { key, name, manufacturer, input: null, output: null };
    if (!device[kind]) device[kind] = port;
    midiDevices.set(key, device);
  };
  inputs.forEach((input) => addPort(input, "input"));
  outputs.forEach((output) => addPort(output, "output"));

  elements.device.replaceChildren();
  if (midiDevices.size === 0) {
    elements.device.add(new Option("SMK MIDI 장치 없음", ""));
    elements.device.disabled = true;
  } else {
    for (const device of midiDevices.values()) {
      const suffix = device.input && device.output ? "" : device.input ? " · Input only" : " · Output only";
      elements.device.add(new Option(`${device.name} · ${device.manufacturer}${suffix}`, device.key));
    }
    elements.device.disabled = false;
    if (midiDevices.has(previous)) elements.device.value = previous;
    else {
      const preferred = [...midiDevices.values()].find((device) => /SMK|M-VAVE/i.test(`${device.name} ${device.manufacturer}`));
      elements.device.value = (preferred || midiDevices.values().next().value).key;
    }
  }
  bindSelectedDevice();
  diagnose("midi-ports", {
    selectedKey: elements.device.value,
    selectedInput: portDetails(selectedInput()),
    selectedOutput: portDetails(selectedOutput()),
    inputs: inputs.map(portDetails),
    outputs: outputs.map(portDetails),
  });
  const connected = midiDevices.size > 0;
  elements.midiState.textContent = connected ? `${midiDevices.size}개 MIDI 장치 사용 가능` : "MIDI 장치 없음";
  elements.midiState.classList.toggle("connected", connected);
  updateHealth();
}

function bindSelectedDevice() {
  if (!midiAccess) return;
  for (const input of midiAccess.inputs.values()) input.onmidimessage = null;
  const input = selectedInput();
  if (input) {
    input.onmidimessage = handleMidiMessage;
    elements.midiLearnState.textContent = focusedPadIndex === null
      ? "Playback Note를 선택한 뒤 MIDI Note를 입력하세요"
      : `MIDI Learn 대상: Pad ${focusedPadIndex + 1} · Note를 입력하세요`;
  } else {
    elements.midiLearnState.textContent = "MIDI Input을 선택하세요";
  }
}

function selectedOutput() {
  return midiDevices.get(elements.device.value)?.output || null;
}

function selectedInput() {
  return midiDevices.get(elements.device.value)?.input || null;
}

async function reopenSelectedDevice() {
  const selectedKey = elements.device.value;
  refreshMidiPorts();
  if (selectedKey && midiDevices.has(selectedKey)) elements.device.value = selectedKey;
  bindSelectedDevice();

  const output = selectedOutput();
  if (!output) throw new Error("SMK MIDI Output을 다시 연결하세요");
  if (output.state === "disconnected") throw new Error("SMK MIDI 장치가 연결 해제 상태입니다");
  await output.open();
  if (output.connection !== "open") throw new Error("SMK MIDI Output을 열 수 없습니다");
  diagnose("midi-output-open", { output: portDetails(output) });

  const input = selectedInput();
  if (input && input.state !== "disconnected") {
    await input.open();
    input.onmidimessage = handleMidiMessage;
  }
  return output;
}

async function connectMidi() {
  if (!("requestMIDIAccess" in navigator)) {
    log("이 브라우저는 Web MIDI를 지원하지 않습니다. Desktop Chrome을 사용하세요.", "ERROR");
    return;
  }
  elements.connect.disabled = true;
  elements.connect.textContent = "연결 중…";
  elements.midiState.textContent = "MIDI 권한 확인 중";
  try {
    midiAccess = await navigator.requestMIDIAccess({ sysex: true });
    midiAccess.onstatechange = refreshMidiPorts;
    refreshMidiPorts();
    log("Web MIDI SysEx 권한이 허용되었습니다.");
    diagnose("midi-connected");
  } catch (error) {
    elements.midiState.textContent = "MIDI 연결 실패";
    elements.midiState.classList.remove("connected");
    log(`Web MIDI 연결 실패: ${error.message}`, "ERROR");
    diagnose("midi-connect-error", { name: error.name, message: error.message });
  } finally {
    elements.connect.disabled = false;
    elements.connect.textContent = midiAccess ? "Web MIDI 재연결" : "Web MIDI 연결";
  }
}

async function sendAll() {
  if (sending) return;
  try {
    const output = await reopenSelectedDevice();
    const queue = transmissionOrder(slots, playbackNotes, { encodePlayback: true });
    diagnose("send-start", {
      output: portDetails(output),
      packets: queue.map((item) => ({
        order: item.order,
        pad: item.pad,
        triggerNote: item.triggerNote,
        playbackNote: item.playbackNote,
        length: item.bytes.length,
        header: [...item.bytes.slice(0, 6)],
        transportByte: item.bytes[161],
        terminator: item.bytes[162],
      })),
    });
    log("재부팅/펌웨어 업데이트 후 지워진 휘발성 Patch Set을 다시 전송합니다.");
    log("각 patch packet에 Playback Note를 함께 전송합니다.");
    log("S1-C6 프로토콜: 먼저 리셋 패킷 1개를 보낸 뒤 patch 16개를 전송합니다.");
    sending = true;
    elements.progress.value = 0;
    updateHealth();
    log(`${output.name}: 리셋 패킷 1개 + patch 16개 전송 시작`);
    output.send(RESET_PACKET);
    diagnose("reset-packet-sent", {
      output: portDetails(output),
      wireBytes67: [...RESET_PACKET.slice(6, 8)],
      byte161: RESET_PACKET[161],
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    for (const item of queue) {
      output.send(item.bytes);
      diagnose("packet-sent", {
        output: portDetails(output),
        order: item.order,
        pad: item.pad,
        triggerNote: item.triggerNote,
        playbackNote: item.playbackNote,
        fileName: item.fileName,
        patchName: item.name,
      });
      elements.progress.value = item.order;
      log(`Sent ${item.order}/16 · Pad ${String(item.pad).padStart(2, "0")} · trigger ${item.triggerNote} · playback ${item.playbackNote} · ${item.name}`);
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    log("리셋 패킷 + 16개 patch 전송 완료. Pad 1–16을 확인하세요.", "PASS");
    diagnose("send-complete", { output: portDetails(output) });
  } catch (error) {
    log(`전송 중단: ${error.message}`, "ERROR");
    diagnose("send-error", { name: error.name, message: error.message, stack: error.stack });
  } finally {
    sending = false;
    updateHealth();
  }
}

async function loadManifest(path, successMessage) {
  try {
    const manifest = await fetch(path).then((response) => {
      if (!response.ok) throw new Error(`sample manifest HTTP ${response.status}`);
      return response.json();
    });
    playbackNotes.fill(null);
    for (const patch of manifest.patches) {
      const response = await fetch(`${path.slice(0, path.lastIndexOf("/") + 1)}${patch.file}`);
      if (!response.ok) throw new Error(`${patch.file}: HTTP ${response.status}`);
      const parsed = validateEditorSysEx(new Uint8Array(await response.arrayBuffer()));
      slots[patch.pad - 1] = { ...parsed, fileName: patch.file };
      playbackNotes[patch.pad - 1] = patch.playbackNote === undefined ? null : patch.playbackNote;
      renderPad(patch.pad - 1);
    }
    elements.title.value = manifest.title;
    log(successMessage, "PASS");
  } catch (error) {
    log(`Preset 로드 실패: ${error.message}`, "ERROR");
  }
}

async function loadDemo() {
  return loadManifest("samples/bank-d-demo/manifest.json", "검증된 Bank D demo 세트를 불러왔습니다.");
}

async function loadDrumKit() {
  return loadManifest("samples/fm-drum-kit/manifest.json", "FM Drum Preset 16개를 불러왔습니다. 현재 S1C5에서는 packet identity 보호를 위해 Playback Note를 Original로 유지합니다.");
}

function exportSet() {
  try {
    const document = createPatchSetDocument(slots, elements.title.value.trim() || "Untitled Patch Set", playbackNotes);
    const data = new TextEncoder().encode(`${JSON.stringify(document, null, 2)}\n`);
    const safe = document.title.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-|-$/g, "") || "patch-set";
    download(`${safe}.smkpatchset.json`, data, "application/json");
    log("Patch set 파일을 내보냈습니다.");
  } catch (error) { log(error.message, "ERROR"); }
}

async function importSet(file) {
  try {
    const parsed = parsePatchSetDocument(JSON.parse(await file.text()));
    slots.splice(0, slots.length, ...parsed.slots);
    playbackNotes.splice(0, playbackNotes.length, ...parsed.playbackNotes);
    elements.title.value = parsed.title;
    slots.forEach((_, index) => renderPad(index));
    log(`${file.name}: patch set 가져오기 완료`, "PASS");
  } catch (error) { log(`${file.name}: ${error.message}`, "ERROR"); }
}

buildPads();
elements.connect.addEventListener("click", connectMidi);
elements.device.addEventListener("change", () => {
  bindSelectedDevice();
  updateHealth();
});
document.addEventListener("pointerdown", (event) => {
  if (!event.target.closest(".pad")) clearFocusedPad();
}, true);
elements.send.addEventListener("click", sendAll);
document.querySelector("#load-demo").addEventListener("click", loadDemo);
document.querySelector("#load-drum-kit").addEventListener("click", loadDrumKit);
document.querySelector("#load-files").addEventListener("click", () => elements.filePicker.click());
elements.filePicker.addEventListener("change", () => loadMany([...elements.filePicker.files]));
document.querySelector("#import-set").addEventListener("click", () => elements.setPicker.click());
elements.setPicker.addEventListener("change", () => elements.setPicker.files?.[0] && importSet(elements.setPicker.files[0]));
document.querySelector("#export-set").addEventListener("click", exportSet);
document.querySelector("#all-original").addEventListener("click", () => {
  playbackNotes.fill(null);
  playbackNotes.forEach((_, index) => renderPad(index));
  log("모든 Pad의 Playback Note를 Original로 설정했습니다.");
});
document.querySelector("#all-c4").addEventListener("click", () => {
  playbackNotes.fill(60);
  playbackNotes.forEach((_, index) => renderPad(index));
  log("모든 Pad의 Playback Note를 C4 (60)로 설정했습니다.");
});
document.querySelector("#clear-set").addEventListener("click", () => {
  slots.fill(null);
  playbackNotes.fill(null);
  slots.forEach((_, index) => renderPad(index));
  elements.progress.value = 0;
  log("모든 Pad를 비웠습니다.");
});
document.querySelector("#clear-log").addEventListener("click", () => { elements.log.textContent = ""; });
updateHealth();
window.addEventListener("error", (event) => diagnose("window-error", { message: event.message, stack: event.error?.stack }));
window.addEventListener("unhandledrejection", (event) => diagnose("unhandled-rejection", { message: String(event.reason), stack: event.reason?.stack }));
