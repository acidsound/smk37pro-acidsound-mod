import {
  PAD_TO_NOTE,
  createPatchSetDocument,
  midiNoteName,
  parsePatchSetDocument,
  transmissionOrder,
  validateEditorSysEx,
} from "./sysex.mjs";

const slots = Array(16).fill(null);
const playbackNotes = Array(16).fill(null);
let midiAccess = null;
let sending = false;
const padElements = [];

const elements = {
  grid: document.querySelector("#pad-grid"),
  template: document.querySelector("#pad-template"),
  title: document.querySelector("#set-title"),
  validCount: document.querySelector("#valid-count"),
  setState: document.querySelector("#set-state"),
  connect: document.querySelector("#connect-midi"),
  midiState: document.querySelector("#midi-state"),
  output: document.querySelector("#midi-output"),
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
    card.querySelector(".pad-note").textContent = `CH10 · NOTE ${PAD_TO_NOTE[index]}`;
    const playbackSelect = card.querySelector(".playback-note");
    playbackSelect.add(new Option(`Original · ${midiNoteName(PAD_TO_NOTE[index])} (${PAD_TO_NOTE[index]})`, ""));
    for (let note = 0; note <= 127; note += 1) {
      playbackSelect.add(new Option(`${midiNoteName(note)} · ${note}`, String(note)));
    }
    playbackSelect.addEventListener("change", () => {
      playbackNotes[index] = playbackSelect.value === "" ? null : Number(playbackSelect.value);
      const effective = playbackNotes[index] ?? PAD_TO_NOTE[index];
      log(`Pad ${String(pad).padStart(2, "0")} Playback Note → ${midiNoteName(effective)} (${effective})${playbackNotes[index] === null ? " · Original" : ""}`);
    });
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

function refreshOutputs() {
  const previous = elements.output.value;
  const outputs = midiAccess ? [...midiAccess.outputs.values()] : [];
  elements.output.replaceChildren();
  if (outputs.length === 0) {
    elements.output.add(new Option("MIDI Output 없음", ""));
    elements.output.disabled = true;
  } else {
    for (const output of outputs) elements.output.add(new Option(`${output.name || "Unnamed"} · ${output.manufacturer || "Unknown"}`, output.id));
    elements.output.disabled = false;
    if (outputs.some((output) => output.id === previous)) elements.output.value = previous;
    else {
      const preferred = outputs.find((output) => /SMK|M-VAVE/i.test(`${output.name} ${output.manufacturer}`));
      elements.output.value = (preferred || outputs[0]).id;
    }
  }
  const connected = outputs.length > 0;
  elements.midiState.textContent = connected ? `${outputs.length}개 Output 사용 가능` : "MIDI Output 없음";
  elements.midiState.classList.toggle("connected", connected);
  updateHealth();
}

function selectedOutput() {
  return midiAccess?.outputs.get(elements.output.value) || null;
}

async function connectMidi() {
  if (!("requestMIDIAccess" in navigator)) {
    log("이 브라우저는 Web MIDI를 지원하지 않습니다. Desktop Chrome을 사용하세요.", "ERROR");
    return;
  }
  try {
    midiAccess = await navigator.requestMIDIAccess({ sysex: true });
    midiAccess.onstatechange = refreshOutputs;
    refreshOutputs();
    log("Web MIDI SysEx 권한이 허용되었습니다.");
  } catch (error) {
    log(`Web MIDI 연결 실패: ${error.message}`, "ERROR");
  }
}

async function sendAll() {
  if (sending) return;
  const output = selectedOutput();
  if (!output) { log("MIDI Output을 선택하세요.", "ERROR"); return; }
  try {
    const queue = transmissionOrder(slots, playbackNotes);
    if (playbackNotes.some((note) => note !== null)) {
      log("Playback Note 설정은 Set에 저장되었습니다. 대응 펌웨어 protocol이 설치되기 전에는 patch data만 전송됩니다.", "WARN");
    }
    sending = true;
    elements.progress.value = 0;
    updateHealth();
    log(`${output.name}: 16개 patch 전송 시작`);
    for (const item of queue) {
      output.send(item.bytes);
      elements.progress.value = item.order;
      log(`Sent ${item.order}/16 · Pad ${String(item.pad).padStart(2, "0")} · trigger ${item.triggerNote} · playback ${item.playbackNote} · ${item.name}`);
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    log("16개 patch 전송 완료. Pad 1–16을 확인하세요.", "PASS");
  } catch (error) {
    log(`전송 중단: ${error.message}`, "ERROR");
  } finally {
    sending = false;
    updateHealth();
  }
}

async function loadDemo() {
  try {
    const manifest = await fetch("samples/bank-d-demo/manifest.json").then((response) => {
      if (!response.ok) throw new Error(`sample manifest HTTP ${response.status}`);
      return response.json();
    });
    playbackNotes.fill(null);
    for (const patch of manifest.patches) {
      const response = await fetch(`samples/bank-d-demo/${patch.file}`);
      if (!response.ok) throw new Error(`${patch.file}: HTTP ${response.status}`);
      const parsed = validateEditorSysEx(new Uint8Array(await response.arrayBuffer()));
      slots[patch.pad - 1] = { ...parsed, fileName: patch.file };
      renderPad(patch.pad - 1);
    }
    elements.title.value = manifest.title;
    log("검증된 Bank D demo 세트를 불러왔습니다.", "PASS");
  } catch (error) {
    log(`Demo 로드 실패: ${error.message}`, "ERROR");
  }
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
elements.output.addEventListener("change", updateHealth);
elements.send.addEventListener("click", sendAll);
document.querySelector("#load-demo").addEventListener("click", loadDemo);
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
