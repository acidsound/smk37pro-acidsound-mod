# FM Drum Kit · patches.fm

16 single-voice Yamaha DX7 SysEx voices arranged for the SMK-37 Pro Ch10 patch set.
The files are public single-voice downloads from [patches.fm](https://patches.fm/patches/dx7/),
with the original voice data and names preserved. `manifest.json` records the source IDs,
source banks, direct URLs, SHA-256 values, fixed Trigger Notes, and explicit Playback Notes.

## Pad layout

| Physical Pad | Fixed Trigger Note | Playback Note | Role | Source voice |
|---:|---:|---:|---|---|
| 1 | 40 | 36 / C1 | Kick A | KICK DRUM |
| 2 | 41 | 37 / C#1 | Kick B | Kick |
| 3 | 42 | 38 / D1 | Snare A | SNARE |
| 4 | 43 | 39 / D#1 | Snare B | Swissnare |
| 5 | 48 | 40 / E1 | Clap | HAND CLAPS |
| 6 | 49 | 41 / F1 | Rim | HITUN RIMS |
| 7 | 50 | 42 / F#1 | High Tom | **tom 1** |
| 8 | 51 | 43 / G1 | Middle Tom | **tom 2** |
| 9 | 36 | 44 / G#1 | Low Tom | LONG TOM |
| 10 | 37 | 45 / A1 | Floor Tom | TOM TOMS |
| 11 | 38 | 46 / A#1 | Closed Hi-Hat | CL.HI-HAT |
| 12 | 39 | 47 / B1 | Open Hi-Hat | Open HiHat |
| 13 | 44 | 48 / C2 | Crash Cymbal | CRASH CYMB |
| 14 | 45 | 49 / C#2 | Ride Cymbal | R.CYMBAL |
| 15 | 46 | 50 / D2 | Cowbell | COW BELL |
| 16 | 47 | 51 / D#2 | Shaker | Shaker |

Trigger Notes are the SMK physical Pad identity and remain unchanged. On S1C6 (S16) this
preset transmits the requested drum-map notes (36..51) as explicit Playback Notes. The
17-packet protocol (1 reset packet with the structurally impossible `0x64 0x65` signature +
16 voices) makes loading and reloading over an armed kit safe — the reset packet is not
loaded as a voice and cannot collide with voice data. **Requires S1C6 (S16) or newer**;
on S1C5 the reset packet would be treated as a voice and the old 16-packet protocol applies.

## Use

1. Open the Patch Set Editor.
2. Connect the SMK MIDI device through Web MIDI or CoreMIDI bridge.
3. Click **FM Drum Preset 불러오기**, or use `FM-Drum-Kit-patches.fm.smkpatchset.json` with **Set 가져오기**.
4. Adjust any Playback Note if a voice needs retuning.
5. Send all 16 patches after every power cycle or firmware reset.

This directory contains no firmware or flash artifact. It is a host-side volatile preset.

## Additional research

The selection was cross-checked against the public [Coffeeshopped 32 FM Drum Sounds bank](https://coffeeshopped.com/2020/03/yamaha-dx7-patches-drum-sounds),
which includes kick, snare, clap, hat, shaker and tom voices, and against the public Yamaha
percussion banks indexed by Yamaha Black Boxes. The final 16 voices use patches.fm single-voice
files so the editor can load them directly without bulk-bank conversion.
