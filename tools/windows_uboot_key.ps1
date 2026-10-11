# Send the SLOOP UBOOT entry key over USB MIDI, then show what Windows sees.
#
# The instrument is running the SLOOP app, which answers this SysEx by calling
# fm1_enter_uboot() and resetting into the WL82 bootloader. That is the same
# forced-upgrade state the Jieli V4 tool reaches with its hardware key, so
# getting there needs no vendor hardware at all.
#
#   F0 22 24 35 7D F7
#
# No driver, no libusb, no Python: Windows already binds this device as a MIDI
# port and winmm can put a SysEx message on it.

$ErrorActionPreference = 'Stop'

$SysEx = [byte[]](0xF0, 0x22, 0x24, 0x35, 0x7D, 0xF7)   # UBOOT entry

# MIDIHDR is 48 bytes on 64-bit Windows:
#   lpData@0(8) dwBufferLength@8(4) dwBytesRecorded@12(4)
#   dwUser@16(8) dwFlags@24(8) hmid@32(8) reserved@40(8)
$HeaderSize = 48

Add-Type -Namespace WinMM -Name Api -MemberDefinition @'
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint midiOutGetNumDevs();
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern IntPtr midiOutOpen(out IntPtr handle, uint deviceId, IntPtr cb, IntPtr instance, uint flags);
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint midiOutPrepareHeader(IntPtr handle, IntPtr header, uint size);
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint midiOutLongMsg(IntPtr handle, IntPtr headerPtr, uint size);
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint midiOutUnprepareHeader(IntPtr handle, IntPtr header, uint size);
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint midiOutClose(IntPtr handle);
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint midiOutGetErrorText(uint err, System.Text.StringBuilder text, uint size);
'@

function Get-MidiError([uint32]$code) {
    if ($code -eq 0) { return 'ok' }
    $sb = New-Object System.Text.StringBuilder 256
    [void][WinMM.Api]::midiOutGetErrorText($code, $sb, 256)
    return ("{0} ({1})" -f $code, $sb.ToString())
}

Write-Host 'USB MIDI ports Windows can see:' -ForegroundColor Cyan
$matches = @(Get-CimInstance Win32_PnPEntity |
             Where-Object { $_.Name -match 'MIDI|SMK|Felucca|1209' })
if ($matches.Count -eq 0) {
    Write-Host ''
    Write-Host 'No MIDI device matched. Check the instrument is on and running SLOOP.' -ForegroundColor Red
    exit 1
}
$matches | Select-Object Name, DeviceID | Format-Table -AutoSize | Out-String | Write-Host

Write-Host 'Sending F0 22 24 35 7D F7 (UBOOT entry) on every OUT port...' -ForegroundColor Cyan

$sent = 0
$count = [WinMM.Api]::midiOutGetNumDevs()
for ($i = 0; $i -lt $count; $i++) {
    $handle = [IntPtr]::Zero
    $rcOpen = [WinMM.Api]::midiOutOpen([ref]$handle, [uint32]$i, [IntPtr]::Zero, [IntPtr]::Zero, 0)
    if ($rcOpen -ne 0) { continue }

    # Header and payload share one allocation; lpData points past the header.
    $total = $HeaderSize + $SysEx.Length
    $block = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($total)
    try {
        for ($j = 0; $j -lt $total; $j++) { [byte][System.Runtime.InteropServices.Marshal]::WriteByte($block, $j, 0) }
        [System.Runtime.InteropServices.Marshal]::WriteInt64($block, 0, [IntPtr]($block.ToInt64() + $HeaderSize).ToInt64())  # lpData
        [System.Runtime.InteropServices.Marshal]::WriteInt32($block, 8, $SysEx.Length)                                # dwBufferLength
        [System.Runtime.InteropServices.Marshal]::Copy($SysEx, 0, [IntPtr]($block.ToInt64() + $HeaderSize), $SysEx.Length)

        $rcPrep = [WinMM.Api]::midiOutPrepareHeader($handle, $block, [uint32]$HeaderSize)
        if ($rcPrep -ne 0) {
            Write-Host ("  OUT {0}: prepare failed: {1}" -f $i, (Get-MidiError $rcPrep))
        } else {
            $rcSend = [WinMM.Api]::midiOutLongMsg($handle, $block, [uint32]$HeaderSize)
            if ($rcSend -eq 0) {
                Write-Host ("  OUT {0}: sent" -f $i) -ForegroundColor Green
                $sent++
            } else {
                Write-Host ("  OUT {0}: send failed: {1}" -f $i, (Get-MidiError $rcSend))
            }
            [void][WinMM.Api]::midiOutUnprepareHeader($handle, $block, [uint32]$HeaderSize)
        }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($block)
        [void][WinMM.Api]::midiOutClose($handle)
    }
}

Write-Host ''
if ($sent -eq 0) {
    Write-Host 'No port accepted the message.' -ForegroundColor Red
    Write-Host 'If every line says prepare failed, the MIDI stack rejected the buffer.'
    Write-Host 'In that case fall back to the Jieli V4 tool for the entry step.'
    exit 1
}

Write-Host "Sent on $sent port(s). The instrument should reset into WL82 UBOOT1.00." -ForegroundColor Green
Write-Host ''
Write-Host 'Verify:' -ForegroundColor Cyan
Write-Host '  Get-Disk | Format-Table Number, FriendlyName, Size'
Write-Host 'Expect one 1 MB device named WL82 UBOOT1.00 USB Device.'
