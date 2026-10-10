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

Add-Type -Namespace WinMM -Name Api -MemberDefinition @'
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint midiOutGetNumDevs();
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern IntPtr midiOutOpen(out IntPtr handle, uint deviceId, IntPtr cb, IntPtr instance, uint flags);
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint midiOutLongMsg(IntPtr handle, IntPtr msgPtr, uint msgSize);
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint midiOutClose(IntPtr handle);
'@

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
    $rc = [WinMM.Api]::midiOutOpen([ref]$handle, [uint32]$i, [IntPtr]::Zero, [IntPtr]::Zero, 0)
    if ($rc -ne 0) { continue }

    # MIDIHDR: no user pointer, no driver buffer, 8-byte header then the payload.
    $total = 8 + $SysEx.Length
    $hdr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($total)
    try {
        [System.Runtime.InteropServices.Marshal]::WriteInt32($hdr, 0, $total)
        [System.Runtime.InteropServices.Marshal]::Copy($SysEx, 0, [IntPtr]($hdr.ToInt64() + 8), $SysEx.Length)
        $rcSend = [WinMM.Api]::midiOutLongMsg($handle, $hdr, [uint32]$total)
        if ($rcSend -eq 0) {
            Write-Host ("  OUT port {0}: sent" -f $i)
            $sent++
        }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($hdr)
        [WinMM.Api]::midiOutClose($handle)
    }
}

Write-Host ''
if ($sent -eq 0) {
    Write-Host 'Nothing accepted the message. See the port list above.' -ForegroundColor Red
    exit 1
}

Write-Host 'Sent. The instrument should now reset into WL82 UBOOT1.00.' -ForegroundColor Green
Write-Host ''
Write-Host 'Verify:' -ForegroundColor Cyan
Write-Host '  Get-Disk | Format-Table Number, FriendlyName, Size'
Write-Host 'Expect one 1 MB device named WL82 UBOOT1.00 USB Device.'
