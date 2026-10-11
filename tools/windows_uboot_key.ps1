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

# MIDIHDR is declared as a real struct so the layout and size come from the
# marshaller rather than from hand-computed offsets. On 64-bit Windows this is
# 48 bytes; getting it wrong makes midiOutPrepareHeader fail with no useful
# diagnostic.
Add-Type -Namespace WinMM -Name Api -MemberDefinition @'
    [System.Runtime.InteropServices.StructLayout(
        System.Runtime.InteropServices.LayoutKind.Sequential)]
    public struct MIDIHDR {
        public IntPtr  lpData;
        public uint    dwBufferLength;
        public uint    dwBytesRecorded;
        public IntPtr  dwUser;
        public IntPtr  dwFlags;
        public IntPtr  hmid;
        public IntPtr  reserved;
    }

    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint midiOutGetNumDevs();
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern IntPtr midiOutOpen(out IntPtr handle, uint deviceId, IntPtr cb, IntPtr instance, uint flags);
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint midiOutPrepareHeader(IntPtr handle, ref MIDIHDR header, uint size);
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint midiOutLongMsg(IntPtr handle, ref MIDIHDR header, uint size);
    [DllImport("winmm.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint midiOutUnprepareHeader(IntPtr handle, ref MIDIHDR header, uint size);
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

$hdrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][WinMM.Api+Midihdr])
Write-Host ("MIDIHDR size on this host: {0} bytes" -f $hdrSize)
if ($hdrSize -ne 48) {
    Write-Host 'Unexpected MIDIHDR size; stopping rather than sending a malformed buffer.' -ForegroundColor Red
    exit 1
}

Write-Host 'Sending F0 22 24 35 7D F7 (UBOOT entry) on every OUT port...' -ForegroundColor Cyan

$sent = 0
$count = [WinMM.Api]::midiOutGetNumDevs()
for ($i = 0; $i -lt $count; $i++) {
    $handle = [IntPtr]::Zero
    $rcOpen = [WinMM.Api]::midiOutOpen([ref]$handle, [uint32]$i, [IntPtr]::Zero, [IntPtr]::Zero, 0)
    if ($rcOpen -ne 0) { continue }

    $payload = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SysEx.Length)
    try {
        [System.Runtime.InteropServices.Marshal]::Copy($SysEx, 0, $payload, $SysEx.Length)

        $hdr = New-Object 'WinMM.Api+Midihdr'
        $hdr.lpData = $payload
        $hdr.dwBufferLength = [uint32]$SysEx.Length
        $hdr.dwBytesRecorded = 0
        $hdr.dwUser = [IntPtr]::Zero
        $hdr.dwFlags = [IntPtr]::Zero
        $hdr.hmid = $handle
        $hdr.reserved = [IntPtr]::Zero

        $rcPrep = [WinMM.Api]::midiOutPrepareHeader($handle, [ref]$hdr, [uint32]$hdrSize)
        if ($rcPrep -ne 0) {
            Write-Host ("  OUT {0}: prepare failed: {1}" -f $i, (Get-MidiError $rcPrep))
        } else {
            $rcSend = [WinMM.Api]::midiOutLongMsg($handle, [ref]$hdr, [uint32]$hdrSize)
            if ($rcSend -eq 0) {
                Write-Host ("  OUT {0}: sent" -f $i) -ForegroundColor Green
                $sent++
            } else {
                Write-Host ("  OUT {0}: send failed: {1}" -f $i, (Get-MidiError $rcSend))
            }
            [void][WinMM.Api]::midiOutUnprepareHeader($handle, [ref]$hdr, [uint32]$hdrSize)
        }
    } catch {
        Write-Host ("  OUT {0}: exception: {1}" -f $i, $_.Exception.Message) -ForegroundColor Red
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($payload)
        [void][WinMM.Api]::midiOutClose($handle)
    }
}

Write-Host ''
if ($sent -eq 0) {
    Write-Host 'No port accepted the message.' -ForegroundColor Red
    Write-Host 'Fall back to the Jieli V4 tool for the entry step; everything after it is unchanged.'
    exit 1
}

Write-Host "Sent on $sent port(s). The instrument should reset into WL82 UBOOT1.00." -ForegroundColor Green
Write-Host ''
Write-Host 'Verify:' -ForegroundColor Cyan
Write-Host '  Get-Disk | Format-Table Number, FriendlyName, Size'
Write-Host 'Expect one 1 MB device named WL82 UBOOT1.00 USB Device.'
