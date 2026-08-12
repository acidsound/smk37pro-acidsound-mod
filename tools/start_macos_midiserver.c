#include <CoreFoundation/CoreFoundation.h>
#include <CoreMIDI/CoreMIDI.h>
#include <stdio.h>

int main(void) {
    MIDIClientRef client = 0;
    OSStatus status = MIDIClientCreate(CFSTR("SMK37 CoreMIDI Recovery"), NULL, NULL, &client);
    if (status != noErr) {
        fprintf(stderr, "MIDIClientCreate failed: %d\n", (int)status);
        return 1;
    }
    printf("CoreMIDI restored: %lu sources, %lu destinations\n",
           (unsigned long)MIDIGetNumberOfSources(),
           (unsigned long)MIDIGetNumberOfDestinations());
    MIDIClientDispose(client);
    return 0;
}
