#ifndef SMK37_USB_PROBE_H
#define SMK37_USB_PROBE_H

int smk37_probe(void);
int smk37_claim_test(void);
int smk37_midi_monitor(unsigned seconds);
int smk37_midi_channel_test(void);

#endif
