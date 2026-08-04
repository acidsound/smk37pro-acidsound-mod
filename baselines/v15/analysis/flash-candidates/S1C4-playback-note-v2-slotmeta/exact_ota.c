/* Exact-hash v15-only OTA wrapper for S1-C4 Playback Note. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = { 0x41, 0x51, 0xfb, 0x69, 0xac, 0xf4, 0x4c, 0x75, 0xe5, 0x80, 0x72, 0x87, 0x18, 0x18, 0x86, 0x9e, 0xbc, 0x05, 0x20, 0x82, 0x8b, 0x86, 0xe3, 0xb0, 0x5f, 0x87, 0xd3, 0x25, 0xfc, 0x82, 0x1c, 0x71 };
static const char CONFIRM[] = "INSTALL-SMK37PRO-V15-S1C4-PLAYBACK-NOTE-V2-SLOTMETA-4151FB69";
static const char DESCRIPTION[] = "SMK37ProMod v15 S1-C4 Playback Note candidate";
static int check_exact(const char *path) { struct smk37_fwsc firmware; int status=1; if(!smk37_fwsc_load(path,&firmware)) return 1; if(strcmp(firmware.name,"SMK-37 Pro")==0 && firmware.version==15 && memcmp(firmware.file_sha256,PACKAGE_SHA256,sizeof(PACKAGE_SHA256))==0) { printf("exact v15 S1-C4 Playback Note package: PASS (%zu-byte OTA payload)\n", firmware.payload_length); status=0; } else fputs("offline check rejected: not exact S1-C4 Playback Note package\n", stderr); smk37_fwsc_free(&firmware); return status; }
int main(int argc,char **argv) { if(argc==3 && strcmp(argv[1],"check")==0) return check_exact(argv[2]); if(argc==6 && strcmp(argv[1],"upload")==0 && strcmp(argv[4],"--confirm")==0) return ota_upload_exact(argv[2],argv[3],argv[5],15,PACKAGE_SHA256,DESCRIPTION,CONFIRM,"v15 S1-C4 Playback Note candidate installed"); fprintf(stderr,"usage:\n  %s check <fwsc>\n  %s upload <fwsc> <transcript> --confirm %s\n",argv[0],argv[0],CONFIRM); return 2; }
