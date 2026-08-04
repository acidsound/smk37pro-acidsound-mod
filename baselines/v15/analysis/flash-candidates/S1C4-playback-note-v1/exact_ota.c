/* Exact-hash v15-only OTA wrapper for S1-C4 Playback Note. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = { 0x27, 0x4b, 0x22, 0x92, 0x6b, 0xab, 0x8e, 0x4d, 0x1b, 0x96, 0xea, 0xfb, 0x8f, 0xb4, 0x1f, 0xed, 0x2b, 0x77, 0xcd, 0xa4, 0xe7, 0xa7, 0x53, 0xbe, 0x08, 0x7e, 0xe4, 0xdc, 0x83, 0xca, 0x9f, 0xd1 };
static const char CONFIRM[] = "INSTALL-SMK37PRO-V15-S1C4-PLAYBACK-NOTE-274B2292";
static const char DESCRIPTION[] = "SMK37ProMod v15 S1-C4 Playback Note candidate";
static int check_exact(const char *path) { struct smk37_fwsc firmware; int status=1; if(!smk37_fwsc_load(path,&firmware)) return 1; if(strcmp(firmware.name,"SMK-37 Pro")==0 && firmware.version==15 && memcmp(firmware.file_sha256,PACKAGE_SHA256,sizeof(PACKAGE_SHA256))==0) { printf("exact v15 S1-C4 Playback Note package: PASS (%zu-byte OTA payload)\n", firmware.payload_length); status=0; } else fputs("offline check rejected: not exact S1-C4 Playback Note package\n", stderr); smk37_fwsc_free(&firmware); return status; }
int main(int argc,char **argv) { if(argc==3 && strcmp(argv[1],"check")==0) return check_exact(argv[2]); if(argc==6 && strcmp(argv[1],"upload")==0 && strcmp(argv[4],"--confirm")==0) return ota_upload_exact(argv[2],argv[3],argv[5],15,PACKAGE_SHA256,DESCRIPTION,CONFIRM,"v15 S1-C4 Playback Note candidate installed"); fprintf(stderr,"usage:\n  %s check <fwsc>\n  %s upload <fwsc> <transcript> --confirm %s\n",argv[0],argv[0],CONFIRM); return 2; }
