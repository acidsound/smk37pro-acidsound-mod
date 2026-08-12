#ifndef SMK37_OTA_H
#define SMK37_OTA_H

int smk37_ota_preflight(const char *firmware_path);
int smk37_ota_dry_run(const char *firmware_path);
int smk37_ota_upload(const char *firmware_path, const char *transcript_path,
                     const char *confirmation);
int smk37_ota_upload_m001(const char *firmware_path,
                          const char *transcript_path,
                          const char *confirmation);
int smk37_ota_upload_m02(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation);
int smk37_ota_upload_m03(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation);
int smk37_ota_upload_m04(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation);
int smk37_ota_upload_m05(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation);
int smk37_ota_upload_m06(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation);
int smk37_ota_upload_m07(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation);
int smk37_ota_upload_m08(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation);
int smk37_ota_upload_m10(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation);
int smk37_ota_upload_v15(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation);
int smk37_ota_upload_v15_r01(const char *firmware_path,
                             const char *transcript_path,
                             const char *confirmation);
int smk37_ota_resume_v12(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation);

#endif
