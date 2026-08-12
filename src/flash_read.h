#ifndef SMK37_FLASH_READ_H
#define SMK37_FLASH_READ_H

#include <stdint.h>

int smk37_flash_read_preview(uint32_t address, uint32_t length);
int smk37_flash_dump(const char *output_path, uint32_t length);

#endif
