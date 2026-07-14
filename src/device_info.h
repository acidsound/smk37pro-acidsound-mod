#ifndef SMK37_DEVICE_INFO_H
#define SMK37_DEVICE_INFO_H

#include <stdbool.h>

enum {
    SMK37_DEVICE_NAME_CAPACITY = 64,
};

struct smk37_device_identity {
    char name[SMK37_DEVICE_NAME_CAPACITY];
    unsigned version;
};

int smk37_read_device_identity(struct smk37_device_identity *identity,
                               bool print_raw_response);
int smk37_device_info(void);

#endif
