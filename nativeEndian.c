#include "nativeEndian.h"

int nativeEndian() {
    unsigned int value = 1;
    unsigned char *byte = (unsigned char *) &value;

    if (*byte == 1) {
        printf("Your laptop has a native little-endian processor.\n");
    } else {
        printf("Your laptop does not have a native little-endian processor.\n");
    }

    return 0;
}