#include "commun.h"

void xor_aa(BYTE* input, size_t length) {

    for (int i = 0; i < length; i++) {
        input[i] = input[i] ^ 0xaa;
    }

}


