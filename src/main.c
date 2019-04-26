#include "scrypt.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void secret()
{
    // Encrypting and decrypting "secret" with ecb
    uint32_t k = 0x98267351;
    unsigned char *m = (unsigned char *) "secret";
    size_t len = strlen((char *) m);
    unsigned char c[len];
    unsigned char d[len];

    sc_enc_ecb(m, c, len, k);
    sc_dec_ecb(c, d, len, k);

    printf("Decrypted text: %s\n", d);
}

void hacker()
{
    // Encrypting an decrytping "hacker" with cbc
    uint32_t k = 0x98267351;
    uint8_t iv = 0x42;
    unsigned char *m = (unsigned char *) "hacker";
    size_t len = strlen((char *) m);
    unsigned char d[len];
    unsigned char c[len];

    sc_enc_cbc(m, c, len, k, iv);
    sc_dec_cbc(c, d, len, k, iv);
    printf("Decrypted text: %s\n", d);
}

int main()
{
    secret();
    hacker();

    return 0;
}