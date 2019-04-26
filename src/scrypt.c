#include "scrypt.h"
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>


/**
 * @brief return k bits to the left of position p (including the bit at p)
 *        example for number = 10101, p = 1, k = 4, we get
 *        return 0101
 * 
 * @param number 
 * @param k 
 * @param p 
 * @return uint8_t 
 */

uint8_t 
bitExtracted(uint8_t number, int k, int p)
{
    return (((1 << k) - 1) & (number >> (p - 1))); 
}


/**
 * @brief Return an sbox cipher text given by m → ((m + 1) * 7) mod (17 − 1)
 * 
 * @param m 
 * @return uint8_t 
 */

uint8_t
sbox(uint8_t m)
{
    uint8_t left = bitExtracted(m, 4, 5);
    uint8_t right = bitExtracted(m, 4, 1);
    
    uint8_t left_cipher = ((left + 1) * 7) % (17 - 1);
    uint8_t right_cipher = ((right + 1) * 7) % (17 - 1);

    uint8_t final_cipher = (left_cipher << 4) + right_cipher;
    return final_cipher;
}


/**
 * @brief inverse sbox that returns cleartext
 * 
 * @param m 
 * @return uint8_t 
 */

uint8_t
sbox_inverse(uint8_t cipher)
{
    int i;

    uint8_t left_cipher = bitExtracted(cipher, 4, 5);
    uint8_t left_clear;

    uint8_t right_cipher = bitExtracted(cipher, 4, 1);
    uint8_t right_clear;

    // uint8_t s_box_inv[] = {15, 6, 13, 4, 11, 2, 9, 0, 7, 14, 5, 12, 3, 10, 1, 8};

    for (i = 0; i < 16; i++)
    {
        if(((i + 1) * 7) % (17 - 1) == left_cipher)
        {
            left_clear = i;
        }

        if(((i + 1) * 7) % (17 - 1) == right_cipher)
        {
            right_clear = i;
        }
    }

    return (left_clear << 4) + right_clear;
}


/**
 * @brief Return a pbox cipher text
 * 
 * @param m 
 * @return uint8_t 
 */

uint8_t
pbox(uint8_t m)
{
    uint8_t first_two_bits = bitExtracted(m, 2, 7);
    uint8_t shifted_left_two = m << 2;
    return shifted_left_two + first_two_bits;
}


/**
 * @brief inverse pbox that returns cleartext
 * 
 * @param m 
 * @return uint8_t 
 */

uint8_t
pbox_inverse(uint8_t cipher)
{
    uint8_t last_two_bits = bitExtracted(cipher, 2, 1);
    uint8_t shifted_right_two = cipher >> 2;
    return (last_two_bits << 6) + shifted_right_two;
}

/**
 * \brief Encrypt an 8-bit cleartext using a 32-bit key.
 *
 * \param m 8-bit cleartext. 
 * \param k 32-bit key.
 * \result 8-bit ciphertext.
 */

uint8_t
sc_enc8(uint8_t m, uint32_t k)
{
    // for the steps
    uint32_t key_segment;
    uint8_t key_step_cipher;
    uint8_t sbox_cipher;
    uint8_t pbox_cipher;

    // Key step
    key_segment = bitExtracted(k, 8, 25);
    key_step_cipher = m^key_segment;

    //Substitution and permutation
    sbox_cipher = sbox(key_step_cipher);
    pbox_cipher = pbox(sbox_cipher);

    //key step
    key_segment = bitExtracted(k, 8, 17);
    key_step_cipher = pbox_cipher^key_segment;

    //Substitution and permutation
    sbox_cipher = sbox(key_step_cipher);
    pbox_cipher = pbox(sbox_cipher);

    //key step
    key_segment = bitExtracted(k, 8, 9);
    key_step_cipher = pbox_cipher^key_segment;

    //substitution
    sbox_cipher = sbox(key_step_cipher);

    //key step
    key_segment = bitExtracted(k, 8, 1);
    key_step_cipher = sbox_cipher^key_segment;

    return key_step_cipher;

}


/**
 * \brief Decrypt an 8-bit ciphertext using a 32-bit key.
 *
 * \param m 8-bit ciphertext. 
 * \param k 32-bit key.
 * \result 8-bit cleartext.
 */

uint8_t
sc_dec8(uint8_t c, uint32_t k)
{
    // for inverse steps
    uint32_t key_segment;
    uint8_t key_step_clear;
    uint8_t sbox_clear;
    uint8_t pbox_clear;

    //inverse key step
    key_segment = bitExtracted(k, 8, 1);
    key_step_clear = c^key_segment;

    // inverse substitution text
    sbox_clear = sbox_inverse(key_step_clear);

    //inverse key step
    key_segment = bitExtracted(k, 8, 9);
    key_step_clear = sbox_clear^key_segment;

    //inverse pbox and sbox
    pbox_clear = pbox_inverse(key_step_clear);
    sbox_clear = sbox_inverse(pbox_clear);

    //inverse key step
    key_segment = bitExtracted(k, 8, 17);
    key_step_clear = sbox_clear^key_segment;

    //inverse pbox and sbox
    pbox_clear = pbox_inverse(key_step_clear);
    sbox_clear = sbox_inverse(pbox_clear);

    //inverse key step
    key_segment = bitExtracted(k, 8, 25);
    key_step_clear = sbox_clear^key_segment;

    return key_step_clear;
}

/**
 * \brief Encrypt a variable-length cleartext using a 32-bit key in ECB mode.
 *
 * \param m cleartext.
 * \param c ciphertext.
 * \param len length of the cleartext and ciphertext buffers.
 * \param k 32-bit key.
 */

void
sc_enc_ecb(unsigned char *m, unsigned char *c, size_t len, uint32_t k)
{

    int i = 0;

    for(i = 0; i < len; i++) 
    {
        c[i] = sc_enc8(m[i], k);
    }

}

/**
 * \brief Decrypt variable-length ciphertext using a 32-bit key in ECB mode.
 *
 * \param c ciphertext.
 * \param m cleartext.
 * \param len length of the ciphertext and cleartext buffers.
 * \param k 32-bit key.
 */

void
sc_dec_ecb(unsigned char *c, unsigned char *m, size_t len, uint32_t k)
{
    int i;

    for(i = 0; i < len; i++)
    {
        m[i] = sc_dec8(c[i], k);
    }
}

/**
 * \brief Encrypt a variable-length cleartext using a 32-bit key in CBC mode.
 *
 * \param m cleartext.
 * \param c ciphertext.
 * \param len length of the cleartext and ciphertext buffers.
 * \param k 32-bit key.
 * \param iv 8-bit initialization vector.
 */

void
sc_enc_cbc(unsigned char *m, unsigned char *c, size_t len, uint32_t k, uint8_t iv)
{
    int i = 0;
    uint8_t blocks[len];
    for(i = 0; i < len; i++) {
        blocks[i] = m[i];
    }

    for(i = 0; i < len; i++) {
        blocks[i] = (blocks[i]^iv);
        c[i] = sc_enc8(blocks[i], k);
        iv = c[i];
    }
}

/**
 * \brief Decrypt variable-length ciphertext using a 32-bit key in CBC mode.
 *
 * \param m ciphertext.
 * \param m cleartext.
 * \param len length of the ciphertext.
 * \param k 32-bit key.
 * \param iv 8-bit initialization vector.
 */

void
sc_dec_cbc(unsigned char *c, unsigned char *m, size_t len, uint32_t k, uint8_t iv)
{
    int i;

    for(i = 0; i < len; i++) {
        m[i] = sc_dec8(c[i], k);
        m[i] = m[i]^iv;
        iv = c[i];
    }

}