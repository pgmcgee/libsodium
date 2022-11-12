
/*
 * AES256-GCM, based on the "Intel Carry-Less Multiplication Instruction and its
 * Usage for Computing the GCM Mode" paper and reference code, using the
 * aggregated reduction method. Originally adapted by Romain Dolbeau.
 */

#include "crypto_aead_aes256gcm.h"
#include "randombytes.h"

size_t
crypto_aead_aes256gcm_keybytes(void)
{
    return crypto_aead_aes256gcm_KEYBYTES;
}

size_t
crypto_aead_aes256gcm_nsecbytes(void)
{
    return crypto_aead_aes256gcm_NSECBYTES;
}

size_t
crypto_aead_aes256gcm_npubbytes(void)
{
    return crypto_aead_aes256gcm_NPUBBYTES;
}

size_t
crypto_aead_aes256gcm_abytes(void)
{
    return crypto_aead_aes256gcm_ABYTES;
}

size_t
crypto_aead_aes256gcm_statebytes(void)
{
    return (sizeof(crypto_aead_aes256gcm_state) + (size_t) 15U) & ~(size_t) 15U;
}

size_t
crypto_aead_aes256gcm_messagebytes_max(void)
{
    return crypto_aead_aes256gcm_MESSAGEBYTES_MAX;
}

void
crypto_aead_aes256gcm_keygen(unsigned char k[crypto_aead_aes256gcm_KEYBYTES])
{
    randombytes_buf(k, crypto_aead_aes256gcm_KEYBYTES);
}