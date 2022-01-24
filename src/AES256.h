/*  
*   Byte-oriented AES-256 implementation.
*   All lookup tables replaced with 'on the fly' calculations. 
*
*   Copyright (c) 2007-2009 Ilya O. Levin, http://www.literatecode.com
*   Other contributors: Hal Finney
*
*   Permission to use, copy, modify, and distribute this software for any
*   purpose with or without fee is hereby granted, provided that the above
*   copyright notice and this permission notice appear in all copies.
*
*   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
*   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
*   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
*   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
*   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
*   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
*   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
#include <stdint.h>

#define AES128_KEYLEN 16 // TODO
#define AES192_KEYLEN 24 // TODO
#define AES256_KEYLEN 32

#define AES_BLOCKLEN 16

typedef struct {
    uint8_t key[AES256_KEYLEN]; 
    uint8_t enckey[AES256_KEYLEN]; 
    uint8_t deckey[AES256_KEYLEN];
    uint8_t iv[AES_BLOCKLEN];
} aes256_context; 

void aes256_init(aes256_context *, uint8_t * /* key */);
void aes256_init_iv(aes256_context *ctx, uint8_t *iv);
void aes256_done(aes256_context *);
void aes256_encrypt_ecb(aes256_context *, uint8_t * /* plaintext */);
void aes256_decrypt_ecb(aes256_context *, uint8_t * /* cipertext */);
void aes256_encrypt_cbc(aes256_context *, uint8_t * /* plaintext */, uint64_t length);
void aes256_decrypt_cbc(aes256_context *, uint8_t * /* cipertext */, uint64_t length);
void aes256_xcrypt_ctr(aes256_context *, uint8_t * /* plaintext */, uint64_t length);
