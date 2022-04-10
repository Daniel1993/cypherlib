#include "cypher.h"
#include "WELL.h"
#include "SHA3.h"
#include "AES256.h"
#include "uECC.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <threads.h>

const char *CYP_RND_FN_NAMES[CYP_RND_NB_FNS] =
{
    "CYP_RND_WELL512A",
    "CYP_RND_WELL44497A",
    "CYP_RND_WELL44497B"
};

const char *CYP_HASH_FN_NAMES[CYP_HASH_NB_FNS] =
{
    "CYP_HASH_SHA3_256",
    "CYP_HASH_SHA3_512"
};

const char *CYP_SIM_FN_NAMES[CYP_SIM_NB_FNS] =
{
    "CYP_SIM_AES256_CBC",
    "CYP_SIM_AES256_ECB",
    "CYP_SIM_AES256_CTR"
};

const char *CYP_PAIR_FN_NAMES[CYP_PAIR_NB_FNS] =
{
    "CYP_PAIR_ECC_SECP160R1",
    "CYP_PAIR_ECC_SECP192R1",
    "CYP_PAIR_ECC_SECP224R1",
    "CYP_PAIR_ECC_SECP256K1"
};

static const uint32_t SIZE_OF_WELL44497 = 1391;
static const uint32_t SIZE_OF_WELL512 = 16;
static const uint32_t SIZE_OF_SHA3_256 = 8;
static const uint32_t SIZE_OF_SHA3_512 = 16;

#define SIZE_OF_ECC_SECP160R1_I_PUB_K (uECC_curve_public_key_size(uECC_secp160r1())) // already does *2
#define SIZE_OF_ECC_SECP160R1_I_PRV_K (uECC_curve_private_key_size(uECC_secp160r1())) // already does +1
#define SIZE_OF_ECC_SECP160R1_C_PUB_K (uECC_curve_public_key_size(uECC_secp160r1()) / 2)
#define SIZE_OF_ECC_SECP160R1_C_PRV_K (uECC_curve_private_key_size(uECC_secp160r1()))

#define SIZE_OF_ECC_SECP192R1_I_PUB_K (uECC_curve_public_key_size(uECC_secp192r1())) // already does *2
#define SIZE_OF_ECC_SECP192R1_I_PRV_K (uECC_curve_private_key_size(uECC_secp192r1())) // already does +1
#define SIZE_OF_ECC_SECP192R1_C_PUB_K (uECC_curve_public_key_size(uECC_secp192r1()) / 2)
#define SIZE_OF_ECC_SECP192R1_C_PRV_K (uECC_curve_private_key_size(uECC_secp192r1()))

#define SIZE_OF_ECC_SECP224R1_I_PUB_K (uECC_curve_public_key_size(uECC_secp224r1())) // already does *2
#define SIZE_OF_ECC_SECP224R1_I_PRV_K (uECC_curve_private_key_size(uECC_secp224r1())) // already does +1
#define SIZE_OF_ECC_SECP224R1_C_PUB_K (uECC_curve_public_key_size(uECC_secp224r1()) / 2)
#define SIZE_OF_ECC_SECP224R1_C_PRV_K (uECC_curve_private_key_size(uECC_secp224r1()))

#define SIZE_OF_ECC_SECP256K1_I_PUB_K (uECC_curve_public_key_size(uECC_secp256k1())) // already does *2
#define SIZE_OF_ECC_SECP256K1_I_PRV_K (uECC_curve_private_key_size(uECC_secp256k1())) // already does +1
#define SIZE_OF_ECC_SECP256K1_C_PUB_K (uECC_curve_public_key_size(uECC_secp256k1()) / 2)
#define SIZE_OF_ECC_SECP256K1_C_PRV_K (uECC_curve_private_key_size(uECC_secp256k1()))

// ---------------------------------------
// --- random generator
// ---------------------------------------
static thread_local enum CYP_RND_FN (*i_cyp_rnd_get_alg)();
static thread_local int (*i_cyp_rnd_get_seed_size)();
static thread_local int (*i_cyp_rnd_set_seed)(void *seed);
static thread_local int (*i_cyp_rnd_get_seed)(void *seed);
static thread_local uint64_t (*i_cyp_rnd_gen_ul)();
static thread_local double (*i_cyp_rnd_gen_d)();

// ---------------------------------------
// --- hashing functions
// ---------------------------------------
static thread_local enum CYP_HASH_FN (*i_cyp_hash_get_alg)();
static thread_local int (*i_cyp_hash_get_size)();
static thread_local int (*i_cyp_hash)(void *dst, void *src, uint64_t size);

// ---------------------------------------
// --- symmetric cipher
// ---------------------------------------
struct cyp_sim_key_ 
{
    void *ctx;
};
static thread_local enum CYP_SIM_FN (*i_cyp_sim_get_alg)();
static thread_local int (*i_cyp_sim_get_key_size)();
static thread_local int (*i_cyp_sim_get_init_size)();
static thread_local cyp_sim_key_s (*i_cyp_sim_new_key)(void*, void*);
static thread_local int (*i_cyp_sim_destroy_key)(cyp_sim_key_s);
static thread_local int (*i_cyp_sim_encrypt)(cyp_sim_key_s, void*, void*, uint64_t);
static thread_local int (*i_cyp_sim_decrypt)(cyp_sim_key_s, void*, void*, uint64_t);

// ---------------------------------------
// --- asymmetric cipher
// ---------------------------------------
struct cyp_pub_key_
{
    void *k;
};

struct cyp_prv_key_
{
    void *k;
};

struct cyp_pair_key_
{
    struct cyp_prv_key_ prv;
    struct cyp_pub_key_ pub;
};

// asymmetric cipher
static thread_local enum CYP_PAIR_FN (*i_cyp_pair_get_alg)();
static thread_local int (*i_cyp_pub_get_key_size)();
static thread_local int (*i_cyp_prv_get_key_size)();
static thread_local int (*i_cyp_pair_get_secret_size)();
static thread_local cyp_pair_key_s (*i_cyp_pair_new_key)();
static thread_local cyp_pub_key_s (*i_cyp_pair_load_pub_key)(void *key);
static thread_local cyp_prv_key_s (*i_cyp_pair_load_prv_key)(void *key);
static thread_local int (*i_cyp_pair_store_pub_key)(cyp_pub_key_s, void *key);
static thread_local int (*i_cyp_pair_store_prv_key)(cyp_prv_key_s, void *key);
static thread_local cyp_pub_key_s (*i_cyp_pair_get_pub_key)(cyp_pair_key_s);
static thread_local cyp_prv_key_s (*i_cyp_pair_get_prv_key)(cyp_pair_key_s);
static thread_local int (*i_cyp_pair_get_secret)(cyp_pub_key_s, cyp_prv_key_s, void *secret);
static thread_local int (*i_cyp_pair_destroy_key)(cyp_pair_key_s);
static thread_local int (*i_cyp_pub_destroy_key)(cyp_pub_key_s);
static thread_local int (*i_cyp_prv_destroy_key)(cyp_prv_key_s);
static thread_local int (*i_cyp_pub_verify)(cyp_pub_key_s, void *signature_in, void *expected_out, uint64_t size_signature);
static thread_local int (*i_cyp_prv_sign)(cyp_prv_key_s, void *data_in, void *signature_out, uint64_t size_signature);

int cyp_init()
{
    cyp_rnd_bind_WELL512a();
    cyp_hash_bind_SHA3_512();
    cyp_sim_bind_AES256_CBC();
    cyp_pair_bind_ECC_secp256k1();
    return 0;
}

#define CYP_RND_ 1
#ifdef CYP_RND_
// ---------------------------------------
// --- random generator
// ---------------------------------------

enum CYP_RND_FN cyp_rnd_get_alg()
{
    return i_cyp_rnd_get_alg();
}

int cyp_rnd_get_seed_size()
{
    return i_cyp_rnd_get_seed_size();
}

int cyp_rnd_set_seed(void *seed)
{
    return i_cyp_rnd_set_seed(seed);
}

int cyp_rnd_get_seed(void *seed)
{
    return i_cyp_rnd_get_seed(seed);
}

uint64_t cyp_rnd_gen_ul()
{
    return i_cyp_rnd_gen_ul();
}

double cyp_rnd_gen_d()
{
    return i_cyp_rnd_gen_d();
}
#endif

#define CYP_HASH_ 1
#ifdef CYP_HASH_
// ---------------------------------------
// --- hashing functions
// ---------------------------------------

enum CYP_HASH_FN cyp_hash_get_alg()
{
    return i_cyp_hash_get_alg();
}

int cyp_hash_get_size()
{
    return i_cyp_hash_get_size();
}

int cyp_hash(void *dst, void *src, uint64_t size)
{
    return i_cyp_hash(dst, src, size);
}
#endif

#define CYP_SIM_ 1
#ifdef CYP_SIM_
// ---------------------------------------
// --- symmetric cipher
// ---------------------------------------

enum CYP_SIM_FN cyp_sim_get_alg()
{
    return i_cyp_sim_get_alg();
}

int cyp_sim_get_key_size()
{
    return i_cyp_sim_get_key_size();
}

int cyp_sim_get_init_size()
{
    return i_cyp_sim_get_init_size();
}

cyp_sim_key_s cyp_sim_new_key(void *secret, void *init)
{
    return i_cyp_sim_new_key(secret, init);
}

int cyp_sim_destroy_key(cyp_sim_key_s key)
{
    return i_cyp_sim_destroy_key(key);
}

int cyp_sim_encrypt(cyp_sim_key_s key, void *data_in, void *cyphered_out, uint64_t size_in)
{
    return i_cyp_sim_encrypt(key, data_in, cyphered_out, size_in);
}

int cyp_sim_decrypt(cyp_sim_key_s key, void *cyphered_in, void *data_out, uint64_t size_in)
{
    return i_cyp_sim_decrypt(key, cyphered_in, data_out, size_in);
}
#endif

#define CYP_PAIR_ 1
#ifdef CYP_PAIR_
// ---------------------------------------
// --- asymmetric cipher
// ---------------------------------------

enum CYP_PAIR_FN cyp_pair_get_alg()
{
    return i_cyp_pair_get_alg();
}

int cyp_pub_get_key_size()
{
    return i_cyp_pub_get_key_size();
}

int cyp_prv_get_key_size()
{
    return i_cyp_prv_get_key_size();
}

int cyp_pair_get_secret_size()
{
    return i_cyp_pair_get_secret_size();
}

cyp_pair_key_s cyp_pair_new_key()
{
    return i_cyp_pair_new_key();
}

cyp_pub_key_s cyp_pair_load_pub_key(void *key)
{
    return i_cyp_pair_load_pub_key(key);
}

cyp_prv_key_s cyp_pair_load_prv_key(void *key)
{
    return i_cyp_pair_load_prv_key(key);
}

int cyp_pair_store_pub_key(cyp_pub_key_s pub, void *key)
{
    return i_cyp_pair_store_pub_key(pub, key);
}

int cyp_pair_store_prv_key(cyp_prv_key_s prv, void *key)
{
    return i_cyp_pair_store_prv_key(prv, key);
}

cyp_pub_key_s cyp_pair_get_pub_key(cyp_pair_key_s pair)
{
    return i_cyp_pair_get_pub_key(pair);
}

cyp_prv_key_s cyp_pair_get_prv_key(cyp_pair_key_s pair)
{
    return i_cyp_pair_get_prv_key(pair);
}

int cyp_pair_get_secret(cyp_pub_key_s pub, cyp_prv_key_s prv, void *secret)
{
    return i_cyp_pair_get_secret(pub, prv, secret);
}

int cyp_pair_destroy_key(cyp_pair_key_s pair)
{
    return i_cyp_pair_destroy_key(pair);
}

int cyp_pub_destroy_key(cyp_pub_key_s pub)
{
    return i_cyp_pub_destroy_key(pub);
}

int cyp_prv_destroy_key(cyp_prv_key_s prv)
{
    return i_cyp_prv_destroy_key(prv);
}

int cyp_pub_verify(cyp_pub_key_s pub, void *signature_in, void *expected_out, uint64_t size_signature)
{
    return i_cyp_pub_verify(pub, signature_in, expected_out, size_signature);
}

int cyp_prv_sign(cyp_prv_key_s prv, void *data_in, void *signature_out, uint64_t size_signature)
{
    return i_cyp_prv_sign(prv, data_in, signature_out, size_signature);
}
#endif


// ---------------------------------------
// --- static functions and bindings
// ---------------------------------------

#define STATIC_CYP_RND_ 1
#ifdef STATIC_CYP_RND_
int cyp_rnd_bind(enum CYP_RND_FN fn)
{
    const int ret_no_err = 0;
    const int ret_err = -1;
    switch (fn)
    {
    case CYP_RND_WELL512A:
        cyp_rnd_bind_WELL512a();
        return ret_no_err;
    case CYP_RND_WELL44497A:
        cyp_rnd_bind_WELL44497a();
        return ret_no_err;
    case CYP_RND_WELL44497B:
        cyp_rnd_bind_WELL44497b();
        return ret_no_err;
    default:
        return ret_err;
    }
}

// --- random generator
// --- WELL512a
static enum CYP_RND_FN WELL512a_get_alg()
{
    return CYP_RND_WELL512A;
}

static int WELL512a_get_seed_size()
{
    return SIZE_OF_WELL512*sizeof(uint32_t) + sizeof(uint32_t);
}

static int WELL512a_set_seed(void *seed)
{
    SetSeedWELLRNG512a((uint32_t*)seed);
    return 0;
}

static int WELL512a_get_seed(void *seed)
{
    GetSeedWELLRNG512a((uint32_t*)seed);
    return 0;
}

static uint64_t WELL512a_gen_ul()
{
    return WELLRNG512a_ul();
}

static double WELL512a_gen_d()
{
    return WELLRNG512a_d();
}

int cyp_rnd_bind_WELL512a()
{   
    uint32_t seed[SIZE_OF_WELL512+1]; // TODO: init with noise
    seed[SIZE_OF_WELL512] = 0;
    for (int i = 0; i < SIZE_OF_WELL512; ++i)
        seed[i] = i;
    InitWELLRNG512a(seed);

    i_cyp_rnd_get_alg = WELL512a_get_alg;
    i_cyp_rnd_get_seed_size = WELL512a_get_seed_size;
    i_cyp_rnd_set_seed = WELL512a_set_seed;
    i_cyp_rnd_get_seed = WELL512a_get_seed;
    i_cyp_rnd_gen_ul = WELL512a_gen_ul;
    i_cyp_rnd_gen_d = WELL512a_gen_d;
    return 0;
}
// --- WELL44497a
static enum CYP_RND_FN WELL44497a_get_alg()
{
    return CYP_RND_WELL44497A;
}

static int WELL44497a_get_seed_size()
{
    return SIZE_OF_WELL44497*sizeof(uint32_t) + sizeof(uint32_t);
}

static int WELL44497a_set_seed(void *seed)
{
    SetSeedWELLRNG44497a((uint32_t*)seed);
    return 0;
}

static int WELL44497a_get_seed(void *seed)
{
    GetSeedWELLRNG44497a((uint32_t*)seed);
    return 0;
}

static uint64_t WELL44497a_gen_ul()
{
    return WELLRNG44497a_ul();
}

static double WELL44497a_gen_d()
{
    return WELLRNG44497a_d();
}

int cyp_rnd_bind_WELL44497a()
{   
    uint32_t seed[SIZE_OF_WELL44497+1]; // TODO: init with noise
    seed[SIZE_OF_WELL44497] = 0;
    for (int i = 0; i < SIZE_OF_WELL44497; ++i)
        seed[i] = i;
    InitWELLRNG44497a(seed);

    i_cyp_rnd_get_alg = WELL44497a_get_alg;
    i_cyp_rnd_get_seed_size = WELL44497a_get_seed_size;
    i_cyp_rnd_set_seed = WELL44497a_set_seed;
    i_cyp_rnd_get_seed = WELL44497a_get_seed;
    i_cyp_rnd_gen_ul = WELL44497a_gen_ul;
    i_cyp_rnd_gen_d = WELL44497a_gen_d;
    return 0;
}

// --- WELL44497b
static enum CYP_RND_FN WELL44497b_get_alg()
{
    return CYP_RND_WELL44497B;
}

static int WELL44497b_get_seed_size()
{
    return SIZE_OF_WELL44497*sizeof(uint32_t) + sizeof(uint32_t);
}

static int WELL44497b_set_seed(void *seed)
{
    SetSeedWELLRNG44497b((uint32_t*)seed);
    return 0;
}

static int WELL44497b_get_seed(void *seed)
{
    GetSeedWELLRNG44497b((uint32_t*)seed);
    return 0;
}

static uint64_t WELL44497b_gen_ul()
{
    return WELLRNG44497b_ul();
}

static double WELL44497b_gen_d()
{
    return WELLRNG44497b_d();
}

int cyp_rnd_bind_WELL44497b()
{   
    uint32_t seed[SIZE_OF_WELL44497+1]; // TODO: init with noise
    seed[SIZE_OF_WELL44497] = 0;
    for (int i = 0; i < SIZE_OF_WELL44497; ++i)
        seed[i] = i;
    InitWELLRNG44497b(seed);

    i_cyp_rnd_get_alg = WELL44497b_get_alg;
    i_cyp_rnd_get_seed_size = WELL44497b_get_seed_size;
    i_cyp_rnd_set_seed = WELL44497b_set_seed;
    i_cyp_rnd_get_seed = WELL44497b_get_seed;
    i_cyp_rnd_gen_ul = WELL44497b_gen_ul;
    i_cyp_rnd_gen_d = WELL44497b_gen_d;
    return 0;
}
#endif

#define STATIC_CYP_HASH_ 1
#ifdef STATIC_CYP_HASH_

int cyp_hash_bind(enum CYP_HASH_FN fn)
{
    const int ret_no_err = 0;
    const int ret_err = -1;
    switch (fn)
    {
    case CYP_HASH_SHA3_256:
        cyp_hash_bind_SHA3_256();
        return ret_no_err;
    case CYP_HASH_SHA3_512:
        cyp_hash_bind_SHA3_512();
        return ret_no_err;
    default:
        return ret_err;
    }
}

// --- hashing functions
// --- SHA3 256
static enum CYP_HASH_FN sha3_256_get_alg()
{
    return CYP_HASH_SHA3_256;
}
static int sha3_256_get_size()
{
    return SIZE_OF_SHA3_256*sizeof(uint32_t);
}

static int sha3_256_hash(void *dst, void *src, uint64_t size)
{
    sha3_256(src, size, dst);
    return 0;
}

int cyp_hash_bind_SHA3_256()
{
    i_cyp_hash_get_alg = sha3_256_get_alg;
    i_cyp_hash_get_size = sha3_256_get_size;
    i_cyp_hash = sha3_256_hash;
    return 0;
}

// --- SHA3 512
static enum CYP_HASH_FN sha3_512_get_alg()
{
    return CYP_HASH_SHA3_512;
}

static int sha3_512_get_size()
{
    return SIZE_OF_SHA3_512*sizeof(uint32_t);
}

static int sha3_512_hash(void *dst, void *src, uint64_t size)
{
    sha3_512(src, size, dst);
    return 0;
}

int cyp_hash_bind_SHA3_512()
{
    i_cyp_hash_get_alg = sha3_512_get_alg;
    i_cyp_hash_get_size = sha3_512_get_size;
    i_cyp_hash = sha3_512_hash;
    return 0;
}
#endif

#define STATIC_CYP_SIM_ 1
#ifdef STATIC_CYP_SIM_

int cyp_sim_bind(enum CYP_SIM_FN fn)
{
    const int ret_no_err = 0;
    const int ret_err = -1;
    switch (fn)
    {
    case CYP_SIM_AES256_CBC:
        cyp_sim_bind_AES256_CBC();
        return ret_no_err;
    case CYP_SIM_AES256_ECB:
        cyp_sim_bind_AES256_ECB();
        return ret_no_err;
    case CYP_SIM_AES256_CTR:
        cyp_sim_bind_AES256_CTR();
        return ret_no_err;
    default:
        return ret_err;
    }
}

// --- symmetric cipher
// --- AES256 CBC
static enum CYP_SIM_FN AES256_CBC_get_alg()
{
    return CYP_SIM_AES256_CBC;
}

static int AES256_CBC_get_key_size()
{
    return AES256_KEYLEN;
}

static int AES256_CBC_get_init_size()
{
    return AES_BLOCKLEN;
}

static cyp_sim_key_s AES256_CBC_new_key(void *secret, void *init)
{
    cyp_sim_key_s ret = (cyp_sim_key_s)malloc(sizeof(struct cyp_sim_key_));
    ret->ctx = malloc(sizeof(aes256_context));
    aes256_init((aes256_context*)ret->ctx, (uint8_t*)secret);
    aes256_init_iv((aes256_context*)ret->ctx, (uint8_t*)init);
    return ret;
}

static int AES256_CBC_destroy_key(cyp_sim_key_s key)
{
    aes256_done((aes256_context*)key->ctx);
    free(key->ctx);
    free(key);
    return 0;
}

static int AES256_CBC_encrypt(cyp_sim_key_s key, void *data_in, void *cyphered_out, uint64_t size_in)
{
    if (size_in % AES_BLOCKLEN)
    {
        fprintf(stderr, "AES256_CBC_encrypt: data size must be multiple of %i\n", AES_BLOCKLEN);
        return -1;
    }
    if (data_in != cyphered_out)
    {
        memcpy(cyphered_out, data_in, size_in);
    }
    aes256_encrypt_cbc((aes256_context*)key->ctx, (uint8_t*)cyphered_out, size_in);
    return 0;
}

static int AES256_CBC_decrypt(cyp_sim_key_s key, void *cyphered_in, void *data_out, uint64_t size_in)
{
    if (size_in % AES_BLOCKLEN)
    {
        fprintf(stderr, "AES256_CBC_decrypt: data size must be multiple of %i\n", AES_BLOCKLEN);
        return -1;
    }
    if (cyphered_in != data_out)
    {
        memcpy(data_out, cyphered_in, size_in);
    }
    aes256_decrypt_cbc((aes256_context*)key->ctx, (uint8_t*)data_out, size_in);
    return 0;
}

int cyp_sim_bind_AES256_CBC()
{
    i_cyp_sim_get_alg = AES256_CBC_get_alg;
    i_cyp_sim_get_key_size = AES256_CBC_get_key_size;
    i_cyp_sim_get_init_size = AES256_CBC_get_init_size;
    i_cyp_sim_new_key = AES256_CBC_new_key;
    i_cyp_sim_destroy_key = AES256_CBC_destroy_key;
    i_cyp_sim_encrypt = AES256_CBC_encrypt;
    i_cyp_sim_decrypt = AES256_CBC_decrypt;
    return 0;
}

// --- simetric cipher
// --- AES256 ECB
static enum CYP_SIM_FN AES256_ECB_get_alg()
{
    return CYP_SIM_AES256_ECB;
}

static int AES256_ECB_get_key_size()
{
    return AES256_KEYLEN;
}

static int AES256_ECB_get_init_size()
{
    return AES_BLOCKLEN;
}

static cyp_sim_key_s AES256_ECB_new_key(void *secret, void *init)
{
    cyp_sim_key_s ret = (cyp_sim_key_s)malloc(sizeof(struct cyp_sim_key_));
    ret->ctx = malloc(sizeof(aes256_context));
    aes256_init((aes256_context*)ret->ctx, (uint8_t*)secret);
    return ret;
}

static int AES256_ECB_destroy_key(cyp_sim_key_s key)
{
    aes256_done((aes256_context*)key->ctx);
    free(key->ctx);
    free(key);
    return 0;
}

static int i_AES256_ECB_encrypt(cyp_sim_key_s key, void *data_in, void *cyphered_out, uint64_t size_in)
{
    if (size_in % AES_BLOCKLEN)
    {
        fprintf(stderr, "AES256_ECB_encrypt: data size must be multiple of %i\n", AES_BLOCKLEN);
        return -1;
    }
    if (data_in != cyphered_out)
    {
        memcpy(cyphered_out, data_in, size_in);
    }
    for (uintptr_t p = (uintptr_t)cyphered_out; p < ((uintptr_t)cyphered_out)+size_in; p += AES_BLOCKLEN)
    {
        aes256_encrypt_ecb((aes256_context*)key->ctx, (uint8_t*)p);
    }
    return 0;
}

static int i_AES256_ECB_decrypt(cyp_sim_key_s key, void *cyphered_in, void *data_out, uint64_t size_in)
{
    if (size_in % AES_BLOCKLEN)
    {
        fprintf(stderr, "AES256_ECB_decrypt: data size must be multiple of %i\n", AES_BLOCKLEN);
        return -1;
    }
    if (cyphered_in != data_out)
    {
        memcpy(data_out, cyphered_in, size_in);
    }
    for (uintptr_t p = (uintptr_t)data_out; p < ((uintptr_t)data_out)+size_in; p += AES_BLOCKLEN)
    {
        aes256_decrypt_ecb((aes256_context*)key->ctx, (uint8_t*)p);
    }
    return 0;
}

int cyp_sim_bind_AES256_ECB()
{
    i_cyp_sim_get_alg = AES256_ECB_get_alg;
    i_cyp_sim_get_key_size = AES256_ECB_get_key_size;
    i_cyp_sim_get_init_size = AES256_ECB_get_init_size;
    i_cyp_sim_new_key = AES256_ECB_new_key;
    i_cyp_sim_destroy_key = AES256_ECB_destroy_key;
    i_cyp_sim_encrypt = i_AES256_ECB_encrypt;
    i_cyp_sim_decrypt = i_AES256_ECB_decrypt;
    return 0;
}

// --- simetric cipher
// --- AES256 CTR

static enum CYP_SIM_FN AES256_CTR_get_alg()
{
    return CYP_SIM_AES256_CTR;
}

static int AES256_CTR_get_key_size()
{
    return AES256_KEYLEN;
}

static int AES256_CTR_get_init_size()
{
    return AES_BLOCKLEN;
}

static cyp_sim_key_s AES256_CTR_new_key(void *secret, void *init)
{
    cyp_sim_key_s ret = (cyp_sim_key_s)malloc(sizeof(struct cyp_sim_key_));
    ret->ctx = malloc(sizeof(aes256_context));
    aes256_init((aes256_context*)ret->ctx, (uint8_t*)secret);
    aes256_init_iv((aes256_context*)ret->ctx, (uint8_t*)init);
    return ret;
}

static int AES256_CTR_destroy_key(cyp_sim_key_s key)
{
    aes256_done((aes256_context*)key->ctx);
    free(key->ctx);
    free(key);
    return 0;
}

static int AES256_CTR_encrypt(cyp_sim_key_s key, void *data_in, void *cyphered_out, uint64_t size_in)
{
    if (size_in % AES_BLOCKLEN)
    {
        fprintf(stderr, "AES256_CTR_encrypt: data size must be multiple of %i\n", AES_BLOCKLEN);
        return -1;
    }
    if (data_in != cyphered_out)
    {
        memcpy(cyphered_out, data_in, size_in);
    }
    aes256_xcrypt_ctr((aes256_context*)key->ctx, (uint8_t*)cyphered_out, size_in);
    return 0;
}

static int AES256_CTR_decrypt(cyp_sim_key_s key, void *cyphered_in, void *data_out, uint64_t size_in)
{
    if (size_in % AES_BLOCKLEN)
    {
        fprintf(stderr, "AES256_CTR_decrypt: data size must be multiple of %i\n", AES_BLOCKLEN);
        return -1;
    }
    if (cyphered_in != data_out)
    {
        memcpy(data_out, cyphered_in, size_in);
    }
    aes256_xcrypt_ctr((aes256_context*)key->ctx, (uint8_t*)data_out, size_in);
    return 0;
}

int cyp_sim_bind_AES256_CTR()
{
    i_cyp_sim_get_alg = AES256_CTR_get_alg;
    i_cyp_sim_get_key_size = AES256_CTR_get_key_size;
    i_cyp_sim_get_init_size = AES256_CTR_get_init_size;
    i_cyp_sim_new_key = AES256_CTR_new_key;
    i_cyp_sim_destroy_key = AES256_CTR_destroy_key;
    i_cyp_sim_encrypt = AES256_CTR_encrypt;
    i_cyp_sim_decrypt = AES256_CTR_decrypt;
    return 0;
}
#endif

#define STATIC_CYP_PAIR_ 1
#ifdef STATIC_CYP_PAIR_

int cyp_pair_bind(enum CYP_PAIR_FN fn)
{
    const int ret_no_err = 0;
    const int ret_err = -1;
    switch (fn)
    {
    case CYP_PAIR_ECC_SECP160R1:
        cyp_pair_bind_ECC_secp160r1();
        return ret_no_err;
    case CYP_PAIR_ECC_SECP192R1:
        cyp_pair_bind_ECC_secp192r1();
        return ret_no_err;
    case CYP_PAIR_ECC_SECP224R1:
        cyp_pair_bind_ECC_secp224r1();
        return ret_no_err;
    case CYP_PAIR_ECC_SECP256K1:
        cyp_pair_bind_ECC_secp256k1();
        return ret_no_err;
    default:
        return ret_err;
    }
}

// --- asymmetric cipher
// --- ECC secp160r1

static enum CYP_PAIR_FN ECC_secp160r1_get_alg()
{
    return CYP_PAIR_ECC_SECP160R1;
}

static int ECC_secp160r1_get_pub_key_size()
{
    return SIZE_OF_ECC_SECP160R1_C_PRV_K;
}

static int ECC_secp160r1_get_prv_key_size()
{
    return SIZE_OF_ECC_SECP160R1_C_PUB_K;
}

static int ECC_secp160r1_get_secret_size()
{
    return SIZE_OF_ECC_SECP160R1_C_PRV_K;
}

static int ECC_secp160r1_destroy_pair_key(cyp_pair_key_s pair)
{
    free(pair->pub.k);
    free(pair->prv.k);
    free(pair);
    return 0;
}

static cyp_pair_key_s ECC_secp160r1_new_key()
{
    cyp_pair_key_s ret;
    ret = (cyp_pair_key_s)malloc(sizeof(struct cyp_pair_key_));
    int sizePub = SIZE_OF_ECC_SECP160R1_I_PUB_K;
    int sizePrv = SIZE_OF_ECC_SECP160R1_I_PRV_K;
    if (sizePub % 8)
        sizePub = sizePub + (8 - (sizePub % 8));
    if (sizePrv % 8)
        sizePrv = sizePrv + (8 - (sizePrv % 8));
    ret->pub.k = malloc(sizePub);
    ret->prv.k = malloc(sizePrv);
    int ok = uECC_make_key(ret->pub.k, ret->prv.k, uECC_secp160r1());
    if (!ok)
    {
        fprintf(stderr, "Error producing the key pair\n");
        ECC_secp160r1_destroy_pair_key(ret);
        ret = NULL;
    }
    return ret;
}

static cyp_pub_key_s ECC_secp160r1_load_pub_key(void *key)
{
    cyp_pub_key_s ret;
    ret = (cyp_pub_key_s)malloc(sizeof(struct cyp_pub_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP160R1_I_PUB_K);
    uECC_decompress((const uint8_t*)key, (uint8_t*)ret->k, uECC_secp160r1());
    return ret;
}

static cyp_prv_key_s ECC_secp160r1_load_prv_key(void *key)
{
    cyp_prv_key_s ret;
    ret = (cyp_prv_key_s)malloc(sizeof(struct cyp_prv_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP160R1_I_PRV_K);
    memcpy(ret->k, key, SIZE_OF_ECC_SECP160R1_I_PRV_K);
    return ret;
}

static int ECC_secp160r1_store_pub_key(cyp_pub_key_s pub, void *key)
{
    uECC_compress((const uint8_t*)pub->k, (uint8_t*)key, uECC_secp160r1());
    return 0;
}

static int ECC_secp160r1_store_prv_key(cyp_prv_key_s prv, void *key)
{
    memcpy(key, prv->k, SIZE_OF_ECC_SECP160R1_I_PRV_K);
    return 0;
}

static cyp_pub_key_s ECC_secp160r1_get_pub_key(cyp_pair_key_s pair)
{
    cyp_pub_key_s ret;
    ret = (cyp_pub_key_s)malloc(sizeof(struct cyp_pub_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP160R1_I_PUB_K);
    memcpy(ret->k, pair->pub.k, SIZE_OF_ECC_SECP160R1_I_PUB_K);
    return ret;
}

static cyp_prv_key_s ECC_secp160r1_get_prv_key(cyp_pair_key_s pair)
{
    cyp_prv_key_s ret;
    ret = (cyp_prv_key_s)malloc(sizeof(struct cyp_prv_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP160R1_I_PRV_K);
    memcpy(ret->k, pair->prv.k, SIZE_OF_ECC_SECP160R1_I_PRV_K);
    return ret;
}

static int ECC_secp160r1_get_secret(cyp_pub_key_s pub, cyp_prv_key_s prv, void *secret)
{
    int valid = uECC_shared_secret((const uint8_t*)pub->k, (const uint8_t*)prv->k, (uint8_t*)secret, uECC_secp160r1());
    return valid ? 0 : -1;
}

static int ECC_secp160r1_destroy_pub_key(cyp_pub_key_s pub)
{
    free(pub->k);
    free(pub);
    return 0;
}

static int ECC_secp160r1_destroy_prv_key(cyp_prv_key_s prv)
{
    free(prv->k);
    free(prv);
    return 0;
}

static int ECC_secp160r1_verify(cyp_pub_key_s pub, void *signature_in, void *expected_out, uint64_t size_signature)
{
    int valid = uECC_verify((const uint8_t*)pub->k,
                (const uint8_t*)expected_out,
                (unsigned)size_signature,
                (const uint8_t*)signature_in,
                uECC_secp160r1());
    return valid;
}

static int ECC_secp160r1_sign(cyp_prv_key_s prv, void *data_in, void *signature_out, uint64_t size_data)
{
    uint8_t tmp_buf[size_data*2+SIZE_OF_ECC_SECP192R1_I_PRV_K];
    void *p = signature_out;
    if (data_in == signature_out)
    {
        p = (void*)tmp_buf;
    }
    int valid = uECC_sign((const uint8_t*)prv->k,
              (const uint8_t*)data_in,
              (unsigned)size_data,
              (uint8_t*)p,
              uECC_secp160r1());
    if (data_in == signature_out)
    {
        memcpy(signature_out, p, size_data);
    }
    return valid ? 0 : -1;
}

int cyp_pair_bind_ECC_secp160r1()
{
    i_cyp_pair_get_alg           = ECC_secp160r1_get_alg;
    i_cyp_pub_get_key_size       = ECC_secp160r1_get_pub_key_size;
    i_cyp_prv_get_key_size       = ECC_secp160r1_get_prv_key_size;
    i_cyp_pair_get_secret_size   = ECC_secp160r1_get_secret_size;
    i_cyp_pair_new_key           = ECC_secp160r1_new_key;
    i_cyp_pair_load_pub_key      = ECC_secp160r1_load_pub_key;
    i_cyp_pair_load_prv_key      = ECC_secp160r1_load_prv_key;
    i_cyp_pair_store_pub_key     = ECC_secp160r1_store_pub_key;
    i_cyp_pair_store_prv_key     = ECC_secp160r1_store_prv_key;
    i_cyp_pair_get_pub_key       = ECC_secp160r1_get_pub_key;
    i_cyp_pair_get_prv_key       = ECC_secp160r1_get_prv_key;
    i_cyp_pair_get_secret        = ECC_secp160r1_get_secret;
    i_cyp_pair_destroy_key       = ECC_secp160r1_destroy_pair_key;
    i_cyp_pub_destroy_key        = ECC_secp160r1_destroy_pub_key;
    i_cyp_prv_destroy_key        = ECC_secp160r1_destroy_prv_key;
    i_cyp_pub_verify             = ECC_secp160r1_verify;
    i_cyp_prv_sign               = ECC_secp160r1_sign;
    return 0;
}

// --- asymmetric cipher
// --- ECC secp192r1

static enum CYP_PAIR_FN ECC_secp192r1_get_alg()
{
    return CYP_PAIR_ECC_SECP192R1;
}

static int ECC_secp192r1_get_pub_key_size()
{
    return SIZE_OF_ECC_SECP192R1_C_PUB_K;
}

static int ECC_secp192r1_get_prv_key_size()
{
    return SIZE_OF_ECC_SECP192R1_C_PRV_K;
}

static int ECC_secp192r1_get_secret_size()
{
    return uECC_curve_private_key_size(uECC_secp192r1());
}

static int ECC_secp192r1_destroy_pair_key(cyp_pair_key_s pair)
{
    free(pair->pub.k);
    free(pair->prv.k);
    free(pair);
    return 0;
}

static cyp_pair_key_s ECC_secp192r1_new_key()
{
    cyp_pair_key_s ret;
    ret = (cyp_pair_key_s)malloc(sizeof(struct cyp_pair_key_));
    int sizePub = SIZE_OF_ECC_SECP192R1_I_PUB_K;
    int sizePrv = SIZE_OF_ECC_SECP192R1_I_PRV_K;
    if (sizePub % 8)
        sizePub = sizePub + (8 - (sizePub % 8));
    if (sizePrv % 8)
        sizePrv = sizePrv + (8 - (sizePrv % 8));
    ret->pub.k = malloc(sizePub);
    ret->prv.k = malloc(sizePrv);
    int ok = uECC_make_key(ret->pub.k, ret->prv.k, uECC_secp192r1());
    if (!ok)
    {
        fprintf(stderr, "Error producing the key pair\n");
        ECC_secp192r1_destroy_pair_key(ret);
        ret = NULL;
    }
    return ret;
}

static cyp_pub_key_s ECC_secp192r1_load_pub_key(void *key)
{
    cyp_pub_key_s ret;
    ret = (cyp_pub_key_s)malloc(sizeof(struct cyp_pub_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP192R1_I_PUB_K);
    uECC_decompress((const uint8_t*)key, (uint8_t*)ret->k, uECC_secp192r1());
    return ret;
}

static cyp_prv_key_s ECC_secp192r1_load_prv_key(void *key)
{
    cyp_prv_key_s ret;
    ret = (cyp_prv_key_s)malloc(sizeof(struct cyp_prv_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP192R1_I_PRV_K);
    memcpy(ret->k, key, SIZE_OF_ECC_SECP192R1_I_PRV_K);
    return ret;
}

static int ECC_secp192r1_store_pub_key(cyp_pub_key_s pub, void *key)
{
    uECC_compress((const uint8_t*)pub->k, (uint8_t*)key, uECC_secp192r1());
    return 0;
}

static int ECC_secp192r1_store_prv_key(cyp_prv_key_s prv, void *key)
{
    memcpy(key, prv->k, SIZE_OF_ECC_SECP192R1_I_PRV_K);
    return 0;
}

static cyp_pub_key_s ECC_secp192r1_get_pub_key(cyp_pair_key_s pair)
{
    cyp_pub_key_s ret;
    ret = (cyp_pub_key_s)malloc(sizeof(struct cyp_pub_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP192R1_I_PUB_K);
    memcpy(ret->k, pair->pub.k, SIZE_OF_ECC_SECP192R1_I_PUB_K);
    return ret;
}

static cyp_prv_key_s ECC_secp192r1_get_prv_key(cyp_pair_key_s pair)
{
    cyp_prv_key_s ret;
    ret = (cyp_prv_key_s)malloc(sizeof(struct cyp_prv_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP192R1_I_PRV_K);
    memcpy(ret->k, pair->prv.k, SIZE_OF_ECC_SECP192R1_I_PRV_K);
    return ret;
}

static int ECC_secp192r1_get_secret(cyp_pub_key_s pub, cyp_prv_key_s prv, void *secret)
{
    int valid = uECC_shared_secret((const uint8_t*)pub->k, (const uint8_t*)prv->k, (uint8_t*)secret, uECC_secp192r1());
    return valid ? 0 : -1;
}

static int ECC_secp192r1_destroy_pub_key(cyp_pub_key_s pub)
{
    free(pub->k);
    free(pub);
    return 0;
}

static int ECC_secp192r1_destroy_prv_key(cyp_prv_key_s prv)
{
    free(prv->k);
    free(prv);
    return 0;
}

static int ECC_secp192r1_verify(cyp_pub_key_s pub, void *signature_in, void *expected_out, uint64_t size_signature)
{
    int valid = uECC_verify((const uint8_t*)pub->k,
                (const uint8_t*)expected_out,
                (unsigned)size_signature,
                (const uint8_t*)signature_in,
                uECC_secp192r1());
    return valid;
}

static int ECC_secp192r1_sign(cyp_prv_key_s prv, void *data_in, void *signature_out, uint64_t size_data)
{
    uint8_t tmp_buf[size_data*2+SIZE_OF_ECC_SECP192R1_I_PRV_K];
    void *p = signature_out;
    if (data_in == signature_out)
    {
        p = (void*)tmp_buf;
    }
    int valid = uECC_sign((const uint8_t*)prv->k,
              (const uint8_t*)data_in,
              (unsigned)size_data,
              (uint8_t*)p,
              uECC_secp192r1());
    if (data_in == signature_out)
    {
        memcpy(signature_out, p, size_data);
    }
    return valid ? 0 : -1;
}

int cyp_pair_bind_ECC_secp192r1()
{
    i_cyp_pair_get_alg           = ECC_secp192r1_get_alg;
    i_cyp_pub_get_key_size       = ECC_secp192r1_get_pub_key_size;
    i_cyp_prv_get_key_size       = ECC_secp192r1_get_prv_key_size;
    i_cyp_pair_get_secret_size   = ECC_secp192r1_get_secret_size;
    i_cyp_pair_new_key           = ECC_secp192r1_new_key;
    i_cyp_pair_load_pub_key      = ECC_secp192r1_load_pub_key;
    i_cyp_pair_load_prv_key      = ECC_secp192r1_load_prv_key;
    i_cyp_pair_store_pub_key     = ECC_secp192r1_store_pub_key;
    i_cyp_pair_store_prv_key     = ECC_secp192r1_store_prv_key;
    i_cyp_pair_get_pub_key       = ECC_secp192r1_get_pub_key;
    i_cyp_pair_get_prv_key       = ECC_secp192r1_get_prv_key;
    i_cyp_pair_get_secret        = ECC_secp192r1_get_secret;
    i_cyp_pair_destroy_key       = ECC_secp192r1_destroy_pair_key;
    i_cyp_pub_destroy_key        = ECC_secp192r1_destroy_pub_key;
    i_cyp_prv_destroy_key        = ECC_secp192r1_destroy_prv_key;
    i_cyp_pub_verify             = ECC_secp192r1_verify;
    i_cyp_prv_sign               = ECC_secp192r1_sign;
    return 0;
}

// --- asymmetric cipher
// --- ECC secp224r1

static enum CYP_PAIR_FN ECC_secp224r1_get_alg()
{
    return CYP_PAIR_ECC_SECP224R1;
}

static int ECC_secp224r1_get_pub_key_size()
{
    return SIZE_OF_ECC_SECP224R1_C_PUB_K;
}

static int ECC_secp224r1_get_prv_key_size()
{
    return SIZE_OF_ECC_SECP224R1_C_PRV_K;
}

static int ECC_secp224r1_get_secret_size()
{
    return uECC_curve_private_key_size(uECC_secp224r1());
}

static int ECC_secp224r1_destroy_pair_key(cyp_pair_key_s pair)
{
    free(pair->pub.k);
    free(pair->prv.k);
    free(pair);
    return 0;
}

static cyp_pair_key_s ECC_secp224r1_new_key()
{
    cyp_pair_key_s ret;
    ret = (cyp_pair_key_s)malloc(sizeof(struct cyp_pair_key_));
    int sizePub = SIZE_OF_ECC_SECP224R1_I_PUB_K;
    int sizePrv = SIZE_OF_ECC_SECP224R1_I_PRV_K;
    if (sizePub % 8)
        sizePub = sizePub + (8 - (sizePub % 8));
    if (sizePrv % 8)
        sizePrv = sizePrv + (8 - (sizePrv % 8));
    ret->pub.k = malloc(sizePub);
    ret->prv.k = malloc(sizePrv);
    int ok = uECC_make_key(ret->pub.k, ret->prv.k, uECC_secp224r1());
    if (!ok)
    {
        fprintf(stderr, "Error producing the key pair\n");
        ECC_secp224r1_destroy_pair_key(ret);
        ret = NULL;
    }
    return ret;
}

static cyp_pub_key_s ECC_secp224r1_load_pub_key(void *key)
{
    cyp_pub_key_s ret;
    ret = (cyp_pub_key_s)malloc(sizeof(struct cyp_pub_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP224R1_I_PUB_K);
    uECC_decompress((const uint8_t*)key, (uint8_t*)ret->k, uECC_secp224r1());
    return ret;
}

static cyp_prv_key_s ECC_secp224r1_load_prv_key(void *key)
{
    cyp_prv_key_s ret;
    ret = (cyp_prv_key_s)malloc(sizeof(struct cyp_prv_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP224R1_I_PRV_K);
    memcpy(ret->k, key, SIZE_OF_ECC_SECP224R1_I_PRV_K);
    return ret;
}

static int ECC_secp224r1_store_pub_key(cyp_pub_key_s pub, void *key)
{
    uECC_compress((const uint8_t*)pub->k, (uint8_t*)key, uECC_secp224r1());
    return 0;
}

static int ECC_secp224r1_store_prv_key(cyp_prv_key_s prv, void *key)
{
    memcpy(key, prv->k, SIZE_OF_ECC_SECP224R1_I_PRV_K);
    return 0;
}

static cyp_pub_key_s ECC_secp224r1_get_pub_key(cyp_pair_key_s pair)
{
    cyp_pub_key_s ret;
    ret = (cyp_pub_key_s)malloc(sizeof(struct cyp_pub_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP224R1_I_PUB_K);
    memcpy(ret->k, pair->pub.k, SIZE_OF_ECC_SECP224R1_I_PUB_K);
    return ret;
}

static cyp_prv_key_s ECC_secp224r1_get_prv_key(cyp_pair_key_s pair)
{
    cyp_prv_key_s ret;
    ret = (cyp_prv_key_s)malloc(sizeof(struct cyp_prv_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP224R1_I_PRV_K);
    memcpy(ret->k, pair->prv.k, SIZE_OF_ECC_SECP224R1_I_PRV_K);
    return ret;
}

static int ECC_secp224r1_get_secret(cyp_pub_key_s pub, cyp_prv_key_s prv, void *secret)
{
    int valid = uECC_shared_secret((const uint8_t*)pub->k, (const uint8_t*)prv->k, (uint8_t*)secret, uECC_secp224r1());
    return valid ? 0 : -1;
}

static int ECC_secp224r1_destroy_pub_key(cyp_pub_key_s pub)
{
    free(pub->k);
    free(pub);
    return 0;
}

static int ECC_secp224r1_destroy_prv_key(cyp_prv_key_s prv)
{
    free(prv->k);
    free(prv);
    return 0;
}

static int ECC_secp224r1_verify(cyp_pub_key_s pub, void *signature_in, void *expected_out, uint64_t size_signature)
{
    int valid = uECC_verify((const uint8_t*)pub->k,
                (const uint8_t*)expected_out,
                (unsigned)size_signature,
                (const uint8_t*)signature_in,
                uECC_secp224r1());
    return valid;
}

static int ECC_secp224r1_sign(cyp_prv_key_s prv, void *data_in, void *signature_out, uint64_t size_data)
{
    uint8_t tmp_buf[size_data*2+SIZE_OF_ECC_SECP224R1_I_PRV_K];
    void *p = signature_out;
    if (data_in == signature_out)
    {
        p = (void*)tmp_buf;
    }
    int valid = uECC_sign((const uint8_t*)prv->k,
              (const uint8_t*)data_in,
              (unsigned)size_data,
              (uint8_t*)p,
              uECC_secp224r1());
    if (data_in == signature_out)
    {
        memcpy(signature_out, p, size_data);
    }
    return valid ? 0 : -1;
}

int cyp_pair_bind_ECC_secp224r1()
{
    i_cyp_pair_get_alg           = ECC_secp224r1_get_alg;
    i_cyp_pub_get_key_size       = ECC_secp224r1_get_pub_key_size;
    i_cyp_prv_get_key_size       = ECC_secp224r1_get_prv_key_size;
    i_cyp_pair_get_secret_size   = ECC_secp224r1_get_secret_size;
    i_cyp_pair_new_key           = ECC_secp224r1_new_key;
    i_cyp_pair_load_pub_key      = ECC_secp224r1_load_pub_key;
    i_cyp_pair_load_prv_key      = ECC_secp224r1_load_prv_key;
    i_cyp_pair_store_pub_key     = ECC_secp224r1_store_pub_key;
    i_cyp_pair_store_prv_key     = ECC_secp224r1_store_prv_key;
    i_cyp_pair_get_pub_key       = ECC_secp224r1_get_pub_key;
    i_cyp_pair_get_prv_key       = ECC_secp224r1_get_prv_key;
    i_cyp_pair_get_secret        = ECC_secp224r1_get_secret;
    i_cyp_pair_destroy_key       = ECC_secp224r1_destroy_pair_key;
    i_cyp_pub_destroy_key        = ECC_secp224r1_destroy_pub_key;
    i_cyp_prv_destroy_key        = ECC_secp224r1_destroy_prv_key;
    i_cyp_pub_verify             = ECC_secp224r1_verify;
    i_cyp_prv_sign               = ECC_secp224r1_sign;
    return 0;
}

// --- asymmetric cipher
// --- ECC secp256k1

static enum CYP_PAIR_FN ECC_secp256k1_get_alg()
{
    return CYP_PAIR_ECC_SECP256K1;
}

static int ECC_secp256k1_get_pub_key_size()
{
    return SIZE_OF_ECC_SECP256K1_C_PUB_K;
}

static int ECC_secp256k1_get_prv_key_size()
{
    return SIZE_OF_ECC_SECP256K1_C_PRV_K;
}

static int ECC_secp256k1_get_secret_size()
{
    return uECC_curve_private_key_size(uECC_secp256k1());
}

static int ECC_secp256k1_destroy_pair_key(cyp_pair_key_s pair)
{
    free(pair->pub.k);
    free(pair->prv.k);
    free(pair);
    return 0;
}

static cyp_pair_key_s ECC_secp256k1_new_key()
{
    cyp_pair_key_s ret;
    ret = (cyp_pair_key_s)malloc(sizeof(struct cyp_pair_key_));
    int sizePub = SIZE_OF_ECC_SECP256K1_I_PUB_K;
    int sizePrv = SIZE_OF_ECC_SECP256K1_I_PRV_K;
    if (sizePub % 8)
        sizePub = sizePub + (8 - (sizePub % 8));
    if (sizePrv % 8)
        sizePrv = sizePrv + (8 - (sizePrv % 8));
    ret->pub.k = malloc(sizePub);
    ret->prv.k = malloc(sizePrv);
    int ok = uECC_make_key(ret->pub.k, ret->prv.k, uECC_secp256k1());
    if (!ok)
    {
        fprintf(stderr, "Error producing the key pair\n");
        ECC_secp256k1_destroy_pair_key(ret);
        ret = NULL;
    }
    return ret;
}

static cyp_pub_key_s ECC_secp256k1_load_pub_key(void *key)
{
    cyp_pub_key_s ret;
    ret = (cyp_pub_key_s)malloc(sizeof(struct cyp_pub_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP256K1_I_PUB_K);
    uECC_decompress((const uint8_t*)key, (uint8_t*)ret->k, uECC_secp256k1());
    return ret;
}

static cyp_prv_key_s ECC_secp256k1_load_prv_key(void *key)
{
    cyp_prv_key_s ret;
    ret = (cyp_prv_key_s)malloc(sizeof(struct cyp_prv_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP256K1_I_PRV_K);
    memcpy(ret->k, key, SIZE_OF_ECC_SECP256K1_I_PRV_K);
    return ret;
}

static int ECC_secp256k1_store_pub_key(cyp_pub_key_s pub, void *key)
{
    uECC_compress((const uint8_t*)pub->k, (uint8_t*)key, uECC_secp256k1());
    return 0;
}

static int ECC_secp256k1_store_prv_key(cyp_prv_key_s prv, void *key)
{
    memcpy(key, prv->k, SIZE_OF_ECC_SECP256K1_I_PRV_K);
    return 0;
}

static cyp_pub_key_s ECC_secp256k1_get_pub_key(cyp_pair_key_s pair)
{
    cyp_pub_key_s ret;
    ret = (cyp_pub_key_s)malloc(sizeof(struct cyp_pub_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP256K1_I_PUB_K);
    memcpy(ret->k, pair->pub.k, SIZE_OF_ECC_SECP256K1_I_PUB_K);
    return ret;
}

static cyp_prv_key_s ECC_secp256k1_get_prv_key(cyp_pair_key_s pair)
{
    cyp_prv_key_s ret;
    ret = (cyp_prv_key_s)malloc(sizeof(struct cyp_prv_key_));
    ret->k = malloc(SIZE_OF_ECC_SECP256K1_I_PRV_K);
    memcpy(ret->k, pair->prv.k, SIZE_OF_ECC_SECP256K1_I_PRV_K);
    return ret;
}

static int ECC_secp256k1_get_secret(cyp_pub_key_s pub, cyp_prv_key_s prv, void *secret)
{
    int valid = uECC_shared_secret((const uint8_t*)pub->k, (const uint8_t*)prv->k, (uint8_t*)secret, uECC_secp256k1());
    return valid ? 0 : -1;
}

static int ECC_secp256k1_destroy_pub_key(cyp_pub_key_s pub)
{
    free(pub->k);
    free(pub);
    return 0;
}

static int ECC_secp256k1_destroy_prv_key(cyp_prv_key_s prv)
{
    free(prv->k);
    free(prv);
    return 0;
}

static int ECC_secp256k1_verify(cyp_pub_key_s pub, void *signature_in, void *expected_out, uint64_t size_signature)
{
    int valid = uECC_verify((const uint8_t*)pub->k,
                (const uint8_t*)expected_out,
                (unsigned)size_signature,
                (const uint8_t*)signature_in,
                uECC_secp256k1());
    return valid;
}

static int ECC_secp256k1_sign(cyp_prv_key_s prv, void *data_in, void *signature_out, uint64_t size_data)
{
    uint8_t tmp_buf[size_data*2+SIZE_OF_ECC_SECP256K1_I_PRV_K];
    void *p = signature_out;
    if (data_in == signature_out)
    {
        p = (void*)tmp_buf;
    }
    int valid = uECC_sign((const uint8_t*)prv->k,
              (const uint8_t*)data_in,
              (unsigned)size_data,
              (uint8_t*)p,
              uECC_secp256k1());
    if (data_in == signature_out)
    {
        memcpy(signature_out, p, size_data);
    }
    return valid ? 0 : -1;
}

int cyp_pair_bind_ECC_secp256k1()
{
    i_cyp_pair_get_alg           = ECC_secp256k1_get_alg;
    i_cyp_pub_get_key_size       = ECC_secp256k1_get_pub_key_size;
    i_cyp_prv_get_key_size       = ECC_secp256k1_get_prv_key_size;
    i_cyp_pair_get_secret_size   = ECC_secp256k1_get_secret_size;
    i_cyp_pair_new_key           = ECC_secp256k1_new_key;
    i_cyp_pair_load_pub_key      = ECC_secp256k1_load_pub_key;
    i_cyp_pair_load_prv_key      = ECC_secp256k1_load_prv_key;
    i_cyp_pair_store_pub_key     = ECC_secp256k1_store_pub_key;
    i_cyp_pair_store_prv_key     = ECC_secp256k1_store_prv_key;
    i_cyp_pair_get_pub_key       = ECC_secp256k1_get_pub_key;
    i_cyp_pair_get_prv_key       = ECC_secp256k1_get_prv_key;
    i_cyp_pair_get_secret        = ECC_secp256k1_get_secret;
    i_cyp_pair_destroy_key       = ECC_secp256k1_destroy_pair_key;
    i_cyp_pub_destroy_key        = ECC_secp256k1_destroy_pub_key;
    i_cyp_prv_destroy_key        = ECC_secp256k1_destroy_prv_key;
    i_cyp_pub_verify             = ECC_secp256k1_verify;
    i_cyp_prv_sign               = ECC_secp256k1_sign;
    return 0;
}

#endif

// ---------------------------------------
// ---------------------------------------
// ---------------------------------------

