#ifndef CYPHER_H_GUARD_
#define CYPHER_H_GUARD_

#include <stdint.h>

#define CYP_RND_NB_FNS 2
enum CYP_RND_FN
{
    CYP_RND_WELL44497A = 0,
    CYP_RND_WELL44497B = 1
};
extern const char *CYP_RND_FN_NAMES[CYP_RND_NB_FNS]; // use this array to retrive the CYP_RND_FN string

#define CYP_HASH_NB_FNS 2
enum CYP_HASH_FN
{
    CYP_HASH_SHA3_256 = 0,
    CYP_HASH_SHA3_512 = 1
};
extern const char *CYP_HASH_FN_NAMES[CYP_HASH_NB_FNS]; // use this array to retrive the CYP_RND_FN string

#define CYP_SIM_NB_FNS 3
enum CYP_SIM_FN
{
    CYP_SIM_AES256_CBC = 0,
    CYP_SIM_AES256_ECB = 1,
    CYP_SIM_AES256_CTR = 2
};
extern const char *CYP_SIM_FN_NAMES[CYP_SIM_NB_FNS]; // use this array to retrive the CYP_RND_FN string

#define CYP_PAIR_NB_FNS 4
enum CYP_PAIR_FN
{
    CYP_PAIR_ECC_SECP160R1 = 0,
    CYP_PAIR_ECC_SECP192R1 = 1,
    CYP_PAIR_ECC_SECP224R1 = 2,
    CYP_PAIR_ECC_SECP256K1 = 3
};
extern const char *CYP_PAIR_FN_NAMES[CYP_PAIR_NB_FNS]; // use this array to retrive the CYP_RND_FN string


// the bindings are thread_local: you need to init on every thread
int cyp_init();

// deterministic random number generator
enum CYP_RND_FN cyp_rnd_get_alg();
int cyp_rnd_get_seed_size(); // in bytes
int cyp_rnd_set_seed(void *seed); // buffer must match seed size
int cyp_rnd_get_seed(void *seed); // buffer must match seed size
uint64_t cyp_rnd_gen_ul(); // between 0 and 0xFFFFFFFFFFFFFFFFL
double cyp_rnd_gen_d(); // between 0.0 and 1.0

// hashing function
enum CYP_HASH_FN cyp_hash_get_alg();
int cyp_hash_get_size(); // in bytes
int cyp_hash(void *dst, void *src, uint64_t size);

// TODO: keys are not kept in protected memory (like TPM or SGX)
typedef struct cyp_sim_key_ *cyp_sim_key_s;

// symmetric cipher
enum CYP_SIM_FN cyp_sim_get_alg();
int cyp_sim_get_key_size(); // in bytes
int cyp_sim_get_init_size(); // in bytes (e.g., IV vector in CBC)
cyp_sim_key_s cyp_sim_new_key(void *secret, void *init); // check sizes with cyp_sim_get_{key,init}_size
int cyp_sim_destroy_key(cyp_sim_key_s);
// be careful with the size of the buffers, they need to have "enough" space and be multiple of cyp_sim_get_key_size
int cyp_sim_encrypt(cyp_sim_key_s, void *data_in, void *cyphered_out, uint64_t size_in);
int cyp_sim_decrypt(cyp_sim_key_s, void *cyphered_in, void *data_out, uint64_t size_in);

// TODO: keys are not kept in protected memory (like TPM or SGX)
typedef struct cyp_pub_key_ *cyp_pub_key_s;
typedef struct cyp_prv_key_ *cyp_prv_key_s;
typedef struct cyp_pair_key_ *cyp_pair_key_s;

// asymmetric cipher
enum CYP_PAIR_FN cyp_pair_get_alg();
int cyp_pub_get_key_size(); // in bytes
int cyp_prv_get_key_size(); // in bytes
int cyp_pair_get_secret_size(); // in bytes
cyp_pair_key_s cyp_pair_new_key();
cyp_pub_key_s cyp_pair_load_pub_key(void *key); // loads from a buffer
cyp_prv_key_s cyp_pair_load_prv_key(void *key);
int cyp_pair_store_pub_key(cyp_pub_key_s, void *key); // stores in buffer
int cyp_pair_store_prv_key(cyp_prv_key_s, void *key);
cyp_pub_key_s cyp_pair_get_pub_key(cyp_pair_key_s); // need to destroy it after use (allocates memory)
cyp_prv_key_s cyp_pair_get_prv_key(cyp_pair_key_s);
int cyp_pair_get_secret(cyp_pub_key_s, cyp_prv_key_s, void *secret); // secret of size cyp_pair_get_secret_size (returns -1 or error)
int cyp_pair_destroy_key(cyp_pair_key_s);
int cyp_pub_destroy_key(cyp_pub_key_s);
int cyp_prv_destroy_key(cyp_prv_key_s);
// be careful with the size of the buffers, they need to have "enough" space
int cyp_pub_verify(cyp_pub_key_s, void *signature_in, void *expected_out, uint64_t size_signature); // returns 1 on Ok
int cyp_prv_sign(cyp_prv_key_s, void *data_in, void *signature_out, uint64_t size_data); // returns -1 on error

// sets to use a specific algorithm
int cyp_rnd_bind(enum CYP_RND_FN);
int cyp_rnd_bind_WELL44497a();
int cyp_rnd_bind_WELL44497b();

int cyp_hash_bind(enum CYP_HASH_FN);
int cyp_hash_bind_SHA3_256();
int cyp_hash_bind_SHA3_512();

int cyp_sim_bind(enum CYP_SIM_FN);
int cyp_sim_bind_AES256_CBC();
int cyp_sim_bind_AES256_ECB();
int cyp_sim_bind_AES256_CTR();

int cyp_pair_bind(enum CYP_PAIR_FN);
int cyp_pair_bind_ECC_secp160r1();
int cyp_pair_bind_ECC_secp192r1();
int cyp_pair_bind_ECC_secp224r1();
int cyp_pair_bind_ECC_secp256k1();

#endif /* CYPHER_H_GUARD_ */
