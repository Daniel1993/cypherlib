#include "cypher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    int err;

    cyp_init();
    printf("Gen doubles: \n");
    for (int i = 0; i < 5; ++i)
    {
        printf("    %f\n", cyp_rnd_gen_d());
    }
    printf("Gen longs: \n");
    for (int i = 0; i < 5; ++i)
    {
        printf("    %llx\n", cyp_rnd_gen_ul());
    }
    printf("Hash numbers: \n");
    for (int i = 0; i < 5; ++i)
    {
        int size = cyp_hash_get_size()/sizeof(uint64_t)+1;
        uint64_t buffer_in[size];
        uint64_t buffer_out[size];
        printf("in: ");
        for (int j = 0; j < size; ++j)
        {
            buffer_in[j] = cyp_rnd_gen_ul();
            if (j < 5) printf("%llx", buffer_in[j]);
        }
        printf("...\nout: ");
        cyp_hash(buffer_out, buffer_in, size*sizeof(uint64_t));
        for (int j = 0; j < 5; ++j)
        {
            printf("%llx", buffer_out[j]);
        }
        printf("...\n");
    }

    printf("cipher text: \n");
    void *secret;
    void *init; // TODO: cyp_sim_get_init_size can be 0
    int sizeSecret;
    int sizeInit;
    cyp_sim_key_s key;
    char msg[1024]; // TODO: It must be multiple of cyp_sim_get_init_size()

    memset(msg, 0, sizeof(msg));
    sprintf(msg, "My critical private information 12345678901234567890");
    cyp_sim_bind_AES256_CBC();
    printf("  %s: \n", CYP_SIM_FN_NAMES[cyp_sim_get_alg()]);
    sizeSecret = cyp_sim_get_key_size();
    sizeInit = cyp_sim_get_key_size();
    secret = malloc(sizeSecret);
    init = malloc(sizeInit);
    memset(secret, 0, sizeSecret);
    memset(init, 0, sizeInit);
    sprintf(secret, "Hello"); // how to get stack errors 101...
    sprintf(init, "init"); // how to get stack errors 101...

    key = cyp_sim_new_key(secret, init);
    printf("private message (init=%s): \"%s\"\n", (char*)init, msg);
    for (int i = 0 ; i < 8; ++i) printf("%016lx", ((uintptr_t*)msg)[i]);
    cyp_sim_encrypt(key, msg, msg, 128); // allows same buffer
    printf("\nciphered: ");
    for (int i = 0 ; i < 8; ++i) printf("%016lx", ((uintptr_t*)msg)[i]);
    printf(" (\"%s\")\n", msg);
    cyp_sim_decrypt(key, msg, msg, 128); // allows same buffer
    printf("deciphered (init=%s): \"%s\"\n", (char*)init, msg);
    cyp_sim_destroy_key(key);
    free(secret);
    free(init);

    memset(msg, 0, sizeof(msg));
    sprintf(msg, "My critical private information 12345678901234567890");
    cyp_sim_bind_AES256_ECB();
    printf("  %s: \n", CYP_SIM_FN_NAMES[cyp_sim_get_alg()]);
    sizeSecret = cyp_sim_get_key_size();
    secret = malloc(sizeSecret);
    memset(secret, 0, sizeSecret);
    sprintf(secret, "Hello"); // how to get stack errors 101...

    key = cyp_sim_new_key(secret, init);
    printf("private message: \"%s\"\n", msg);
    for (int i = 0 ; i < 8; ++i) printf("%016lx", ((uintptr_t*)msg)[i]);
    cyp_sim_encrypt(key, msg, msg, 128); // allows same buffer
    printf("\nciphered: ", msg);
    for (int i = 0 ; i < 8; ++i) printf("%016lx", ((uintptr_t*)msg)[i]);
    printf(" (\"%s\")\n", msg);
    cyp_sim_decrypt(key, msg, msg, 128); // allows same buffer
    printf("deciphered: \"%s\"\n", msg);
    cyp_sim_destroy_key(key);
    free(secret);

    memset(msg, 0, sizeof(msg));
    sprintf(msg, "My critical private information 12345678901234567890");
    cyp_sim_bind_AES256_CTR();
    printf("  %s: \n", CYP_SIM_FN_NAMES[cyp_sim_get_alg()]);
    sizeSecret = cyp_sim_get_key_size();
    sizeInit = cyp_sim_get_key_size();
    secret = malloc(sizeSecret);
    init = malloc(sizeInit);
    memset(secret, 0, sizeSecret);
    memset(init, 0, sizeInit);
    sprintf(secret, "Hello"); // how to get stack errors 101...

    key = cyp_sim_new_key(secret, init);
    printf("private message: \"%s\"\n", msg);
    for (int i = 0 ; i < 8; ++i) printf("%016lx", ((uintptr_t*)msg)[i]);
    cyp_sim_encrypt(key, msg, msg, 128); // allows same buffer
    printf("\nciphered: ", msg);
    for (int i = 0 ; i < 8; ++i) printf("%016lx", ((uintptr_t*)msg)[i]);
    printf(" (\"%s\")\n", msg);
    cyp_sim_decrypt(key, msg, msg, 128); // allows same buffer
    printf("deciphered: \"%s\"\n", msg);
    cyp_sim_destroy_key(key);
    free(secret);
    free(init);

    cyp_pair_key_s pair;
    cyp_pub_key_s pub;
    cyp_prv_key_s prv;
    cyp_pair_key_s pair2;
    cyp_pub_key_s pub2;
    cyp_prv_key_s prv2;
    uint8_t sign_buf[1024];
    uint8_t secret_buf1[1024];
    uint8_t secret_buf2[1024];


    printf("\n --- public keys test ---\n");
    // --------------------------------------
    // --- ECC_secp160r1
    cyp_pair_bind_ECC_secp160r1();
    printf("  %s: \n", CYP_PAIR_FN_NAMES[cyp_pair_get_alg()]);
    printf("PUB key size: %i\n", cyp_pub_get_key_size());
    printf("PRV key size: %i\n", cyp_prv_get_key_size());
    printf("secret size: %i\n", cyp_pair_get_secret_size());
    pair = cyp_pair_new_key();
    pub = cyp_pair_get_pub_key(pair);
    prv = cyp_pair_get_prv_key(pair);

    memset(msg, 0, sizeof(msg)); // TODO: hash the message
    memset(sign_buf, 0, sizeof(sign_buf)); // TODO: hash the message
    sprintf(msg, "My critical private information 12345678901234567890");

    err = cyp_prv_sign(prv, msg, sign_buf, 20);
    printf("error on sign = %i (\"%52s\" len = %i)\n", err, sign_buf, strlen(sign_buf));

    err = cyp_pub_verify(pub, sign_buf, msg, 20);
    printf("verify signature = %i\n", err);

    printf("secret size: %i\n", cyp_pair_get_secret_size());

    pair2 = cyp_pair_new_key();
    pub2 = cyp_pair_get_pub_key(pair2);
    prv2 = cyp_pair_get_prv_key(pair2);

    cyp_pair_get_secret(pub, prv2, secret_buf1);
    cyp_pair_get_secret(pub2, prv, secret_buf2);
    printf("secret 1 = %lx secret 2 = %lx\n", ((uint64_t*)secret_buf1)[0], ((uint64_t*)secret_buf2)[0]);

    cyp_pair_destroy_key(pair);
    cyp_pub_destroy_key(pub);
    cyp_prv_destroy_key(prv);
    cyp_pair_destroy_key(pair2);
    cyp_pub_destroy_key(pub2);
    cyp_prv_destroy_key(prv2);
    // --------------------------------------

    // --------------------------------------
    // --- ECC_secp192r1
    cyp_pair_bind_ECC_secp192r1();
    printf("  %s: \n", CYP_PAIR_FN_NAMES[cyp_pair_get_alg()]);
    printf("PUB key size: %i\n", cyp_pub_get_key_size());
    printf("PRV key size: %i\n", cyp_prv_get_key_size());
    printf("secret size: %i\n", cyp_pair_get_secret_size());
    pair = cyp_pair_new_key();
    pub = cyp_pair_get_pub_key(pair);
    prv = cyp_pair_get_prv_key(pair);

    memset(msg, 0, sizeof(msg)); // TODO: hash the message
    memset(sign_buf, 0, sizeof(sign_buf)); // TODO: hash the message
    sprintf(msg, "My critical private information 12345678901234567890");

    err = cyp_prv_sign(prv, msg, sign_buf, 20);
    printf("error on sign = %i (\"%52s\" len = %i)\n", err, sign_buf, strlen(sign_buf));

    err = cyp_pub_verify(pub, sign_buf, msg, 20);
    printf("verify signature = %i\n", err);

    printf("secret size: %i\n", cyp_pair_get_secret_size());

    pair2 = cyp_pair_new_key();
    pub2 = cyp_pair_get_pub_key(pair2);
    prv2 = cyp_pair_get_prv_key(pair2);

    cyp_pair_get_secret(pub, prv2, secret_buf1);
    cyp_pair_get_secret(pub2, prv, secret_buf2);
    printf("secret 1 = %lx secret 2 = %lx\n", ((uint64_t*)secret_buf1)[0], ((uint64_t*)secret_buf2)[0]);

    cyp_pair_destroy_key(pair);
    cyp_pub_destroy_key(pub);
    cyp_prv_destroy_key(prv);
    cyp_pair_destroy_key(pair2);
    cyp_pub_destroy_key(pub2);
    cyp_prv_destroy_key(prv2);
    // --------------------------------------
    
    // --------------------------------------
    // --- ECC_secp224r1
    cyp_pair_bind_ECC_secp224r1();
    printf("  %s: \n", CYP_PAIR_FN_NAMES[cyp_pair_get_alg()]);
    printf("PUB key size: %i\n", cyp_pub_get_key_size());
    printf("PRV key size: %i\n", cyp_prv_get_key_size());
    printf("secret size: %i\n", cyp_pair_get_secret_size());
    pair = cyp_pair_new_key();
    pub = cyp_pair_get_pub_key(pair);
    prv = cyp_pair_get_prv_key(pair);
    memset(msg, 0, sizeof(msg)); // TODO: hash the message
    memset(sign_buf, 0, sizeof(sign_buf)); // TODO: hash the message
    sprintf(msg, "My critical private information 12345678901234567890");

    err = cyp_prv_sign(prv, msg, sign_buf, 20);
    printf("error on sign = %i (\"%52s\" len = %i)\n", err, sign_buf, strlen(sign_buf));

    err = cyp_pub_verify(pub, sign_buf, msg, 20);
    printf("verify signature = %i\n", err);

    printf("secret size: %i\n", cyp_pair_get_secret_size());

    pair2 = cyp_pair_new_key();
    pub2 = cyp_pair_get_pub_key(pair2);
    prv2 = cyp_pair_get_prv_key(pair2);

    cyp_pair_get_secret(pub, prv2, secret_buf1);
    cyp_pair_get_secret(pub2, prv, secret_buf2);
    printf("secret 1 = %lx secret 2 = %lx\n", ((uint64_t*)secret_buf1)[0], ((uint64_t*)secret_buf2)[0]);

    cyp_pair_destroy_key(pair);
    cyp_pub_destroy_key(pub);
    cyp_prv_destroy_key(prv);
    cyp_pair_destroy_key(pair2);
    cyp_pub_destroy_key(pub2);
    cyp_prv_destroy_key(prv2);
    // --------------------------------------
    
    // --------------------------------------
    // --- ECC_secp256r1
    cyp_pair_bind_ECC_secp256k1();
    printf("  %s: \n", CYP_PAIR_FN_NAMES[cyp_pair_get_alg()]);
    printf("PUB key size: %i\n", cyp_pub_get_key_size());
    printf("PRV key size: %i\n", cyp_prv_get_key_size());
    printf("secret size: %i\n", cyp_pair_get_secret_size());
    pair = cyp_pair_new_key();
    pub = cyp_pair_get_pub_key(pair);
    prv = cyp_pair_get_prv_key(pair);
    memset(msg, 0, sizeof(msg)); // TODO: hash the message
    memset(sign_buf, 0, sizeof(sign_buf)); // TODO: hash the message
    sprintf(msg, "My critical private information 12345678901234567890");

    err = cyp_prv_sign(prv, msg, sign_buf, 20);
    printf("error on sign = %i (\"%52s\" len = %i)\n", err, sign_buf, strlen(sign_buf));

    err = cyp_pub_verify(pub, sign_buf, msg, 20);
    printf("verify signature = %i\n", err);

    printf("secret size: %i\n", cyp_pair_get_secret_size());

    pair2 = cyp_pair_new_key();
    pub2 = cyp_pair_get_pub_key(pair2);
    prv2 = cyp_pair_get_prv_key(pair2);

    cyp_pair_get_secret(pub, prv2, secret_buf1);
    cyp_pair_get_secret(pub2, prv, secret_buf2);
    printf("secret 1 = %lx secret 2 = %lx\n", ((uint64_t*)secret_buf1)[0], ((uint64_t*)secret_buf2)[0]);

    cyp_pair_destroy_key(pair);
    cyp_pub_destroy_key(pub);
    cyp_prv_destroy_key(prv);
    cyp_pair_destroy_key(pair2);
    cyp_pub_destroy_key(pub2);
    cyp_prv_destroy_key(prv2);
    // --------------------------------------
}
