#ifndef SHA_H_GUARD_
#define SHA_H_GUARD_

#include <stdint.h>

void sha3_256(void* data, uint64_t len, char* hash);
void sha3_512(void* data, uint64_t len, char* hash);

#endif /* SHA_H_GUARD_ */
