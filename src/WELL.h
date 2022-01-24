/* ***************************************************************************** */
/* Copyright:      Francois Panneton and Pierre L'Ecuyer, University of Montreal */
/*                 Makoto Matsumoto, Hiroshima University                        */
/* Notice:         This code can be used freely for personal, academic,          */
/*                 or non-commercial purposes. For commercial purposes,          */
/*                 please contact P. L'Ecuyer at: lecuyer@iro.UMontreal.ca       */
/* ***************************************************************************** */

#include <stdint.h>

void InitWELLRNG44497a(unsigned int *init);
void GetSeedWELLRNG44497a(unsigned int *seed);
void SetSeedWELLRNG44497a(unsigned int *seed);
extern double (*WELLRNG44497a_d)(void);
extern uint64_t (*WELLRNG44497a_ul)(void);

void InitWELLRNG44497b(unsigned int *init);
void GetSeedWELLRNG44497b(unsigned int *seed);
void SetSeedWELLRNG44497b(unsigned int *seed);
extern double (*WELLRNG44497b_d)(void);
extern uint64_t (*WELLRNG44497b_ul)(void);
