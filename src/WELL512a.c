/* ***************************************************************************** */
/* Copyright:      Francois Panneton and Pierre L'Ecuyer, University of Montreal */
/*                 Makoto Matsumoto, Hiroshima University                        */
/* Notice:         This code can be used freely for personal, academic,          */
/*                 or non-commercial purposes. For commercial purposes,          */
/*                 please contact P. L'Ecuyer at: lecuyer@iro.UMontreal.ca       */
/* ***************************************************************************** */
#include <stdint.h>
#define W 32
#define R 16
#define P 0
#define M1 13
#define M2 9
#define M3 5

#define MAT0POS(t,v) (v^(v>>t))
#define MAT0NEG(t,v) (v^(v<<(-(t))))
#define MAT3NEG(t,v) (v<<(-(t)))
#define MAT4NEG(t,b,v) (v ^ ((v<<(-(t))) & b))

#define V0            STATE[state_i                   ]
#define VM1           STATE[(state_i+M1) & 0x0000000fU]
#define VM2           STATE[(state_i+M2) & 0x0000000fU]
#define VM3           STATE[(state_i+M3) & 0x0000000fU]
#define VRm1          STATE[(state_i+15) & 0x0000000fU]
#define VRm2          STATE[(state_i+14) & 0x0000000fU]
#define newV0         STATE[(state_i+15) & 0x0000000fU]
#define newV1         STATE[state_i                 ]
#define newVRm1       STATE[(state_i+14) & 0x0000000fU]

#define FACT 2.32830643653869628906e-10

static uint32_t state_i = 0;
static uint32_t STATE[R];
static uint32_t z0, z1, z2;

double WELLRNG512a_d(void);
uint64_t WELLRNG512a_ul(void);

void InitWELLRNG512a (uint32_t *init){
	int j;
	state_i = 0;
	for (j = 0; j < R; j++)
		STATE[j] = init[j];
	for(j=0;j<R;j++)
	  WELLRNG512a_ul(); // scrambles a bit
}

void GetSeedWELLRNG512a(uint32_t *seed)
{
	int j;
	for(j=0;j<R;j++)
		seed[j]=STATE[j];
}

void SetSeedWELLRNG512a(uint32_t *seed)
{
	int j;
	for(j=0;j<R;j++)
		STATE[j]=seed[j];
}

double WELLRNG512a_d (void)
{
	z0    = VRm1;
	z1    = MAT0NEG (-16,V0)    ^ MAT0NEG (-15, VM1);
	z2    = MAT0POS (11, VM2)  ;
	newV1 = z1                  ^ z2; 
	newV0 = MAT0NEG (-2,z0)     ^ MAT0NEG(-18,z1)    ^ MAT3NEG(-28,z2) ^ MAT4NEG(-5,0xda442d24U,newV1) ;
	state_i = (state_i + 15) & 0x0000000fU;
	return ((double) STATE[state_i]) * FACT;
}

uint64_t WELLRNG512a_ul (void)
{
	z0    = VRm1;
	z1    = MAT0NEG (-16,V0)    ^ MAT0NEG (-15, VM1);
	z2    = MAT0POS (11, VM2)  ;
	newV1 = z1                  ^ z2; 
	newV0 = MAT0NEG (-2,z0)     ^ MAT0NEG(-18,z1)    ^ MAT3NEG(-28,z2) ^ MAT4NEG(-5,0xda442d24U,newV1) ;
	state_i = (state_i + 15) & 0x0000000fU;
	return (uint64_t)STATE[state_i]|(((uint64_t)(STATE[(state_i+1)%R]))<<32);
}
