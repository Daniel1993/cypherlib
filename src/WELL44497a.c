/* ***************************************************************************** */
/* Copyright:      Francois Panneton and Pierre L'Ecuyer, University of Montreal */
/*                 Makoto Matsumoto, Hiroshima University                        */
/* Notice:         This code can be used freely for personal, academic,          */
/*                 or non-commercial purposes. For commercial purposes,          */
/*                 please contact P. L'Ecuyer at: lecuyer@iro.UMontreal.ca       */
/* ***************************************************************************** */
#include <stdint.h>
#define W 32
#define R 1391
#define P 15
#define MASKU (0xffffffffU>>(W-P))
#define MASKL (~MASKU)

#define M1 23
#define M2 481
#define M3 229

#define MAT0POS(t,v) (v^(v>>t))
#define MAT0NEG(t,v) (v^(v<<(-(t))))
#define MAT1(v) v
#define MAT2(a,v) ((v & 1U)?((v>>1)^a):(v>>1))
#define MAT3POS(t,v) (v>>t)
#define MAT3NEG(t,v) (v<<(-(t)))
#define MAT4POS(t,b,v) (v ^ ((v>>  t ) & b))
#define MAT4NEG(t,b,v) (v ^ ((v<<(-(t))) & b))
#define MAT5(r,a,ds,dt,v) ((v & dt)?((((v<<r)^(v>>(W-r)))&ds)^a):(((v<<r)^(v>>(W-r)))&ds))
#define MAT7(v) 0

#define V0            STATE[state_i]
#define VM1Over       STATE[state_i+M1-R]
#define VM1           STATE[state_i+M1]
#define VM2Over       STATE[state_i+M2-R]
#define VM2           STATE[state_i+M2]
#define VM3Over       STATE[state_i+M3-R]
#define VM3           STATE[state_i+M3]
#define Vrm1          STATE[state_i-1]
#define Vrm1Under     STATE[state_i+R-1]
#define Vrm2          STATE[state_i-2]
#define Vrm2Under     STATE[state_i+R-2]

#define newV0         STATE[state_i-1]
#define newV0Under    STATE[state_i-1+R]
#define newV1         STATE[state_i]
#define newVRm1       STATE[state_i-2]
#define newVRm1Under  STATE[state_i-2+R]

#define FACT 2.32830643653869628906e-10

static uint32_t STATE[R];
static uint32_t z0,z1,z2,y;
static int state_i=0;

static void case_1(void);
static void case_2(void);
static void case_3(void);
static void case_4(void);
static void case_5(void);
static void case_6(void);

static double case_d_1(void);
static double case_d_2(void);
static double case_d_3(void);
static double case_d_4(void);
static double case_d_5(void);
static double case_d_6(void);

static uint64_t case_ul_1(void);
static uint64_t case_ul_2(void);
static uint64_t case_ul_3(void);
static uint64_t case_ul_4(void);
static uint64_t case_ul_5(void);
static uint64_t case_ul_6(void);

typedef double(*cases_d_fn)(void);
static cases_d_fn cases_d[6] = {
	case_d_1, case_d_2, case_d_3, case_d_4, case_d_5, case_d_6
};

typedef uint64_t(*cases_ul_fn)(void);
static cases_ul_fn cases_ul[6] = {
	case_ul_1, case_ul_2, case_ul_3, case_ul_4, case_ul_5, case_ul_6
};

static uint32_t case_i = 0;
double (*WELLRNG44497a_d)(void);
uint64_t (*WELLRNG44497a_ul)(void);

void InitWELLRNG44497a(uint32_t *init){
	int j;
	state_i=0;
	case_i=0;
	WELLRNG44497a_d = case_d_1;
	WELLRNG44497a_ul = case_ul_1;
	for(j=0;j<R;j++)
		STATE[j]=init[j];
	for(j=0;j<R;j++)
	  WELLRNG44497a_ul(); // scrambles a bit
}

void GetSeedWELLRNG44497a(uint32_t *seed)
{
	int j;
	seed[R] = case_i;
	for(j=0;j<R;j++)
		seed[j]=STATE[j];
}

void SetSeedWELLRNG44497a(uint32_t *seed)
{
	int j;
	case_i = seed[R];
	case_i %= 6;
	WELLRNG44497a_d = cases_d[case_i];
	WELLRNG44497a_ul = cases_ul[case_i];
	for(j=0;j<R;j++)
		STATE[j]=seed[j];
}

void case_1(void){
	// state_i == 0
	z0 = (Vrm1Under & MASKL) | (Vrm2Under & MASKU);
	z1 = MAT0NEG(-24,V0) ^ MAT0POS(30,VM1);
	z2 = MAT0NEG(-10,VM2) ^ MAT3NEG(-26,VM3);
	newV1  = z1 ^ z2;
	newV0Under = MAT1(z0) ^ MAT0POS(20,z1) ^  MAT5(9,0xb729fcecU,0xfbffffffU,0x00020000U,z2) ^ MAT1(newV1);
	state_i = R-1;
	case_i=2;
	WELLRNG44497a_d = case_d_3;
	WELLRNG44497a_ul = case_ul_3;
}

double case_d_1(void){
	case_1();
	return ((double) STATE[state_i] * FACT);
}

uint64_t case_ul_1(void)
{
	case_1();
	return (uint64_t)STATE[state_i]|(((uint64_t)(STATE[(state_i+1)%R]))<<32);
}

void case_2(void)
{
	// state_i == 1
	z0 = (Vrm1 & MASKL) | (Vrm2Under & MASKU);
	z1 = MAT0NEG(-24,V0) ^ MAT0POS(30,VM1);
	z2 = MAT0NEG(-10,VM2) ^ MAT3NEG(-26,VM3);
	newV1 = z1 ^ z2;
	newV0 =  MAT1(z0) ^ MAT0POS(20,z1) ^ MAT5(9,0xb729fcecU,0xfbffffffU,0x00020000U,z2) ^ MAT1(newV1);
	state_i=0;
	case_i=0;
	WELLRNG44497a_d = case_d_1;
	WELLRNG44497a_ul = case_ul_1;
}

double case_d_2(void)
{
	case_2();
	return ((double) STATE[state_i] * FACT);
}

uint64_t case_ul_2(void)
{
	case_2();
	return (uint64_t)STATE[state_i]|(((uint64_t)(STATE[(state_i+1)%R]))<<32);
}

void case_3(void)
{
	// state_i+M1 >= R
	z0 = (Vrm1 & MASKL) | (Vrm2 & MASKU);
	z1 = MAT0NEG(-24,V0) ^ MAT0POS(30,VM1Over);
	z2 = MAT0NEG(-10,VM2Over) ^ MAT3NEG(-26,VM3Over);
	newV1 = z1 ^ z2;
	newV0 = MAT1(z0) ^ MAT0POS(20,z1) ^ MAT5(9,0xb729fcecU,0xfbffffffU,0x00020000U,z2) ^ MAT1(newV1);
	state_i--;
	if(state_i+M1<R) {
		case_i=3;
		WELLRNG44497a_d = case_d_4;
		WELLRNG44497a_ul = case_ul_4;
	}
}

double case_d_3(void)
{
	case_3();
	return ((double) STATE[state_i] * FACT);
}

uint64_t case_ul_3(void){
	case_3();
	return (uint64_t)STATE[state_i]|(((uint64_t)(STATE[(state_i+1)%R]))<<32);
}

void case_4(void)
{
	// state_i+M3 >= R
	z0 = (Vrm1 & MASKL) | (Vrm2 & MASKU);
	z1 = MAT0NEG(-24,V0) ^ MAT0POS(30,VM1);
	z2 = MAT0NEG(-10,VM2Over) ^ MAT3NEG(-26,VM3Over);
	newV1 = z1 ^ z2;
	newV0 = MAT1(z0) ^ MAT0POS(20,z1) ^ MAT5(9,0xb729fcecU,0xfbffffffU,0x00020000U,z2) ^ MAT1(newV1);
	state_i--;
	if (state_i+M3 < R) {
		case_i=4;
		WELLRNG44497a_d = case_d_5;
		WELLRNG44497a_ul = case_ul_5;
	}
}

double case_d_4(void)
{
	case_4();
	return ((double) STATE[state_i] * FACT);
}

uint64_t case_ul_4(void)
{
	case_4();
	return (uint64_t)STATE[state_i]|(((uint64_t)(STATE[(state_i+1)%R]))<<32);
}

void case_5(void)
{
	//state_i+M2 >= R
	z0 = (Vrm1 & MASKL) | (Vrm2 & MASKU);
	z1 = MAT0NEG(-24,V0) ^ MAT0POS(30,VM1);
	z2 = MAT0NEG(-10,VM2Over) ^ MAT3NEG(-26,VM3);
	newV1 = z1 ^ z2;
	newV0 = MAT1(z0) ^ MAT0POS(20,z1) ^ MAT5(9,0xb729fcecU,0xfbffffffU,0x00020000U,z2) ^ MAT1(newV1);
	state_i--;
	if(state_i+M2 < R) {
		case_i=5;
		WELLRNG44497a_d = case_d_6;
		WELLRNG44497a_ul = case_ul_6;
	}
}

double case_d_5(void)
{
	case_5();
	return ((double) STATE[state_i] * FACT);
}

uint64_t case_ul_5(void)
{
	case_5();
	return (uint64_t)STATE[state_i]|(((uint64_t)(STATE[(state_i+1)%R]))<<32);
}

void case_6(void)
{
	// 2 <= state_i <= R-M2-1
	z0 = (Vrm1 & MASKL) | (Vrm2 & MASKU);
	z1 = MAT0NEG(-24,V0) ^ MAT0POS(30,VM1);
	z2 = MAT0NEG(-10,VM2) ^ MAT3NEG(-26,VM3);
	newV1 = z1 ^ z2;
	newV0 = MAT1(z0) ^ MAT0POS(20,z1) ^ MAT5(9,0xb729fcecU,0xfbffffffU,0x00020000U,z2) ^ MAT1(newV1);
	state_i--;
	if(state_i == 1) {
		case_i=1;
		WELLRNG44497a_d = case_d_2;
		WELLRNG44497a_ul = case_ul_2;
	}
}

double case_d_6(void)
{
	case_6();
	return ((double) STATE[state_i] * FACT);
}

uint64_t case_ul_6(void)
{
	case_6();
	return (uint64_t)STATE[state_i]|(((uint64_t)(STATE[(state_i+1)%R]))<<32);
}
