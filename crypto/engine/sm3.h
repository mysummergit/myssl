#ifndef FMHASH_H
#define FMHASH_H

#include <stdlib.h>
#include <inttypes.h>

#include "sm2_lcl.h"

#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n, b, i) \
{ \
		(n) = ((uint32_t)(b)[(i)] << 24) \
			| ((uint32_t)(b)[(i) + 1] << 16) \
			| ((uint32_t)(b)[(i) + 2] << 8) \
			| ((uint32_t)(b)[(i) + 3]); \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n, b, i) \
{ \
		(b)[(i)] = (unsigned char)((n) >> 24); \
		(b)[(i) + 1] = (unsigned char)((n) >> 16); \
		(b)[(i) + 2] = (unsigned char)((n) >> 8); \
		(b)[(i) + 3] = (unsigned char)((n)); \
}
#endif

#define FF0(X,Y,Z) ((X)^(Y)^(Z))
#define FF1(X,Y,Z) (((X)&(Y))|((X)&(Z))|((Y)&(Z)))

#define GG0(X,Y,Z) ((X)^(Y)^(Z))
#define GG1(X,Y,Z) (((X)&(Y))|((~X)&(Z)))

#define ROTL(X,n) ((((X) & 0xFFFFFFFF) << (n)) | ((X) >> (32 - (n))))

#define P0(X) (X) ^ (ROTL((X),9)) ^ (ROTL((X),17))
#define P1(X) (X) ^ (ROTL((X),15)) ^ (ROTL((X),23))

//int sm3_hash(SM3_CTX *ctx, unsigned char *data, size_t length);

#endif
