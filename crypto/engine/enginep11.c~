/*****************************************
	sm3 engine
	by dz
*****************************************/
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include "enginep11.h"
#include "sm3.h"
#include <openssl/obj_mac.h>
#include "e_sm2_err.h"
#include "sm2_lcl.h"

static const unsigned char sm33_padding[64] = {0x80};

static void sm33_process(SM3_CTX *ctx, unsigned char data[64])
{
	uint32_t SS1, SS2, TT1, TT2, W[68], W1[64];
	uint32_t A, B, C, D, E, F, G, H;
	uint32_t T[64];

	int i;

    // 4.2 设置常量T
	for(i = 0; i < 16; i++)
		T[i] = 0x79CC4519;
	for(i = 16; i < 64; i++)
		T[i] = 0x7A879D8A;

    // 将data数据大端格式存放到W中
	for(i = 0; i < 16; i++)
		GET_ULONG_BE(W[i], data, i * 4);

    // 5.3.2 消息扩展W[16, 67]
	for(i = 16; i < 68; i++)
	{
		W[i] = P1((W[i-16]^W[i-9]^(ROTL(W[i-3],15))))^(ROTL(W[i-13],7))^W[i-6]; 
	}

#if DEBUG
	printf("Expanding message W0-67:\n");
	for(i = 0; i < 68; i++)
	{
		printf("%08x ",W[i]);
		if(((i + 1) % 8) == 0) printf("\n");
	}
	printf("\n");
#endif

	for(i = 0; i < 64; i++)
	{
		W1[i] = W[i]^W[i+4];
	}

#if DEBUG
	printf("Expanding message W'0-63\n");
	for(i = 0; i < 64; i++)
	{
		printf("%08x ", W1[i]);
		if(((i + 1) % 8) == 0) printf("\n");
	}
	printf("\n");
#endif

	A = ctx->iv[0];
	B = ctx->iv[1];
	C = ctx->iv[2];
	D = ctx->iv[3];
	E = ctx->iv[4];
	F = ctx->iv[5];
	G = ctx->iv[6];
	H = ctx->iv[7];

#if DEBUG
	printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", A, B, C, D, E, F, G, H);
#endif
    // 5.3.3 压缩函数 这里写成两轮是方便调试
	for(i = 0; i < 16; i++)
	{
		SS1 = (ROTL(((ROTL(A,12)) + E + (ROTL(T[i],i))),7));
		SS2 = SS1 ^ (ROTL(A,12));
		TT1 = FF0(A,B,C) + D + SS2 + W1[i];
		TT2 = GG0(E,F,G) + H + SS1 + W[i];
		D = C;
		C = (ROTL(B,9));
		B = A;
		A = TT1;
		H = G;
		G = (ROTL(F,19));
		F = E;
		E = P0(TT2);
#if DEBUG
		printf("[%d] %08x %08x %08x %08x %08x %08x %08x %08x\n", i, A, B, C, D, E, F, G, H);
#endif
	}

	for(i = 16; i < 64; i++)
	{
		SS1 = (ROTL(((ROTL(A,12)) + E + (ROTL(T[i],i))),7));
		SS2 = SS1 ^ (ROTL(A,12));
		TT1 = FF1(A,B,C) + D + SS2 + W1[i];
		TT2 = GG1(E,F,G) + H + SS1 + W[i];
		D = C;
		C = (ROTL(B,9));
		B = A;
		A = TT1;
		H = G;
		G = (ROTL(F,19));
		F = E;
		E = P0(TT2);
#if DEBUG
		printf("[%d] %08x %08x %08x %08x %08x %08x %08x %08x\n", i, A, B, C, D, E, F, G, H);
#endif
	}

    // 更新下一轮的iv
	ctx->iv[0] ^= A;
	ctx->iv[1] ^= B;
	ctx->iv[2] ^= C;
	ctx->iv[3] ^= D;
	ctx->iv[4] ^= E;
	ctx->iv[5] ^= F;
	ctx->iv[6] ^= G;
	ctx->iv[7] ^= H;
}

void sm33_update( SM3_CTX *ctx, const void *input, int ilen )
{
    int fill;
    uint32_t left;

    if( ilen <= 0 )
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (uint32_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, fill );
        sm33_process( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        sm33_process( ctx, input );
        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, ilen );
    }
}


void sm33_final( SM3_CTX *ctx, unsigned char output[32] )
{
    uint32_t last, padn;
    uint32_t high, low;
    unsigned char msglen[8];
    int i;

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_ULONG_BE( high, msglen, 0 );
    PUT_ULONG_BE( low,  msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sm33_update( ctx, sm33_padding, padn );
    sm33_update( ctx, msglen, 8 );

    // 输出iv结果到output
    for (i = 0; i < 8; i++) {
        PUT_ULONG_BE( ctx->iv[i], output, i*4 );
    }
}

#if 0
int sm33_hash(SM3_CTX *ctx, unsigned char *data, size_t ilen)
{
	int l = ilen * 8; // 转换成bit的长度
	int k = 0;
	int nbytes = 0;
	int n = 0;

	unsigned char *original = NULL;
	unsigned char toBytes[8];

	if(ilen <= 0)
		return 0;

	toBytes[0] = 0x00;
	toBytes[1] = 0x00;
	toBytes[2] = 0x00;
	toBytes[3] = 0x00;
	PUT_ULONG_BE((uint32_t)l,toBytes,4);

	int j = 0;
	j = ilen / 64;
	k = (447 - l) % 512 + j * 512;

	nbytes = (l + k + 1 + 64) / 8;
	original = (unsigned char *)OPENSSL_malloc(nbytes);

	for(j = 0; j < ilen; j++)
		original[j] = data[j];
	original[j] = 0x80;

	for(j = 1; j <= 8; j++)
		original[nbytes - j] = toBytes[8 - j];

	while(nbytes >= 64)
	{
		sm33_process(ctx, original);
		original += 64;
		nbytes -= 64;
	}

	if(nbytes > 0)
		return 0;

	return 1;
}
#endif

int digest_sm3_init(EVP_MD_CTX *ctx)
{
    SM3_CTX *c = ctx->md_data;
    c->total[0] = 0;
    c->total[1] = 0;

	c->iv[0] = 0x7380166f;
	c->iv[1] = 0x4914b2b9;
	c->iv[2] = 0x172442d7;
	c->iv[3] = 0xda8a0600;
	c->iv[4] = 0xa96f30bc;
	c->iv[5] = 0x163138aa;
	c->iv[6] = 0xe38dee4d;
	c->iv[7] = 0xb0fb0e4e;

    return 1;
}


int digest_sm3_update(EVP_MD_CTX *ctx, const void *data,
       size_t count)
{
	printf("this is my ssl");
    sm33_update((SM3_CTX *)ctx->md_data, data, count );
    return 1;
}

int digest_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	printf("this is my ssl");
	SM3_CTX *c = ctx->md_data;
    sm33_final(c, md);
	return 1;
}

int digest_sm3_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
	//SM3_CTX *md_ctx = to->md_data;
	if(to->md_data && from->md_data) {
		memcpy(to->md_data, from->md_data,
				sizeof(SM3_CTX));
	}
	return 1;
}

int digest_sm3_cleanup(EVP_MD_CTX *ctx)
{
	if(ctx->md_data)
		memset(ctx->md_data, 0, sizeof(SM3_CTX));
	return 1;
}

/****************************************************************************
 *			sm3 functions													*
*****************************************************************************/

int digest_selector(ENGINE *e, const EVP_MD **digest,
                    const int **nids, int nid);
					
static int digest_nids[] = { NID_sm3, 0 };

static int digests(ENGINE *e, const EVP_MD **digest,
                   const int **nids, int nid)
{
  int ok = 1;
  if (!digest) {
    /* We are returning a list of supported nids */
    *nids = digest_nids;
    return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
  }

  /* We are being asked for a specific digest */
  switch (nid) {
  case NID_sm3:
    *digest = &digest_md5;
    break;
  default:
    ok = 0;
    *digest = NULL;
    break;
  }
  return ok;
}

/****************************************************************************
 *			               sm2 engine 								                     *
*****************************************************************************/



//--------------------------------

//--------------------------------

/****************************************************************************
 *			Flunctions to handle the engine									*
*****************************************************************************/

static int bind_p11(ENGINE *e)
{
	//const RSA_METHOD *meth1;
	if(!ENGINE_set_id(e, engine_p11_id)
		|| !ENGINE_set_name(e, engine_p11_name)
		/*|| !ENGINE_set_RSA(e, &p11_rsa)*/
		/*|| !ENGINE_set_ciphers(e, mytest_ciphers)*/
		|| !ENGINE_set_digests(e, digests)
		/*|| !ENGINE_set_pkey_meths(e, sm2_pkey_meths)*/
		/*|| !ENGINE_set_pkey_asn1_meths(e, sm2_pkey_asn1_meths)*/
		|| !ENGINE_set_destroy_function(e, p11_destroy)
		|| !ENGINE_set_init_function(e, p11_init)
		|| !ENGINE_set_finish_function(e, p11_finish)
		/* || !ENGINE_set_ctrl_function(e, p11_ctrl) */
		/* || !ENGINE_set_cmd_defns(e, p11_cmd_defns) */)
		return 0;
	
	/* Ensure the p11 error handling is set up */
	ERR_load_P11_strings();
	return 1;
}




#ifdef ENGINE_DYNAMIC_SUPPORT
static int bind_helper(ENGINE *e, const char *id)
{
	if(id && (strcmp(id, engine_p11_id) != 0))
		return 0;
	if(!bind_p11(e))
		return 0;
	return 1;
}       
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#else
static ENGINE *engine_p11(void)
{
	ENGINE *ret = ENGINE_new();
	if(!ret)
		return NULL;
	if(!bind_p11(ret))
	{
		ENGINE_free(ret);
		return NULL;
	}
	return ret;
}

void ENGINE_load_pkcs11(void)
{
	/* Copied from eng_[openssl|dyn].c */
	ENGINE *toadd = engine_p11();
	if(!toadd) return;
	ENGINE_add(toadd);
	ENGINE_free(toadd);
	ERR_clear_error();
	ENGINE_set_default(toadd,0xFFFF);
}
#endif

/* Initiator which is only present to make sure this engine looks available */
static int p11_init(ENGINE *e)
{
	//printf("p11_init  OK.[FILE:%s,LINE:%d]\n",__FILE__,__LINE__);
	return 1;
}

/* Finisher which is only present to make sure this engine looks available */
static int p11_finish(ENGINE *e)
{
	//printf("p11_finish  OK.[FILE:%s,LINE:%d]\n",__FILE__,__LINE__);
	
	return 1;
}

/* Destructor (complements the "ENGINE_ncipher()" constructor) */
static int p11_destroy(ENGINE *e)
{
	
	//printf("p11_destroy  OK.[FILE:%s,LINE:%d]\n",__FILE__,__LINE__);

	
	return 1;
}

void ERR_load_P11_strings()
{
	//printf("ERR_load_P11_strings  OK.[FILE:%s,LINE:%d]\n",__FILE__,__LINE__);
	return;
	
}
