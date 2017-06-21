#define EVP_PKEY_NULL_method	NULL,NULL,{0,0,0,0}
#include "sm2_lcl.h"
static int digest_sm3_init(EVP_MD_CTX *ctx);
static int digest_sm3_update(EVP_MD_CTX *ctx, const void *data,
        size_t count);
static int digest_sm3_final(EVP_MD_CTX *ctx, unsigned char *md);
static int digest_sm3_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int digest_sm3_cleanup(EVP_MD_CTX *ctx);



/****************************************************************************
 *			 Constants used when creating the ENGINE						*
 ***************************************************************************/
static const char *engine_p11_id = "sm3engine";
static const char *engine_p11_name = "sm3 engine support(by dz)";


/****************************************************************************
 *			Functions to handle the engine									*
 ***************************************************************************/
static int p11_destroy(ENGINE *e);
static int p11_init(ENGINE *e);
static int p11_finish(ENGINE *e);


/****************************************************************************
 *			Engine commands													*
*****************************************************************************/
static const ENGINE_CMD_DEFN p11_cmd_defns[] = 
{
	{0, NULL, NULL, 0}
};


static const EVP_MD digest_md5 = {
  NID_sm3,                      /* The name ID for MD5 */
  NID_sm2sign_with_sm3,         /* IGNORED: MD5 with private key encryption NID */
  32,                           /* Size of MD5 result, in bytes */
  0,                            /* Flags */
  digest_sm3_init,                     /* digest init */
  digest_sm3_update,                /* digest update */
  digest_sm3_final,                   /* digest final */
  digest_sm3_copy,                        /* digest copy */
  digest_sm3_cleanup,                      /* digest cleanup */
  (evp_sign_method *)SM2_sign,
  (evp_verify_method *)SM2_verify,
  {NID_sm2sign,0,0,0},              /* IGNORED: pkey methods */
  64,                           /* Internal blocksize, see rfc1321/md5.h */
  sizeof(SM3_CTX),
  NULL                          /* IGNORED: control function */
};

/****************************************************************************
 *			Symetric cipher and digest function registrars					*
*****************************************************************************/

static int p11_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
						  const int **nids, int nid);

static int p11_digests(ENGINE *e, const EVP_MD **digest,
						  const int **nids, int nid);


static int p11_cipher_nids[] ={ NID_des_cbc, NID_des_ede3_cbc, NID_desx_cbc, 0 };
static int p11_digest_nids[] ={ NID_md2, NID_md5, 0 };



void ERR_load_P11_strings();



void ENGINE_load_pkcs11();


