#ifndef SM2_TOOLS_H
# define SM2_TOOLS_H
# include <inttypes.h>
# include <openssl/bn.h>
# include <openssl/evp.h>
# include <openssl/dsa.h>
# include <openssl/asn1t.h>
# include <openssl/x509.h>
# include <openssl/engine.h>
# include <openssl/ec.h>

extern const ENGINE_CMD_DEFN sm2_cmds[];
int sm2_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void));
const char *get_sm2_engine_param(int param);
int sm2_set_default_param(int param, const char *value);
void sm2_param_free(void);


/* method registration */

int register_ameth_sm2(int nid, EVP_PKEY_ASN1_METHOD **ameth,
                        const char *pemstr, const char *info);
int register_pmeth_sm2(int id, EVP_PKEY_METHOD **pmeth, int flags);

/* Gost-specific pmeth control-function parameters */
/* For GOST R34.10 parameters */
# define param_ctrl_string "paramset"
# define EVP_PKEY_CTRL_SM2_PARAMSET (EVP_PKEY_ALG_CTRL+1)
/* For GOST 28147 MAC */
# define key_ctrl_string "key"
# define hexkey_ctrl_string "hexkey"
# define EVP_PKEY_CTRL_SM2_MAC_HEXKEY (EVP_PKEY_ALG_CTRL+3)





typedef struct {
    ASN1_OCTET_STRING *encrypted_key;
    ASN1_OCTET_STRING *imit;
} SM2_KEY_INFO;
DECLARE_ASN1_FUNCTIONS(SM2_KEY_INFO)

typedef struct {
    ASN1_OBJECT *cipher;
    X509_PUBKEY *ephem_key;
    ASN1_OCTET_STRING *eph_iv;
} SM2_KEY_AGREEMENT_INFO;
DECLARE_ASN1_FUNCTIONS(SM2_KEY_AGREEMENT_INFO)

typedef struct {
    SM2_KEY_INFO *key_info;
    SM2_KEY_AGREEMENT_INFO *key_agreement_info;
} SM2_KEY_TRANSPORT;
DECLARE_ASN1_FUNCTIONS(SM2_KEY_TRANSPORT)

typedef struct {                /* FIXME incomplete */
    SM2_KEY_TRANSPORT *gkt;
} SM2_CLIENT_KEY_EXCHANGE_PARAMS;


# ifdef OPENSSL_SYS_VMS
#  undef SM2_CLIENT_KEY_EXCHANGE_PARAMS_it
#  define SM2_CLIENT_KEY_EXCHANGE_PARAMS_it      SM2_CLIENT_KEY_EXC_PARAMS_it
#  undef SM2_CLIENT_KEY_EXCHANGE_PARAMS_new
#  define SM2_CLIENT_KEY_EXCHANGE_PARAMS_new     SM2_CLIENT_KEY_EXC_PARAMS_new
#  undef SM2_CLIENT_KEY_EXCHANGE_PARAMS_free
#  define SM2_CLIENT_KEY_EXCHANGE_PARAMS_free    SM2_CLIENT_KEY_EXC_PARAMS_free
#  undef d2i_SM2_CLIENT_KEY_EXCHANGE_PARAMS
#  define d2i_SM2_CLIENT_KEY_EXCHANGE_PARAMS     d2i_SM2_CLIENT_KEY_EXC_PARAMS
#  undef i2d_SM2_CLIENT_KEY_EXCHANGE_PARAMS
#  define i2d_SM2_CLIENT_KEY_EXCHANGE_PARAMS     i2d_SM2_CLIENT_KEY_EXC_PARAMS
# endif                         
/* End of hack */
DECLARE_ASN1_FUNCTIONS(SM2_CLIENT_KEY_EXCHANGE_PARAMS)

/*============= Message digest  and cipher related structures  =========*/

typedef struct sm3_ctx_st {
    uint32_t total[2];        // number of bytes processed
    uint32_t iv[8];           // iv初始值

    unsigned char buffer[64]; //
    unsigned char ipad[64];   // HMAC inner padding
    unsigned char opad[64];   // HMAC inner padding
} SM3_CTX;

/* EVP_MD structure for SM3 */
extern EVP_MD digest_sm3;


const struct sm2_cipher_info *get_encryption_params(ASN1_OBJECT *obj);
/* Implementation of GOST 28147-89 cipher in CFB and CNT modes */
extern EVP_CIPHER cipher_sm2;
extern EVP_CIPHER cipher_sm2_cpacnt;
# define EVP_MD_CTRL_KEY_LEN (EVP_MD_CTRL_ALG_CTRL+3)
# define EVP_MD_CTRL_SET_KEY (EVP_MD_CTRL_ALG_CTRL+4)
/* EVP_PKEY_METHOD key encryption callbacks */
/* From sm2_keyx.c */
int pkey_SM2cp_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out,
                          size_t *outlen, const unsigned char *key,
                          size_t key_len);

int pkey_SM2cp_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out,
                          size_t *outlen, const unsigned char *in,
                          size_t in_len);
/* derive functions */
/* From sm2_keyx.c */
int pkey_sm2_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                         size_t *keylen);

/* Internal functions for signature algorithms */
int fill_SM2_params(EC_KEY *eckey, int nid);
int sm2_sign_keygen(DSA *dsa);
int sm2_keygen(EC_KEY *ec);

//DSA_SIG *sm2_do_sign(const unsigned char *dgst, int dlen, EC_KEY *eckey);
ECDSA_SIG *sm2_do_sign(const unsigned char *dgst, int dgst_len,
        const BIGNUM *in_k, const BIGNUM *in_r, EC_KEY *eckey);

//int sm2_do_verify(const unsigned char *dgst, int dgst_len,
//                       DSA_SIG *sig, EC_KEY *ec);

int	  SM22_sign(int type, const unsigned char *dgst, int dlen,
        unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

int SM22_verify(int type, const unsigned char *dgst, int dgst_len,
        const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);

void sm33_update( SM3_CTX *ctx, const void *input, int ilen );
void sm33_final( SM3_CTX *ctx, unsigned char output[32] );

int sm2_compute_public(EC_KEY *ec);

/*============== miscellaneous functions============================= */
/* from sm2_sign.c */
/* Convert GOST R 34.11 hash sum to bignum according to standard */
BIGNUM *hashsum2bn(const unsigned char *dgst);

/*
 * Store bignum in byte array of given length, prepending by zeros if
 * nesseccary
 */
int store_bignum(BIGNUM *bn, unsigned char *buf, int len);

/* Read bignum, which can have few MSB all-zeros    from buffer*/
BIGNUM *getbnfrombuf(const unsigned char *buf, size_t len);

/* Pack signature according to CryptoPro rules */
int pack_sign_cp(DSA_SIG *s, int order, unsigned char *sig, size_t *siglen);
/* Unpack signature according to CryptoPro rules */
DSA_SIG *unpack_cp_signature(const unsigned char *sig, size_t siglen);

/* from ameth.c */
/* Get private key as BIGNUM from both R 34.10-94 and R 34.10-2001  keys*/
/* Returns pointer into EVP_PKEY structure */
BIGNUM *gost_get0_priv_key(const EVP_PKEY *pkey);
/* Find NID by GOST 94 parameters */
int gost94_nid_by_params(DSA *p);

#endif
