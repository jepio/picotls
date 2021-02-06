/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <unistd.h>
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include "picotls.h"
//#include "AArch64cryptolib.h"

#include "picotls/aarch64cryptolib.h"
#include "picotls/openssl.h"

#ifdef _WINDOWS
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#pragma warning(disable : 4996)
#include <ms/applink.c>
#endif

#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
#define OPENSSL_1_1_API 1
#elif defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x2070000fL
#define OPENSSL_1_1_API 1
#else
#define OPENSSL_1_1_API 0
#endif

#if !OPENSSL_1_1_API

#define EVP_PKEY_up_ref(p) CRYPTO_add(&(p)->references, 1, CRYPTO_LOCK_EVP_PKEY)
#define X509_STORE_up_ref(p) CRYPTO_add(&(p)->references, 1, CRYPTO_LOCK_X509_STORE)

static HMAC_CTX *HMAC_CTX_new(void)
{
    HMAC_CTX *ctx;

    if ((ctx = OPENSSL_malloc(sizeof(*ctx))) == NULL)
        return NULL;
    HMAC_CTX_init(ctx);
    return ctx;
}

static void HMAC_CTX_free(HMAC_CTX *ctx)
{
    HMAC_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}

static int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx)
{
    return EVP_CIPHER_CTX_cleanup(ctx);
}

#endif

void ptls_openssl_random_bytes(void *buf, size_t len)
{
    int ret = RAND_bytes(buf, (int)len);
    if (ret != 1) {
        fprintf(stderr, "RAND_bytes() failed with code: %d\n", ret);
        abort();
    }
}

static EC_KEY *ecdh_gerenate_key(EC_GROUP *group)
{
    EC_KEY *key;

    if ((key = EC_KEY_new()) == NULL)
        return NULL;
    if (!EC_KEY_set_group(key, group) || !EC_KEY_generate_key(key)) {
        EC_KEY_free(key);
        return NULL;
    }

    return key;
}

static int ecdh_calc_secret(ptls_iovec_t *out, const EC_GROUP *group, EC_KEY *privkey, EC_POINT *peer_point)
{
    ptls_iovec_t secret;
    int ret;

    secret.len = (EC_GROUP_get_degree(group) + 7) / 8;
    if ((secret.base = malloc(secret.len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (ECDH_compute_key(secret.base, secret.len, peer_point, privkey, NULL) <= 0) {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE; /* ??? */
        goto Exit;
    }
    ret = 0;

Exit:
    if (ret == 0) {
        *out = secret;
    } else {
        free(secret.base);
        *out = (ptls_iovec_t){NULL};
    }
    return ret;
}

static EC_POINT *x9_62_decode_point(const EC_GROUP *group, ptls_iovec_t vec, BN_CTX *bn_ctx)
{
    EC_POINT *point = NULL;

    if ((point = EC_POINT_new(group)) == NULL)
        return NULL;
    if (!EC_POINT_oct2point(group, point, vec.base, vec.len, bn_ctx)) {
        EC_POINT_free(point);
        return NULL;
    }

    return point;
}

static ptls_iovec_t x9_62_encode_point(const EC_GROUP *group, const EC_POINT *point, BN_CTX *bn_ctx)
{
    ptls_iovec_t vec;

    if ((vec.len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bn_ctx)) == 0)
        return (ptls_iovec_t){NULL};
    if ((vec.base = malloc(vec.len)) == NULL)
        return (ptls_iovec_t){NULL};
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, vec.base, vec.len, bn_ctx) != vec.len) {
        free(vec.base);
        return (ptls_iovec_t){NULL};
    }

    return vec;
}

struct st_x9_62_keyex_context_t {
    ptls_key_exchange_context_t super;
    BN_CTX *bn_ctx;
    EC_KEY *privkey;
};

static void x9_62_free_context(struct st_x9_62_keyex_context_t *ctx)
{
    free(ctx->super.pubkey.base);
    if (ctx->privkey != NULL)
        EC_KEY_free(ctx->privkey);
    if (ctx->bn_ctx != NULL)
        BN_CTX_free(ctx->bn_ctx);
    free(ctx);
}

static int x9_62_on_exchange(ptls_key_exchange_context_t **_ctx, int release, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    struct st_x9_62_keyex_context_t *ctx = (struct st_x9_62_keyex_context_t *)*_ctx;
    const EC_GROUP *group = EC_KEY_get0_group(ctx->privkey);
    EC_POINT *peer_point = NULL;
    int ret;

    if (secret == NULL) {
        ret = 0;
        goto Exit;
    }

    if ((peer_point = x9_62_decode_point(group, peerkey, ctx->bn_ctx)) == NULL) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }
    if ((ret = ecdh_calc_secret(secret, group, ctx->privkey, peer_point)) != 0)
        goto Exit;

Exit:
    if (peer_point != NULL)
        EC_POINT_free(peer_point);
    if (release) {
        x9_62_free_context(ctx);
        *_ctx = NULL;
    }
    return ret;
}

static int x9_62_create_context(ptls_key_exchange_algorithm_t *algo, struct st_x9_62_keyex_context_t **ctx)
{
    int ret;

    if ((*ctx = (struct st_x9_62_keyex_context_t *)malloc(sizeof(**ctx))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    **ctx = (struct st_x9_62_keyex_context_t){{algo, {NULL}, x9_62_on_exchange}};

    if (((*ctx)->bn_ctx = BN_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    ret = 0;
Exit:
    if (ret != 0 && *ctx != NULL) {
        x9_62_free_context(*ctx);
        *ctx = NULL;
    }
    return ret;
}

static int x9_62_setup_pubkey(struct st_x9_62_keyex_context_t *ctx)
{
    const EC_GROUP *group = EC_KEY_get0_group(ctx->privkey);
    const EC_POINT *pubkey = EC_KEY_get0_public_key(ctx->privkey);
    if ((ctx->super.pubkey = x9_62_encode_point(group, pubkey, ctx->bn_ctx)).base == NULL)
        return PTLS_ERROR_NO_MEMORY;
    return 0;
}

static int x9_62_create_key_exchange(ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **_ctx)
{
    EC_GROUP *group = NULL;
    struct st_x9_62_keyex_context_t *ctx = NULL;
    int ret;

    /* FIXME use a global? */
    if ((group = EC_GROUP_new_by_curve_name((int)algo->data)) == NULL) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if ((ret = x9_62_create_context(algo, &ctx)) != 0)
        goto Exit;
    if ((ctx->privkey = ecdh_gerenate_key(group)) == NULL) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if ((ret = x9_62_setup_pubkey(ctx)) != 0)
        goto Exit;
    ret = 0;

Exit:
    if (group != NULL)
        EC_GROUP_free(group);
    if (ret == 0) {
        *_ctx = &ctx->super;
    } else {
        if (ctx != NULL)
            x9_62_free_context(ctx);
        *_ctx = NULL;
    }

    return ret;
}

static int x9_62_init_key(ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **_ctx, EC_KEY *eckey)
{
    struct st_x9_62_keyex_context_t *ctx = NULL;
    int ret;

    if ((ret = x9_62_create_context(algo, &ctx)) != 0)
        goto Exit;
    ctx->privkey = eckey;
    if ((ret = x9_62_setup_pubkey(ctx)) != 0)
        goto Exit;
    ret = 0;

Exit:
    if (ret == 0) {
        *_ctx = &ctx->super;
    } else {
        if (ctx != NULL)
            x9_62_free_context(ctx);
        *_ctx = NULL;
    }
    return ret;
}

static int x9_62_key_exchange(EC_GROUP *group, ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey, BN_CTX *bn_ctx)
{
    EC_POINT *peer_point = NULL;
    EC_KEY *privkey = NULL;
    int ret;

    *pubkey = (ptls_iovec_t){NULL};
    *secret = (ptls_iovec_t){NULL};

    /* decode peer key */
    if ((peer_point = x9_62_decode_point(group, peerkey, bn_ctx)) == NULL) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }

    /* create private key */
    if ((privkey = ecdh_gerenate_key(group)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* encode public key */
    if ((*pubkey = x9_62_encode_point(group, EC_KEY_get0_public_key(privkey), bn_ctx)).base == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* calc secret */
    secret->len = (EC_GROUP_get_degree(group) + 7) / 8;
    if ((secret->base = malloc(secret->len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* ecdh! */
    if (ECDH_compute_key(secret->base, secret->len, peer_point, privkey, NULL) <= 0) {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE; /* ??? */
        goto Exit;
    }

    ret = 0;

Exit:
    if (peer_point != NULL)
        EC_POINT_free(peer_point);
    if (privkey != NULL)
        EC_KEY_free(privkey);
    if (ret != 0) {
        free(pubkey->base);
        *pubkey = (ptls_iovec_t){NULL};
        free(secret->base);
        *secret = (ptls_iovec_t){NULL};
    }
    return ret;
}

static int secp_key_exchange(ptls_key_exchange_algorithm_t *algo, ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    EC_GROUP *group = NULL;
    BN_CTX *bn_ctx = NULL;
    int ret;

    if ((group = EC_GROUP_new_by_curve_name((int)algo->data)) == NULL) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if ((bn_ctx = BN_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    ret = x9_62_key_exchange(group, pubkey, secret, peerkey, bn_ctx);

Exit:
    if (bn_ctx != NULL)
        BN_CTX_free(bn_ctx);
    if (group != NULL)
        EC_GROUP_free(group);
    return ret;
}

#if PTLS_OPENSSL_HAVE_X25519

struct st_evp_keyex_context_t {
    ptls_key_exchange_context_t super;
    EVP_PKEY *privkey;
};

static void evp_keyex_free(struct st_evp_keyex_context_t *ctx)
{
    if (ctx->privkey != NULL)
        EVP_PKEY_free(ctx->privkey);
    if (ctx->super.pubkey.base != NULL)
        OPENSSL_free(ctx->super.pubkey.base);
    free(ctx);
}

static int evp_keyex_on_exchange(ptls_key_exchange_context_t **_ctx, int release, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    struct st_evp_keyex_context_t *ctx = (void *)*_ctx;
    EVP_PKEY *evppeer = NULL;
    EVP_PKEY_CTX *evpctx = NULL;
    int ret;

    if (secret == NULL) {
        ret = 0;
        goto Exit;
    }

    secret->base = NULL;

    if (peerkey.len != ctx->super.pubkey.len) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }

    if ((evppeer = EVP_PKEY_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (EVP_PKEY_copy_parameters(evppeer, ctx->privkey) <= 0) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_PKEY_set1_tls_encodedpoint(evppeer, peerkey.base, peerkey.len) <= 0) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if ((evpctx = EVP_PKEY_CTX_new(ctx->privkey, NULL)) == NULL) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_PKEY_derive_init(evpctx) <= 0) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_PKEY_derive_set_peer(evpctx, evppeer) <= 0) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_PKEY_derive(evpctx, NULL, &secret->len) <= 0) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if ((secret->base = malloc(secret->len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (EVP_PKEY_derive(evpctx, secret->base, &secret->len) <= 0) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }

    ret = 0;
Exit:
    if (evpctx != NULL)
        EVP_PKEY_CTX_free(evpctx);
    if (evppeer != NULL)
        EVP_PKEY_free(evppeer);
    if (ret != 0)
        free(secret->base);
    if (release) {
        evp_keyex_free(ctx);
        *_ctx = NULL;
    }
    return ret;
}

static int evp_keyex_init(ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **_ctx, EVP_PKEY *pkey)
{
    struct st_evp_keyex_context_t *ctx = NULL;
    int ret;

    /* instantiate */
    if ((ctx = malloc(sizeof(*ctx))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    *ctx = (struct st_evp_keyex_context_t){{algo, {NULL}, evp_keyex_on_exchange}, pkey};

    /* set public key */
    if ((ctx->super.pubkey.len = EVP_PKEY_get1_tls_encodedpoint(ctx->privkey, &ctx->super.pubkey.base)) == 0) {
        ctx->super.pubkey.base = NULL;
        return PTLS_ERROR_NO_MEMORY;
    }

    *_ctx = &ctx->super;
    ret = 0;
Exit:
    if (ret != 0 && ctx != NULL)
        evp_keyex_free(ctx);
    return ret;
}

static int evp_keyex_create(ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **ctx)
{
    EVP_PKEY_CTX *evpctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret;

    /* generate private key */
    if ((evpctx = EVP_PKEY_CTX_new_id((int)algo->data, NULL)) == NULL) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_PKEY_keygen_init(evpctx) <= 0) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_PKEY_keygen(evpctx, &pkey) <= 0) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }

    /* setup */
    if ((ret = evp_keyex_init(algo, ctx, pkey)) != 0)
        goto Exit;
    pkey = NULL;
    ret = 0;

Exit:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (evpctx != NULL)
        EVP_PKEY_CTX_free(evpctx);
    return ret;
}

static int evp_keyex_exchange(ptls_key_exchange_algorithm_t *algo, ptls_iovec_t *outpubkey, ptls_iovec_t *secret,
                              ptls_iovec_t peerkey)
{
    ptls_key_exchange_context_t *ctx = NULL;
    int ret;

    outpubkey->base = NULL;

    if ((ret = evp_keyex_create(algo, &ctx)) != 0)
        goto Exit;
    if ((outpubkey->base = malloc(ctx->pubkey.len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    memcpy(outpubkey->base, ctx->pubkey.base, ctx->pubkey.len);
    outpubkey->len = ctx->pubkey.len;
    ret = evp_keyex_on_exchange(&ctx, 1, secret, peerkey);
    assert(ctx == NULL);

Exit:
    if (ctx != NULL)
        evp_keyex_on_exchange(&ctx, 1, NULL, ptls_iovec_init(NULL, 0));
    if (ret != 0)
        free(outpubkey->base);
    return ret;
}

#endif

int ptls_openssl_create_key_exchange(ptls_key_exchange_context_t **ctx, EVP_PKEY *pkey)
{
    int ret, id;

    switch (id = EVP_PKEY_id(pkey)) {

    case EVP_PKEY_EC: {
        /* obtain eckey */
        EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pkey);

        /* determine algo */
        ptls_key_exchange_algorithm_t *algo;
        switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey))) {
        case NID_X9_62_prime256v1:
            algo = &ptls_openssl_secp256r1;
            break;
#if PTLS_OPENSSL_HAVE_SECP384R1
        case NID_secp384r1:
            algo = &ptls_openssl_secp384r1;
            break;
#endif
#if PTLS_OPENSSL_HAVE_SECP521R1
        case NID_secp521r1:
            algo = &ptls_openssl_secp521r1;
            break;
#endif
        default:
            EC_KEY_free(eckey);
            return PTLS_ERROR_INCOMPATIBLE_KEY;
        }

        /* load key */
        if ((ret = x9_62_init_key(algo, ctx, eckey)) != 0) {
            EC_KEY_free(eckey);
            return ret;
        }

        return 0;
    } break;

#if PTLS_OPENSSL_HAVE_X25519
    case NID_X25519:
        if ((ret = evp_keyex_init(&ptls_openssl_x25519, ctx, pkey)) != 0)
            return ret;
        EVP_PKEY_up_ref(pkey);
        return 0;
#endif

    default:
        return PTLS_ERROR_INCOMPATIBLE_KEY;
    }
}

static int do_sign(EVP_PKEY *key, ptls_buffer_t *outbuf, ptls_iovec_t input, const EVP_MD *md)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx;
    size_t siglen;
    int ret;

    if ((ctx = EVP_MD_CTX_create()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (EVP_DigestSignInit(ctx, &pkey_ctx, md, NULL, key) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_PKEY_id(key) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
    }
    if (EVP_DigestSignUpdate(ctx, input.base, input.len) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_DigestSignFinal(ctx, NULL, &siglen) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if ((ret = ptls_buffer_reserve(outbuf, siglen)) != 0)
        goto Exit;
    if (EVP_DigestSignFinal(ctx, outbuf->base + outbuf->off, &siglen) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    outbuf->off += siglen;

    ret = 0;
Exit:
    if (ctx != NULL)
        EVP_MD_CTX_destroy(ctx);
    return ret;
}

struct cipher_context_t {
    ptls_cipher_context_t super;
    EVP_CIPHER_CTX *evp;
};

static void cipher_dispose(ptls_cipher_context_t *_ctx)
{
    struct cipher_context_t *ctx = (struct cipher_context_t *)_ctx;
    EVP_CIPHER_CTX_free(ctx->evp);
}

static void cipher_do_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct cipher_context_t *ctx = (struct cipher_context_t *)_ctx;
    int ret;
    ret = EVP_EncryptInit_ex(ctx->evp, NULL, NULL, NULL, iv);
    assert(ret);
}

static int cipher_setup_crypto(ptls_cipher_context_t *_ctx, int is_enc, const void *key, const EVP_CIPHER *cipher,
                               void (*do_transform)(ptls_cipher_context_t *, void *, const void *, size_t))
{
    struct cipher_context_t *ctx = (struct cipher_context_t *)_ctx;

    ctx->super.do_dispose = cipher_dispose;
    ctx->super.do_init = cipher_do_init;
    ctx->super.do_transform = do_transform;

    if ((ctx->evp = EVP_CIPHER_CTX_new()) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    if (is_enc) {
        if (!EVP_EncryptInit_ex(ctx->evp, cipher, NULL, key, NULL))
            goto Error;
    } else {
        if (!EVP_DecryptInit_ex(ctx->evp, cipher, NULL, key, NULL))
            goto Error;
        EVP_CIPHER_CTX_set_padding(ctx->evp, 0); /* required to disable one block buffering in ECB mode */
    }

    return 0;
Error:
    EVP_CIPHER_CTX_free(ctx->evp);
    return PTLS_ERROR_LIBRARY;
}

static void cipher_encrypt(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t _len)
{
    struct cipher_context_t *ctx = (struct cipher_context_t *)_ctx;
    int len = (int)_len, ret = EVP_EncryptUpdate(ctx->evp, output, &len, input, len);
    assert(ret);
    assert(len == (int)_len);
}

static void cipher_decrypt(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t _len)
{
    struct cipher_context_t *ctx = (struct cipher_context_t *)_ctx;
    int len = (int)_len, ret = EVP_DecryptUpdate(ctx->evp, output, &len, input, len);
    assert(ret);
    assert(len == (int)_len);
}

static int aes128ecb_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return cipher_setup_crypto(ctx, is_enc, key, EVP_aes_128_ecb(), is_enc ? cipher_encrypt : cipher_decrypt);
}

static int aes256ecb_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return cipher_setup_crypto(ctx, is_enc, key, EVP_aes_256_ecb(), is_enc ? cipher_encrypt : cipher_decrypt);
}

static int aes128ctr_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return cipher_setup_crypto(ctx, 1, key, EVP_aes_128_ctr(), cipher_encrypt);
}

static int aes256ctr_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return cipher_setup_crypto(ctx, 1, key, EVP_aes_256_ctr(), cipher_encrypt);
}

#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305

static int chacha20_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return cipher_setup_crypto(ctx, 1, key, EVP_chacha20(), cipher_encrypt);
}

#endif

#if PTLS_OPENSSL_HAVE_BF

static int bfecb_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return cipher_setup_crypto(ctx, is_enc, key, EVP_bf_ecb(), is_enc ? cipher_encrypt : cipher_decrypt);
}

#endif

struct aead_crypto_context_t {
    ptls_aead_context_t super;
    EVP_CIPHER_CTX *evp_ctx;
    uint8_t static_iv[PTLS_MAX_IV_SIZE];
};

static void aead_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;

    if (ctx->evp_ctx != NULL)
        EVP_CIPHER_CTX_free(ctx->evp_ctx);
}

static void aead_xor_iv(ptls_aead_context_t *_ctx, const void *_bytes, size_t len)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    const uint8_t *bytes = _bytes;

    for (size_t i = 0; i < len; ++i)
        ctx->static_iv[i] ^= bytes[i];
}

static void aead_do_encrypt_init(ptls_aead_context_t *_ctx, uint64_t seq, const void *aad, size_t aadlen)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    uint8_t iv[PTLS_MAX_IV_SIZE];
    int ret;

    ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);
    ret = EVP_EncryptInit_ex(ctx->evp_ctx, NULL, NULL, NULL, iv);
    assert(ret);

    if (aadlen != 0) {
        int blocklen;
        ret = EVP_EncryptUpdate(ctx->evp_ctx, NULL, &blocklen, aad, (int)aadlen);
        assert(ret);
    }
}

static size_t aead_do_encrypt_update(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    int blocklen, ret;

    ret = EVP_EncryptUpdate(ctx->evp_ctx, output, &blocklen, input, (int)inlen);
    assert(ret);

    return blocklen;
}

static size_t aead_do_encrypt_final(ptls_aead_context_t *_ctx, void *_output)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    uint8_t *output = _output;
    size_t off = 0, tag_size = ctx->super.algo->tag_size;
    int blocklen, ret;

    ret = EVP_EncryptFinal_ex(ctx->evp_ctx, output + off, &blocklen);
    assert(ret);
    off += blocklen;
    ret = EVP_CIPHER_CTX_ctrl(ctx->evp_ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_size, output + off);
    assert(ret);
    off += tag_size;

    return off;
}

static size_t aead_do_decrypt(ptls_aead_context_t *_ctx, void *_output, const void *input, size_t inlen, uint64_t seq,
                              const void *aad, size_t aadlen)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    uint8_t *output = _output, iv[PTLS_MAX_IV_SIZE];
    size_t off = 0, tag_size = ctx->super.algo->tag_size;
    int blocklen, ret;

    if (inlen < tag_size)
        return SIZE_MAX;

    ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);
    ret = EVP_DecryptInit_ex(ctx->evp_ctx, NULL, NULL, NULL, iv);
    assert(ret);
    if (aadlen != 0) {
        ret = EVP_DecryptUpdate(ctx->evp_ctx, NULL, &blocklen, aad, (int)aadlen);
        assert(ret);
    }
    ret = EVP_DecryptUpdate(ctx->evp_ctx, output + off, &blocklen, input, (int)(inlen - tag_size));
    assert(ret);
    off += blocklen;
    if (!EVP_CIPHER_CTX_ctrl(ctx->evp_ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_size, (void *)((uint8_t *)input + inlen - tag_size)))
        return SIZE_MAX;
    if (!EVP_DecryptFinal_ex(ctx->evp_ctx, output + off, &blocklen))
        return SIZE_MAX;
    off += blocklen;

    return off;
}

static int aead_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, const void *iv, const EVP_CIPHER *cipher)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    int ret;

    memcpy(ctx->static_iv, iv, ctx->super.algo->iv_size);
    if (key == NULL)
        return 0;

    ctx->super.dispose_crypto = aead_dispose_crypto;
    ctx->super.do_xor_iv = aead_xor_iv;
    if (is_enc) {
        ctx->super.do_encrypt_init = aead_do_encrypt_init;
        ctx->super.do_encrypt_update = aead_do_encrypt_update;
        ctx->super.do_encrypt_final = aead_do_encrypt_final;
        ctx->super.do_encrypt = ptls_aead__do_encrypt;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_decrypt = aead_do_decrypt;
    }
    ctx->evp_ctx = NULL;

    if ((ctx->evp_ctx = EVP_CIPHER_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }
    if (is_enc) {
        if (!EVP_EncryptInit_ex(ctx->evp_ctx, cipher, NULL, key, NULL)) {
            ret = PTLS_ERROR_LIBRARY;
            goto Error;
        }
    } else {
        if (!EVP_DecryptInit_ex(ctx->evp_ctx, cipher, NULL, key, NULL)) {
            ret = PTLS_ERROR_LIBRARY;
            goto Error;
        }
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx->evp_ctx, EVP_CTRL_GCM_SET_IVLEN, (int)ctx->super.algo->iv_size, NULL)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Error;
    }

    return 0;

Error:
    aead_dispose_crypto(&ctx->super);
    return ret;
}

static int aead_aes256gcm_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv)
{
    return aead_setup_crypto(ctx, is_enc, key, iv, EVP_aes_256_gcm());
}

ptls_aead_algorithm_t ptls_openssl_aes256gcm = {"AES256-GCM",
                                                PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
                                                PTLS_AESGCM_INTEGRITY_LIMIT,
                                                NULL,
                                                NULL,
                                                PTLS_AES256_KEY_SIZE,
                                                PTLS_AESGCM_IV_SIZE,
                                                PTLS_AESGCM_TAG_SIZE,
                                                sizeof(struct aead_crypto_context_t),
                                                aead_aes256gcm_setup_crypto};
ptls_cipher_suite_t ptls_openssl_aes256gcmsha384 = {PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &ptls_aarch64cryptolib_aes256gcm,
                                                    &ptls_openssl_sha384};
