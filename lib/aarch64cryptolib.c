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
#include "AArch64cryptolib.h"

#include "picotls/aarch64cryptolib.h"
#include "picotls/openssl.h"

struct aead_crypto_context_t {
    ptls_aead_context_t super;
    uint8_t key[PTLS_MAX_SECRET_SIZE];
    uint8_t static_iv[PTLS_MAX_IV_SIZE];
};

static void aead_dispose_crypto(ptls_aead_context_t *_ctx)
{
    //struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
}

static void aead_xor_iv(ptls_aead_context_t *_ctx, const void *_bytes, size_t len)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    const uint8_t *bytes = _bytes;

    for (size_t i = 0; i < len; ++i)
        ctx->static_iv[i] ^= bytes[i];
}

static void armv8_aes_gcm_do_encrypt(ptls_aead_context_t *_ctx, void *_output,
		const void *input, size_t inlen, uint64_t seq, const void *aad,
		size_t aadlen, ptls_aead_supplementary_encryption_t *supp)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    uint8_t iv[PTLS_MAX_IV_SIZE];
    int ret;
    uint8_t *output = _output;

    ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);
    armv8_operation_result_t res = armv8_enc_aes_gcm_full(AES_GCM_256, ctx->key,
		    iv, PTLS_AESGCM_IV_SIZE<<3,
		    aad, aadlen<<3,
		    input, inlen<<3,
		    output,
		    output + inlen);
    assert(res == SUCCESSFUL_OPERATION);
    return inlen + PTLS_AESGCM_TAG_SIZE;
}

static size_t armv8_aes_gcm_do_decrypt(ptls_aead_context_t *_ctx, void *_output, const void *input, size_t inlen, uint64_t seq,
                              const void *aad, size_t aadlen)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    uint8_t *output = _output, iv[PTLS_MAX_IV_SIZE];
    size_t off = 0, tag_size = ctx->super.algo->tag_size;
    int blocklen, ret;

    if (inlen < tag_size)
        return SIZE_MAX;

    ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);
    armv8_operation_result_t res = armv8_dec_aes_gcm_full(AES_GCM_256, ctx->key,
      iv, PTLS_AESGCM_IV_SIZE<<3,
      aad, aadlen<<3,
      input, (inlen - tag_size)<<3,
      input + inlen - tag_size,
      output
    );
    if (res != SUCCESSFUL_OPERATION)
        return SIZE_MAX;
    return inlen - tag_size;
}

static int aead_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, const void *iv)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    int ret;

    memcpy(ctx->static_iv, iv, ctx->super.algo->iv_size);
    if (key == NULL)
        return 0;
    memcpy(ctx->key, key, ctx->super.algo->key_size);

    ctx->super.dispose_crypto = aead_dispose_crypto;
    ctx->super.do_xor_iv = aead_xor_iv;
    if (is_enc) {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_encrypt = armv8_aes_gcm_do_encrypt;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_decrypt = armv8_aes_gcm_do_decrypt;
    }

    return 0;

Error:
    aead_dispose_crypto(&ctx->super);
    return ret;
}

static int aead_aes256gcm_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv)
{
    return aead_setup_crypto(ctx, is_enc, key, iv);
}

ptls_aead_algorithm_t ptls_aarch64cryptolib_aes256gcm = {"AES256-GCM",
                                                PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
                                                PTLS_AESGCM_INTEGRITY_LIMIT,
                                                NULL,
                                                NULL,
                                                PTLS_AES256_KEY_SIZE,
                                                PTLS_AESGCM_IV_SIZE,
                                                PTLS_AESGCM_TAG_SIZE,
                                                sizeof(struct aead_crypto_context_t),
                                                aead_aes256gcm_setup_crypto};
ptls_cipher_suite_t ptls_aarch64cryptolib_aes256gcmsha384 = {PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &ptls_aarch64cryptolib_aes256gcm,
                                                    &ptls_openssl_sha384};
