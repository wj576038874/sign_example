/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/bb1ibe.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_BB1IBE,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_BB1IBE,0,reason)

static ERR_STRING_DATA BB1IBE_str_functs[] = {
    {ERR_FUNC(BB1IBE_F_BB1CIPHERTEXTBLOCK_HASH_TO_RANGE),
     "BB1CiphertextBlock_hash_to_range"},
    {ERR_FUNC(BB1IBE_F_BB1IBE_DECRYPT), "BB1IBE_decrypt"},
    {ERR_FUNC(BB1IBE_F_BB1IBE_DOUBLE_HASH), "BB1IBE_double_hash"},
    {ERR_FUNC(BB1IBE_F_BB1IBE_DO_DECRYPT), "BB1IBE_do_decrypt"},
    {ERR_FUNC(BB1IBE_F_BB1IBE_DO_ENCRYPT), "BB1IBE_do_encrypt"},
    {ERR_FUNC(BB1IBE_F_BB1IBE_ENCRYPT), "BB1IBE_encrypt"},
    {ERR_FUNC(BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY),
     "BB1IBE_extract_private_key"},
    {ERR_FUNC(BB1IBE_F_BB1IBE_SETUP), "BB1IBE_setup"},
    {0, NULL}
};

static ERR_STRING_DATA BB1IBE_str_reasons[] = {
    {ERR_REASON(BB1IBE_R_BB1CIPHERTEXT_INVALID_MAC),
     "bb1ciphertext invalid mac"},
    {ERR_REASON(BB1IBE_R_BB1IBE_HASH_FAILURE), "bb1ibe hash failure"},
    {ERR_REASON(BB1IBE_R_BUFFER_TOO_SMALL), "buffer too small"},
    {ERR_REASON(BB1IBE_R_COMPUTE_OUTLEN_FAILURE), "compute outlen failure"},
    {ERR_REASON(BB1IBE_R_COMPUTE_TATE_FAILURE), "compute tate failure"},
    {ERR_REASON(BB1IBE_R_D2I_FAILURE), "d2i failure"},
    {ERR_REASON(BB1IBE_R_DECRYPT_FAILURE), "decrypt failure"},
    {ERR_REASON(BB1IBE_R_DOUBLE_HASH_FAILURE), "double hash failure"},
    {ERR_REASON(BB1IBE_R_ENCRYPT_FAILURE), "encrypt failure"},
    {ERR_REASON(BB1IBE_R_I2D_FAILURE), "i2d failure"},
    {ERR_REASON(BB1IBE_R_INVALID_INPUT), "invalid input"},
    {ERR_REASON(BB1IBE_R_INVALID_MD), "invalid md"},
    {ERR_REASON(BB1IBE_R_INVALID_OUTPUT_BUFFER), "invalid output buffer"},
    {ERR_REASON(BB1IBE_R_INVALID_TYPE1CURVE), "invalid type1curve"},
    {ERR_REASON(BB1IBE_R_NOT_NAMED_CURVE), "not named curve"},
    {ERR_REASON(BB1IBE_R_PARSE_PAIRING), "parse pairing"},
    {0, NULL}
};

#endif

int ERR_load_BB1IBE_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(BB1IBE_str_functs[0].error) == NULL) {
        ERR_load_strings(0, BB1IBE_str_functs);
        ERR_load_strings(0, BB1IBE_str_reasons);
    }
#endif
    return 1;
}
