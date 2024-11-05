/* fips_rsastest.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2005.
 */
/* ====================================================================
 * Copyright (c) 2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#define OPENSSL_FIPSAPI

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#include "acvp.h"

#ifndef OPENSSL_FIPS

int main(int argc, char *argv[])
{
    printf("No FIPS RSA support\n");
    return(0);
}

#else

#include <openssl/rsa.h>
#include <openssl/fips.h>
#include "fips_utl.h"

static int rsa_stest_acvp(FILE *out, FILE *in, int Saltlen);
static int rsa_stest_cavs(FILE *out, FILE *in, int Saltlen);
static int rsa_printsig(FILE *out, RSA *rsa, const EVP_MD *dgst,
		unsigned char *Msg, long Msglen, int Saltlen, unsigned char **sig, int *sig_len);

#ifdef FIPS_ALGVS
int fips_rsastest_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
	{
	FILE *in = NULL, *out = NULL;

	int ret = 1, Saltlen = -1;

	fips_algtest_init();

    if(select_mode() != 0)  {
        printf("Unable to determine if CAVS or ACVP mode selected.\n");
        return -1;
    }

	if ((argc > 2) && !strcmp("-saltlen", argv[1]))
		{
		Saltlen = atoi(argv[2]);
		if (Saltlen < 0)
			{
			fprintf(stderr, "FATAL: Invalid salt length\n");
			goto end;
			}
		argc -= 2;
		argv += 2;
		}
	else if ((argc > 1) && !strcmp("-x931", argv[1]))
		{
		Saltlen = -2;
		argc--;
		argv++;
		}

	if (argc == 1)
		in = stdin;
	else
		in = fopen(argv[1], "r");

	if (argc < 2)
		out = stdout;
	else
		out = fopen(argv[2], "w");

	if (!in)
		{
		fprintf(stderr, "FATAL input initialization error\n");
		goto end;
		}

	if (!out)
		{
		fprintf(stderr, "FATAL output initialization error\n");
		goto end;
		}

    int res = 0;
    if (cavs)
        res = rsa_stest_cavs(out, in, Saltlen);
    else if (acvp)
        res = rsa_stest_acvp(out, in, Saltlen);
    else
        printf("Unknown operational mode (CAVS or ACVP required).");

    if (!res)
        {
        fprintf(stderr, "FATAL RSASTEST file processing error\n");
        goto end;
        }
    else
        ret = 0;

	end:

	if (in && (in != stdin))
		fclose(in);
	if (out && (out != stdout))
		fclose(out);

	return ret;

	}

#define RSA_TEST_MAXLINELEN	10240

int rsa_stest_acvp(FILE *out, FILE *in, int Saltlen)  {
    RSA *rsa = NULL;
    BIGNUM *ebn = NULL;
    const EVP_MD *dgst = NULL;
    unsigned char *msg = NULL;
    int msg_len = 0;
    unsigned char *n = NULL, *e = NULL;
    size_t n_len = 0, e_len = 0;
    unsigned char *sig = NULL;
    int sig_len = 0;


    int ret = 0;    /* Everything consider failure until it gets to end */

    cJSON *json = NULL; 
    cJSON *output = NULL;

    if ((json = read_fd_as_json(in)) == NULL)  {
        printf("Cannot parse JSON file\n");
        goto error_die;
    }

    /* Check version is correct */
    if (!verify_acvp_version(json, "1.0"))  {
        printf("ACVP version number is not expected.");
        goto error_die;
    }

    /* Initialize output structure */
    output = init_output (json);

    /* Vector set */
    cJSON *vs = NULL;
    SAFEGET(get_array_item(&vs, json, 1), "Vector set missing in JSON\n");

    /* Construct the (empty) response body */
    cJSON *response = cJSON_CreateObject ();
    cJSON *vsId = NULL;
    SAFEGET (get_integer_object (&vsId, vs, "vsId"), "vsId missing in JSON\n");
    SAFEPUT (put_integer ("vsId", vsId->valueint, response), "Unable to add vsId to output JSON\n");
    cJSON *tgs_output = cJSON_CreateArray ();
    SAFEPUT (put_object ("testGroups", tgs_output, response), "Unable to add testGroups to output JSON\n");

    SAFEPUT (put_array_item (response, output), "Unable to add response body to JSON\n");
    
    /* We are testing a vector set.
     * Parameters are found in both the testGroup and the test case.
     */
    cJSON *tgs = NULL;
    SAFEGET(get_object(&tgs, vs, "testGroups"), "Missing 'testGroups' in input JSON\n");
    
    cJSON *tg = NULL;
    cJSON_ArrayForEach(tg, tgs)  {
        /* Get test group ID */
        cJSON *c_tgId = NULL;
        SAFEGET(get_integer_object(&c_tgId, tg, "tgId"), "Missing test group id!\n");
        int tgId = c_tgId->valueint;

        cJSON *tg_output = cJSON_CreateObject ();
        SAFEPUT (put_array_item (tg_output, tgs_output), "Unable to append test group to output\n");
        SAFEPUT (put_integer ("tgId", tgId, tg_output), "Unable to add tgId to test group %d\n", tgId);

        /* Check test type */
        cJSON *test_type = NULL;
        SAFEGET(get_string_object(&test_type, tg, "testType"), "Missing `testType' in input JSON\n");

        cJSON *sigType = NULL;
        SAFEGET(get_string_object(&sigType, tg, "sigType"), "Missing `sigType' in test group %d\n", tgId);
        cJSON *modulo = NULL;
        SAFEGET(get_integer_object(&modulo, tg, "modulo"), "Missing `modulo' in test group %d\n", tgId);
        cJSON *hashAlg = NULL;
        SAFEGET(get_string_object(&hashAlg, tg, "hashAlg"), "Missing `hashAlg' in test group %d\n", tgId);

        /* Get hash alg */
        if(!strcmp("SHA-1", hashAlg->valuestring))
            dgst=EVP_sha1();
        else if(!strcmp("SHA2-224", hashAlg->valuestring))
            dgst=EVP_sha224();
        else if (!strcmp("SHA2-256", hashAlg->valuestring))
            dgst=EVP_sha256();
        else if (!strcmp("SHA2-384", hashAlg->valuestring))
            dgst=EVP_sha384();
        else if (!strcmp("SHA2-512", hashAlg->valuestring))
            dgst=EVP_sha512();
        else {
            printf("Unknown message digest algorithm `%s'\n", hashAlg->valuestring);
            goto error_die;
        }

        cJSON *saltLen = NULL;
        SAFEGET(get_integer_object(&saltLen, tg, "saltLen"), "Missing `saltLen' in test group %d\n", tgId);

        /* Each test group assumes the use of the same public/private RSA key pair */
        if(!strcasecmp(test_type->valuestring, "GDT"))  {
            rsa = FIPS_rsa_new();
            if(!rsa)
                goto error_die;

            /* TODO: Might have to generate a random 'e' value here. 
             * Until told otherwise, just use 0x10001.
             */
            ebn = BN_new();
            if(!ebn)
                goto error_die;
            BN_set_word(ebn, 0x10001);  /* Typical exponent */

            if(!RSA_X931_generate_key_ex(rsa, modulo->valueint, ebn, NULL))
                goto error_die;

            const BIGNUM *_n = NULL;
            _n = rsa->n;
            if(!_n)
                goto error_die;

            if((ls_BN_bn2buf(_n, &n, &n_len) <= 0)
               || (ls_BN_bn2buf(ebn, &e, &e_len) <= 0))
                goto error_die;

            /* Dump out the properties of the keys we are using */
#ifdef TRACE
            printf("N: ");
            print_bytearray(n, n_len);
            printf("E: ");
            print_bytearray(e, e_len);
#endif
            SAFEPUT(put_bytearray("n", n, n_len, tg_output), "Unable to output n for test group %d\n", tgId);
            SAFEPUT(put_bytearray("e", e, e_len, tg_output), "Unable to output e for test group %d\n", tgId);
        }



        cJSON *tests = NULL;
        SAFEGET(get_object(&tests, tg, "tests"), "Missing test cases in test group %d\n", tgId);

        cJSON *tests_output = cJSON_CreateArray ();
        SAFEPUT (put_object ("tests", tests_output, tg_output), "Unable to add tests array to output JSON for test group %d\n", tgId);

        cJSON *tc = NULL;
        cJSON_ArrayForEach(tc, tests)  {
            /* Get test case ID */
            int tcId = 0;
            cJSON *c_tcId = NULL;
            SAFEGET(get_integer_object(&c_tcId, tc, "tcId"), "Missing test case id in test group %d!\n", tgId);
            tcId = c_tcId->valueint;

            cJSON *tc_output = cJSON_CreateObject ();
            SAFEPUT (put_array_item (tc_output, tests_output), "Unable to append test case to test case array for group %d in JSON output\n", tgId);
            SAFEPUT (put_integer ("tcId", tcId, tc_output), "Unable to provide tcId to test case %d in test group %d in JSON output\n", tcId, tgId);

            SAFEGET(get_as_bytearray(&msg, &msg_len, tc, "message"), "Missing message in test case %d in test group %d\n", tcId, tgId);

            if(!strcasecmp(test_type->valuestring, "GDT"))  {
                /* Determine padding mode via salt length, negative values are non PSS mode */
                int padding = -1;
                if(!strcasecmp(sigType->valuestring, "pkcs1v1.5")) padding = -1;
                else if(!strcasecmp(sigType->valuestring, "pss"))       padding = saltLen->valueint;
                else if(!strcasecmp(sigType->valuestring, "ansx9.31"))  padding = -2;
                else {
                    fprintf(stderr, "Unknown padding mode %s\n", sigType->valuestring);
                    goto error_die;
                }

                if(!rsa_printsig(NULL, rsa, dgst, msg, msg_len, padding, &sig, &sig_len))  {
                    fprintf(stderr, "Unable to generate digital signature for test group %d in test case %d.\n", tgId, tcId);
                    goto error_die;
                }

                SAFEPUT(put_bytearray("signature", sig, sig_len, tc_output), "Unable to output signature for test case %d in test group %d\n", tcId, tgId);
            }

            /* Free structures here */
            SAFE_FUNC_FREE(sig, free);
            SAFE_FUNC_FREE(msg, free);
        }   /* End of TC */

        SAFE_FUNC_FREE(n, OPENSSL_free);
        SAFE_FUNC_FREE(e, OPENSSL_free);
        SAFE_FUNC_FREE(ebn, BN_free);
        SAFE_FUNC_FREE(rsa, FIPS_rsa_free);
    }


    fprintf (out, "%s\n", cJSON_Print (output));
    ret = 1;
    goto cleanup;

error_die:
    ret = 0;

cleanup:
    /* Free structures for final time */
    SAFE_FUNC_FREE(rsa, FIPS_rsa_free);
    SAFE_FUNC_FREE(n, OPENSSL_free);
    SAFE_FUNC_FREE(e, OPENSSL_free);
    SAFE_FUNC_FREE(ebn, BN_free);
    SAFE_FUNC_FREE(msg, free);
    SAFE_FUNC_FREE(sig, OPENSSL_free);


    if(json) cJSON_Delete(json);
    json = NULL;

    return ret;
}

int rsa_stest_cavs(FILE *out, FILE *in, int Saltlen)
	{
	char *linebuf, *olinebuf, *p, *q;
	char *keyword, *value;
	RSA *rsa = NULL;
	const EVP_MD *dgst = NULL;
	unsigned char *Msg = NULL;
	long Msglen = -1;
	int keylen = -1, current_keylen = -1;
	int ret = 0;
	int lnum = 0;

	olinebuf = OPENSSL_malloc(RSA_TEST_MAXLINELEN);
	linebuf = OPENSSL_malloc(RSA_TEST_MAXLINELEN);

	if (!linebuf || !olinebuf)
		goto error;

	while (fgets(olinebuf, RSA_TEST_MAXLINELEN, in))
		{
		lnum++;
		strcpy(linebuf, olinebuf);
		keyword = linebuf;
		/* Skip leading space */
		while (isspace((unsigned char)*keyword))
			keyword++;

		/* Look for = sign */
		p = strchr(linebuf, '=');

		/* If no = just copy */
		if (!p)
			{
			if (fputs(olinebuf, out) < 0)
				goto error;
			continue;
			}

		q = p - 1;

		/* Remove trailing space */
		while (isspace((unsigned char)*q))
			*q-- = 0;

		*p = 0;
		value = p + 1;

		/* Remove leading space from value */
		while (isspace((unsigned char)*value))
			value++;

		/* Remove trailing space from value */
		p = value + strlen(value) - 1;

		while (*p == '\n' || isspace((unsigned char)*p))
			*p-- = 0;

		/* Look for [mod = XXX] for key length */

		if (!strcmp(keyword, "[mod"))
			{
			p = value + strlen(value) - 1;
			if (*p != ']')
				goto parse_error;
			*p = 0;
			keylen = atoi(value);
			if (keylen < 0)
				goto parse_error;
			}
		else if (!strcmp(keyword, "SHAAlg"))
			{
			if (!strcmp(value, "SHA1"))
				dgst = EVP_sha1();
			else if (!strcmp(value, "SHA224"))
				dgst = EVP_sha224();
			else if (!strcmp(value, "SHA256"))
				dgst = EVP_sha256();
			else if (!strcmp(value, "SHA384"))
				dgst = EVP_sha384();
			else if (!strcmp(value, "SHA512"))
				dgst = EVP_sha512();
			else
				{
				fprintf(stderr,
					"FATAL: unsupported algorithm \"%s\"\n",
								value);
				goto parse_error;
				}
			}
		else if (!strcmp(keyword, "Msg"))
			{
			if (Msg)
				goto parse_error;
			if (strlen(value) & 1)
				*(--value) = '0';
			Msg = hex2bin_m(value, &Msglen);
			if (!Msg)
				goto parse_error;
			}

		fputs(olinebuf, out);

		/* If key length has changed, generate and output public
		 * key components of new RSA private key.
		 */

		if (keylen != current_keylen)
			{
			BIGNUM *bn_e;
			if (rsa)
				FIPS_rsa_free(rsa);
			rsa = FIPS_rsa_new();
			if (!rsa)
				goto error;
			bn_e = BN_new();
			if (!bn_e || !BN_set_word(bn_e, 0x1001))
				goto error;
			if (!RSA_X931_generate_key_ex(rsa, keylen, bn_e, NULL))
				goto error;
			BN_free(bn_e);
			fputs("n = ", out);
			do_bn_print(out, rsa->n);
			fputs(RESP_EOL "e = ", out);
			do_bn_print(out, rsa->e);
			fputs(RESP_EOL, out);
			current_keylen = keylen;
			}

		if (Msg && dgst)
			{
			if (!rsa_printsig(out, rsa, dgst, Msg, Msglen,
								Saltlen, NULL, NULL))
				goto error;
			OPENSSL_free(Msg);
			Msg = NULL;
			}

		}

	ret = 1;

	error:

	if (olinebuf)
		OPENSSL_free(olinebuf);
	if (linebuf)
		OPENSSL_free(linebuf);
	if (rsa)
		FIPS_rsa_free(rsa);

	return ret;

	parse_error:

	fprintf(stderr, "FATAL parse error processing line %d\n", lnum);

	goto error;

	}

static int rsa_printsig(FILE *out, RSA *rsa, const EVP_MD *dgst,
		unsigned char *Msg, long Msglen, int Saltlen, unsigned char **sig, int *sig_len)
	{
	int ret = 0;
	unsigned char *sigbuf = NULL;
	int i, siglen, pad_mode;
	/* EVP_PKEY structure */

	siglen = RSA_size(rsa);
	sigbuf = OPENSSL_malloc(siglen);
	if (!sigbuf)
		goto error;

	if (Saltlen >= 0)
		pad_mode = RSA_PKCS1_PSS_PADDING;
	else if (Saltlen == -2)
		pad_mode = RSA_X931_PADDING;
	else
		pad_mode = RSA_PKCS1_PADDING;

	if (!FIPS_rsa_sign(rsa, Msg, Msglen, dgst, pad_mode, Saltlen, NULL,
				sigbuf, (unsigned int *)&siglen))
		goto error;

    if(cavs)  {
	    fputs("S = ", out);

	    for (i = 0; i < siglen; i++)
		    fprintf(out, "%02X", sigbuf[i]);

	    fputs(RESP_EOL, out);
    }
    else if(acvp)  {
        if(sig_len) *sig_len = siglen;
        /* Dupe the buffer to avoid having to play more tricks within this function to accomodate CAVS/ACVP. */
        if(sig) {
            *sig = OPENSSL_malloc(siglen);
            memcpy(*sig, sigbuf, siglen);
        }
    }
	ret = 1;

	error:

	if (sigbuf)
		OPENSSL_free(sigbuf);

	return ret;
	}
#endif
