/* fips_rsavtest.c */
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

int rsa_vtest_cavs(FILE *out, FILE *in, int saltlen);
int rsa_vtest_acvp(FILE *out, FILE *in, int saltlen);
static int rsa_printver(FILE *out,
		BIGNUM *n, BIGNUM *e,
		const EVP_MD *dgst,
		unsigned char *Msg, long Msglen,
		unsigned char *S, long Slen, int Saltlen, int *_passed);

#ifdef FIPS_ALGVS
int fips_rsavtest_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
	{
	FILE *in = NULL, *out = NULL;

	int ret = 1;
	int Saltlen = -1;

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
        res = rsa_vtest_cavs(out, in, Saltlen);
    else if (acvp)
        res = rsa_vtest_acvp(out, in, Saltlen);
    else
        printf("Unknown operational mode (CAVS or ACVP required).");

	if (!res)
		{
		fprintf(stderr, "FATAL RSAVTEST file processing error\n");
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

int rsa_vtest_acvp(FILE *out, FILE *in, int Saltlen)  {
    const EVP_MD *dgst = NULL;
    BIGNUM *bn_n = NULL, *bn_e = NULL;

    unsigned char *sig = NULL;
    int sig_len = 0;
    unsigned char *n = NULL, *e = NULL;
    int n_len = 0, e_len = 0;
    unsigned char *msg = NULL;
    int msg_len = 0;

    int ret = 0;
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

    /* For each test group
     *      For each test case
     *          Process...
     */
    cJSON *tg = NULL;
    cJSON_ArrayForEach(tg, tgs)  {
        char saltLen_str[64] = {0};
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
        cJSON *saltLen = NULL;
        SAFEGET(get_integer_object(&saltLen, tg, "saltLen"), "Missing `saltLen' in test group %d\n", tgId);
        /* OpenSSL expects the salt length as a string */
        snprintf(saltLen_str, sizeof(saltLen_str), "%u", saltLen->valueint);

        cJSON *_n = NULL, *_e = NULL;
        SAFEGET(get_string_object(&_n, tg, "n"), "Missing `n' in test group %d\n", tgId);
        SAFEGET(get_string_object(&_e, tg, "e"), "Missing `e' in test group %d\n", tgId);

        /* Each test group assumes the use of the same public RSA key */
        if(!strcasecmp(test_type->valuestring, "GDT"))  {
            /* Create an RSA public key with the right properties */
            /* Because sending directly as BIGNUM, we have to alter the endian-ness and reverse the array */
            //reverse_bytearray(n, n_len);
            //reverse_bytearray(e, e_len);

            if (!do_hex2bn(&bn_n,_n->valuestring))  {
                fprintf(stderr, "Parse error (n).\n");
                goto error_die;
            }
            if (!do_hex2bn(&bn_e,_e->valuestring))  {
                fprintf(stderr, "Parse error (e).\n");
                goto error_die;
            }
        }

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
            SAFEGET(get_as_bytearray(&sig, &sig_len, tc, "signature"), "Missing signature in test case %d in test group %d\n", tcId, tgId);

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

#ifdef TRACE
                printf("Message: ");
                print_bytearray(msg, msg_len);
                printf("Signature: ");
                print_bytearray(sig, sig_len);
#endif
                /* Build a buffer for the return signature data */
                int passed = 1;

                if(!rsa_printver(NULL, bn_n, bn_e, dgst, msg, msg_len, sig, sig_len, padding, &passed)) {
                    fprintf(stderr, "Error validating digital signature in test case %d for test group %d.\n", tcId, tgId);
                    goto error_die;
                }

#ifdef TRACE
                printf("testPassed: %s\n", passed ? "true" : "false");
#endif
                SAFEPUT(put_boolean("testPassed", (cJSON_bool)passed, tc_output), "Unable to add testPassed to test case %d in test group %d in JSON output\n", tcId, tgId);
            }

            /* Free structures here */
            SAFE_FUNC_FREE(sig, free);
            SAFE_FUNC_FREE(msg, free);
        }   /* End of TC */
    
        SAFE_FUNC_FREE(n, OPENSSL_free);
        SAFE_FUNC_FREE(e, OPENSSL_free);
    }

    fprintf (out, "%s\n", cJSON_Print (output));
    ret = 1;
    goto cleanup;

error_die:
    ret = 0;

cleanup:
    /* Free structures for final time */
    SAFE_FUNC_FREE(n, OPENSSL_free);
    SAFE_FUNC_FREE(e, OPENSSL_free);
    SAFE_FUNC_FREE(msg, free);
    SAFE_FUNC_FREE(sig, free);

    if(json) cJSON_Delete(json);
    json = NULL;

    return ret;
}

int rsa_vtest_cavs(FILE *out, FILE *in, int Saltlen)
	{
	char *linebuf, *olinebuf, *p, *q;
	char *keyword, *value;
	const EVP_MD *dgst = NULL;
	BIGNUM *n = NULL, *e = NULL;
	unsigned char *Msg = NULL, *S = NULL;
	long Msglen, Slen;
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

		/* If no = or starts with [ (for [foo = bar] line) just copy */
		if (!p || *keyword=='[')
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

		if (!strcmp(keyword, "n"))
			{
			if (!do_hex2bn(&n,value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "e"))
			{
			if (!do_hex2bn(&e,value))
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
		else if (!strcmp(keyword, "S"))
			{
			if (S)
				goto parse_error;
			if (strlen(value) & 1)
				*(--value) = '0';
			S = hex2bin_m(value, &Slen);
			if (!S)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Result"))
			continue;
		else
			goto parse_error;

		fputs(olinebuf, out);

		if (n && e && Msg && S && dgst)
			{
			if (!rsa_printver(out, n, e, dgst,
					Msg, Msglen, S, Slen, Saltlen, NULL))
				goto error;
			OPENSSL_free(Msg);
			Msg = NULL;
			OPENSSL_free(S);
			S = NULL;
			}

		}


	ret = 1;


	error:

	if (olinebuf)
		OPENSSL_free(olinebuf);
	if (linebuf)
		OPENSSL_free(linebuf);
	if (n)
		BN_free(n);
	if (e)
		BN_free(e);

	return ret;

	parse_error:

	fprintf(stderr, "FATAL parse error processing line %d\n", lnum);

	goto error;

	}

static int rsa_printver(FILE *out,
		BIGNUM *n, BIGNUM *e,
		const EVP_MD *dgst,
		unsigned char *Msg, long Msglen,
		unsigned char *S, long Slen, int Saltlen, int *_passed)
	{
	int ret = 0, r, pad_mode;
	/* Setup RSA and EVP_PKEY structures */
	RSA *rsa_pubkey = NULL;
	unsigned char *buf = NULL;
	rsa_pubkey = FIPS_rsa_new();
	if (!rsa_pubkey)
		goto error;
	rsa_pubkey->n = BN_dup(n);
	rsa_pubkey->e = BN_dup(e);
	if (!rsa_pubkey->n || !rsa_pubkey->e)
		goto error;

	if (Saltlen >= 0)
		pad_mode = RSA_PKCS1_PSS_PADDING;
	else if (Saltlen == -2)
		pad_mode = RSA_X931_PADDING;
	else
		pad_mode = RSA_PKCS1_PADDING;

	no_err = 1;
	r = FIPS_rsa_verify(rsa_pubkey, Msg, Msglen, dgst,
				pad_mode, Saltlen, NULL, S, Slen);
	no_err = 0;

	if (r < 0)
		goto error;

    if (cavs)  {
    	if (r == 0)
	    	fputs("Result = F" RESP_EOL, out);
    	else
	    	fputs("Result = P" RESP_EOL, out);
    }
    else if (acvp && _passed)
        *_passed = r;

	ret = 1;

	error:
	if (rsa_pubkey)
		FIPS_rsa_free(rsa_pubkey);
	if (buf)
		OPENSSL_free(buf);

	return ret;
	}
#endif
