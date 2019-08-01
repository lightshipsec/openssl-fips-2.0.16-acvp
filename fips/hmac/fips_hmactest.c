/* fips_hmactest.c */
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
    printf("No FIPS HMAC support\n");
    return(0);
}

#else

#include <openssl/fips.h>
#include "fips_utl.h"

static int hmac_test_acvp(const EVP_MD *md, FILE *out, FILE *in);
static int hmac_test_cavs(const EVP_MD *md, FILE *out, FILE *in);
static int print_hmac(const EVP_MD *md, FILE *out, cJSON *node,
		unsigned char *Key, int Klen,
		unsigned char *Msg, int Msglen, int Tlen);

#ifdef FIPS_ALGVS
int fips_hmactest_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
	{
	FILE *in = NULL, *out = NULL;

	int ret = 1, res = 0;
	fips_algtest_init();

    if(select_mode() != 0)  {
        printf("Unable to determine if CAVS or ACVP mode selected.\n");
        return -1;
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

    if (cavs)
        res = hmac_test_cavs(EVP_sha1(), out, in);
    else if (acvp)
        res = hmac_test_acvp(EVP_sha1(), out, in);
    else
        printf("Unknown operational mode (CAVS or ACVP required).");

    if (!res)  {
		fprintf(stderr, "FATAL hmac file processing error\n");
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

#define HMAC_TEST_MAXLINELEN	1024

int hmac_test_acvp(const EVP_MD *md, FILE *out, FILE *in)  {
	unsigned char *Key = NULL, *Msg = NULL;
	int Klen, Tlen;
	long Keylen, Msglen;
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

    /* Need the algorithm function, the msg and the length */
    cJSON *algStr = NULL;
    SAFEGET(get_string_object(&algStr, vs, "algorithm"), "Algorithm identifier missing in JSON\n");

    /* Copy algorithm and revision to output */
    /* TODO: Actually not clear if the algorithm and revision are needed since the server can marry those up based on vector set id.
     * The spec says they are needed, but, for example, AES does not need it. 
     */ 
    SAFEPUT (put_string("algorithm", (const unsigned char *)algStr->valuestring, response), "Unable to add algorithm specifier to response body\n");
    /* Get algorithm revision and copy to output */
    cJSON *alg_rev = NULL;
    SAFEGET(get_string_object(&alg_rev, vs, "revision"), "Revision identifier missing in JSON\n");
    SAFEPUT (put_string("revision", (const unsigned char *)alg_rev->valuestring, response), "Unable to add algorithm revision to response body\n");

    if(!strcmp("HMAC-SHA-1", algStr->valuestring))
        md=EVP_sha1();
    else if(!strcmp("HMAC-SHA2-224", algStr->valuestring))
        md=EVP_sha224();
    else if (!strcmp("HMAC-SHA2-256", algStr->valuestring))
        md=EVP_sha256();
    else if (!strcmp("HMAC-SHA2-384", algStr->valuestring))
        md=EVP_sha384();
    else if (!strcmp("HMAC-SHA2-512", algStr->valuestring))
        md=EVP_sha512();
    /* TODO: Truncated versions? Maybe already handled by macLen parameter in JSON */
    else {
        printf("Unknown message digest algorithm `%s'\n", algStr->valuestring);
        goto error_die;
    }


    /* For each test group
     *      For each test case
     *          Process...
     */
    cJSON *tgs = NULL;
    SAFEGET(get_object(&tgs, vs, "testGroups"), "Missing 'testGroups' in input JSON\n");
    cJSON *tg = NULL;
    cJSON_ArrayForEach(tg, tgs)  {
        cJSON *tg_output = cJSON_CreateObject ();
        /* Add to output */
        SAFEPUT (put_array_item (tg_output, tgs_output), "Unable to append test group to output\n");

        if(!tg)  {
            printf("Test groups array is missing test group object.\n");
            goto error_die;
        }

        /* Get test group ID */
        cJSON *tgId = NULL;
        SAFEGET(get_integer_object(&tgId, tg, "tgId"), "Missing test group id!\n");
        /* Copy tgId to output */
        SAFEPUT (put_integer ("tgId", tgId->valueint, tg_output), "Unable to add tgId to test group %d\n", tgId->valueint);
        /* Get test type */
        cJSON *test_type = NULL;
        SAFEGET(get_string_object(&test_type, tg, "testType"), "Missing `testType' in input JSON\n");

        /* Key length, message length, mac length */
        cJSON *keyLen = NULL;
        SAFEGET(get_integer_object(&keyLen, tg, "keyLen"), "Missing `keyLen' in input JSON\n");

        cJSON *msgLen = NULL;
        SAFEGET(get_integer_object(&msgLen, tg, "msgLen"), "Missing `msgLen' in input JSON\n");

        cJSON *macLen = NULL;
        SAFEGET(get_integer_object(&macLen, tg, "macLen"), "Missing `macLen' in input JSON\n");

        /* Now iterate over the test cases */
        cJSON *tests = NULL;
        SAFEGET(get_object(&tests, tg, "tests"), "Missing test cases in test group %d\n", tgId->valueint);

        /* Create test cases array */
        cJSON *tests_output = cJSON_CreateArray ();
        SAFEPUT (put_object ("tests", tests_output, tg_output), "Unable to add tests array to output JSON for test group %d\n", tgId->valueint);

        cJSON *tc = NULL;
        cJSON_ArrayForEach(tc, tests)  {
            cJSON *tc_output = cJSON_CreateObject ();
            /* Add to output */
            SAFEPUT (put_array_item (tc_output, tests_output), "Unable to append test case to test case array for group %d in JSON output\n", tgId->valueint);

            if(!tc)  {
                printf("Test groups array is missing test cases.");
                goto error_die;
            }

            /* Get test case ID */
            cJSON *tcId = NULL;
            SAFEGET(get_integer_object(&tcId, tc, "tcId"), "Missing test case id in test group %d!\n", tgId->valueint);

            /* Copy back to output */
            SAFEPUT (put_integer ("tcId", tcId->valueint, tc_output), "Unable to provide tcId to test case %d in test group %d in JSON output\n", tcId->valueint, tgId->valueint);

            cJSON *msgStr = NULL;
            SAFEGET(get_string_object(&msgStr, tc, "msg"), "Missing message in test case %d in test group %d\n", tcId->valueint, tgId->valueint);
            cJSON *keyStr = NULL;
            SAFEGET(get_string_object(&keyStr, tc, "key"), "Missing key in test %d in test group %d\n", tcId->valueint, tgId->valueint);

            Msg = hex2bin_m(msgStr->valuestring, &Msglen);
            Key = hex2bin_m(keyStr->valuestring, &Keylen);

            Tlen = macLen->valueint/8;
            Klen = keyLen->valueint/8;
            Msglen = msgLen->valueint;

		    if (Key && Msg && (Tlen > 0) && (Klen > 0))  {
			    if (!print_hmac(md, NULL, tc_output, Key, Klen, Msg, Msglen, Tlen))
				    goto error_die;
    			OPENSSL_free(Key);
	    		Key = NULL;
		    	OPENSSL_free(Msg);
			    Msg = NULL;
			    Klen = -1;
			    Tlen = -1;
			}
        }
    }

    printf ("%s\n", cJSON_Print (output));

    ret = 1;
    goto cleanup;


error_die:
    ret = 0;

cleanup:
    if(json) 
        cJSON_Delete(json); 
    json = NULL;
    if(output)
        cJSON_Delete(output);
    output = NULL;

    return ret;
}

int hmac_test_cavs(const EVP_MD *md, FILE *out, FILE *in)
	{
	char *linebuf, *olinebuf, *p, *q;
	char *keyword, *value;
	unsigned char *Key = NULL, *Msg = NULL;
	int Count, Klen, Tlen;
	long Keylen, Msglen;
	int ret = 0;
	int lnum = 0;

	olinebuf = OPENSSL_malloc(HMAC_TEST_MAXLINELEN);
	linebuf = OPENSSL_malloc(HMAC_TEST_MAXLINELEN);

	if (!linebuf || !olinebuf)
		goto error;

	Count = -1;
	Klen = -1;
	Tlen = -1;

	while (fgets(olinebuf, HMAC_TEST_MAXLINELEN, in))
		{
		lnum++;
		strcpy(linebuf, olinebuf);
		keyword = linebuf;
		/* Skip leading space */
		while (isspace((unsigned char)*keyword))
			keyword++;

		/* Look for = sign */
		p = strchr(linebuf, '=');

		/* If no = or starts with [ (for [L=20] line) just copy */
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

		if (!strcmp(keyword,"[L") && *p==']')
			{
			switch (atoi(value))
				{
				case 20: md=EVP_sha1();   break;
				case 28: md=EVP_sha224(); break;
				case 32: md=EVP_sha256(); break;
				case 48: md=EVP_sha384(); break;
				case 64: md=EVP_sha512(); break;
				default: goto parse_error;
				}
			}
		else if (!strcmp(keyword, "Count"))
			{
			if (Count != -1)
				goto parse_error;
			Count = atoi(value);
			if (Count < 0)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Klen"))
			{
			if (Klen != -1)
				goto parse_error;
			Klen = atoi(value);
			if (Klen < 0)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Tlen"))
			{
			if (Tlen != -1)
				goto parse_error;
			Tlen = atoi(value);
			if (Tlen < 0)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Msg"))
			{
			if (Msg)
				goto parse_error;
			Msg = hex2bin_m(value, &Msglen);
			if (!Msg)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Key"))
			{
			if (Key)
				goto parse_error;
			Key = hex2bin_m(value, &Keylen);
			if (!Key)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Mac"))
			continue;
		else
			goto parse_error;

		fputs(olinebuf, out);

		if (Key && Msg && (Tlen > 0) && (Klen > 0))
			{
			if (!print_hmac(md, out, NULL, Key, Klen, Msg, Msglen, Tlen))
				goto error;
			OPENSSL_free(Key);
			Key = NULL;
			OPENSSL_free(Msg);
			Msg = NULL;
			Klen = -1;
			Tlen = -1;
			Count = -1;
			}

		}


	ret = 1;


	error:

	if (olinebuf)
		OPENSSL_free(olinebuf);
	if (linebuf)
		OPENSSL_free(linebuf);
	if (Key)
		OPENSSL_free(Key);
	if (Msg)
		OPENSSL_free(Msg);

	return ret;

	parse_error:

	fprintf(stderr, "FATAL parse error processing line %d\n", lnum);

	goto error;

	}

static int print_hmac(const EVP_MD *emd, FILE *out, cJSON *node,
		unsigned char *Key, int Klen,
		unsigned char *Msg, int Msglen, int Tlen)
	{
	int i, mdlen;
	unsigned char md[EVP_MAX_MD_SIZE];
    if((cavs && !out) || (acvp && !node))  {
        fprintf(stderr, "Unable to construct output stream for %s format output\n", cavs ? "CAVS" : acvp ? "ACVP" : "UNKNOWN");
        return 0;
    }

	if (!HMAC(emd, Key, Klen, Msg, Msglen, md,
						(unsigned int *)&mdlen))
		{
		fputs("Error calculating HMAC\n", stderr);
		return 0;
		}
	if (Tlen > mdlen)
		{
		fputs("Parameter error, Tlen > HMAC length\n", stderr);
		return 0;
		}
    if (cavs)  {
    	fputs("Mac = ", out);
	    for (i = 0; i < Tlen; i++)
		    fprintf(out, "%02x", md[i]);
    	fputs(RESP_EOL, out);
    }
    if(acvp)  {
        unsigned char result_hex[EVP_MAX_MD_SIZE*2+1];
        SAFEPUT(put_string("mac", bin2hex(md, Tlen, result_hex, sizeof(result_hex)), node), "Unable to allocate MAC output for JSON\n");
    }
    return 1;

error_die:
	return 0;
	}

#endif
