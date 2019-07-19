/* fips_shatest.c */
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
#include <openssl/err.h>
#include <openssl/bn.h>

#include "acvp.h"


#ifndef OPENSSL_FIPS

int main(int argc, char *argv[])
{
    printf("No FIPS SHAXXX support\n");
    return(0);
}

#else

#include <openssl/fips.h>

#include "fips_utl.h"

static int dgst_test_cavs(FILE *out, FILE *in);
static int dgst_test_acvp(FILE *out, FILE *in);
static int print_dgst(const EVP_MD *md, FILE *out,
		unsigned char *Msg, int Msglen);
static int print_monte(const EVP_MD *md, FILE *out,
		unsigned char *Seed, int SeedLen);

#ifdef FIPS_ALGVS
int fips_shatest_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
	{
	FILE *in = NULL, *out = NULL;

	int ret = 1;
	fips_algtest_init();

    int acvp = 0, cavs = 0;
    if(select_mode(&cavs, &acvp) != 0)  {
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

    int res = 0;
    if (cavs)
        res = dgst_test_cavs(out, in);
    else if (acvp)
        res = dgst_test_acvp(out, in);
    else
        printf("Unknown operational mode (CAVS or ACVP required).");

    if (!res)
		{
		fprintf(stderr, "FATAL digest file processing error\n");
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

#define SHA_TEST_MAX_BITS	102400
#define SHA_TEST_MAXLINELEN	(((SHA_TEST_MAX_BITS >> 3) * 2) + 100)

int dgst_test_acvp(FILE *out, FILE *in)  {
	const EVP_MD *md = NULL;
	unsigned char *Msg = NULL;
	long MsgLen = -1, Len = -1;
	int ret = 0;
    cJSON *json = NULL;

    if ((json = read_fd_as_json(in)) == NULL)  {
        printf("Cannot parse JSON file\n");
        goto error_die;
    }

    /* Check version is correct */
    if (!verify_acvp_version(json, "1.0"))  {
        printf("ACVP version number is not expected.");
        goto error_die;
    }


    /* Vector set */
    const cJSON *vs = NULL;
    SAFEGET(get_array_item(&vs, json, 1), "Vector set missing in JSON\n");

    /* Need the algorithm function, the msg and the length */
    const cJSON *algStr = NULL;
    SAFEGET(get_string_object(&algStr, vs, "algorithm"), "Algorithm identifier missing in JSON\n");

    if(!strncmp("SHA-1", algStr->valuestring, 8))   /* UNTESTED! */
        md=EVP_sha1();
    else if(!strncmp("SHA2-224", algStr->valuestring, 8))
        md=EVP_sha224();
    else if (!strncmp("SHA2-256", algStr->valuestring, 8))
        md=EVP_sha256();
    else if (!strncmp("SHA2-384", algStr->valuestring, 8))
        md=EVP_sha384();
    else if (!strncmp("SHA2-512", algStr->valuestring, 8))
        md=EVP_sha512();
    else {
        printf("Unknown message digest algorithm `%s'\n", algStr->valuestring);
        goto error_die;
    }


    /* For each test group
     *      For each test case
     *          Process...
     */
    const cJSON *tgs = NULL;
    SAFEGET(get_object(&tgs, vs, "testGroups"), "Missing 'testGroups' in input JSON\n");
    const cJSON *tg = NULL;
    cJSON_ArrayForEach(tg, tgs)  {
        if(!tg)  {
            printf("Test groups array is missing test group object.\n");
            goto error_die;
        }

        /* Get test group ID */
        const cJSON *tgId = NULL;
        SAFEGET(get_integer_object(&tgId, tg, "tgId"), "Missing test group id!\n");
        /* Get test type */
        const cJSON *test_type = NULL;
        SAFEGET(get_string_object(&test_type, tg, "testType"), "Missing `testType' in input JSON\n");

        /* Now iterate over the test cases */
        const cJSON *tests = NULL;
        SAFEGET(get_object(&tests, tg, "tests"), "Missing test cases in test group %d\n", tgId->valueint);

        const cJSON *tc = NULL;
        cJSON_ArrayForEach(tc, tests)  {
            if(!tc)  {
                printf("Test groups array is missing test cases.");
                goto error_die;
            }

            /* Get test case ID */
            const cJSON *tcId = NULL;
            SAFEGET(get_integer_object(&tcId, tc, "tcId"), "Missing test case id in test group %d!\n", tgId->valueint);

            const cJSON *msgStr = NULL;
            SAFEGET(get_string_object(&msgStr, tc, "msg"), "Missing message in test case %d in test group %d\n", tcId->valueint, tgId->valueint);
            const cJSON *msgLen = NULL;
            SAFEGET(get_integer_object(&msgLen, tc, "len"), "Missing message length in test %d in test group %d\n", tcId->valueint, tgId->valueint);

            Len = msgLen->valueint;
            if (Len < 0)
                goto error_die;
            /* Only handle multiples of 8 bits */
            if (Len & 0x7)
                goto error_die;
            if (Len > SHA_TEST_MAX_BITS)
                goto error_die;
            MsgLen = Len >> 3;

            long tmplen = 0;
            Msg = hex2bin_m(msgStr->valuestring, &tmplen);

            if(!strncmp("AFT", test_type->valuestring, 3))  {
    			if (!print_dgst(md, out, Msg, MsgLen))
	    			goto error_die;
            }
            else if (!strncmp("MCT", test_type->valuestring, 3))  {
			    if (!print_monte(md, out, Msg, MsgLen))
				    goto error_die;
            }
			OPENSSL_free(Msg);
			Msg = NULL;
			MsgLen = -1;
			Len = -1;
        }
    }

    ret = 1;
    goto cleanup;


error_die:
    ret = 0;

cleanup:
    if(json) cJSON_Delete(json); json = NULL;
	if (Msg) OPENSSL_free(Msg); Msg = NULL;

    return ret;
}

int dgst_test_cavs(FILE *out, FILE *in)
	{
	const EVP_MD *md = NULL;
	char *linebuf, *olinebuf, *p, *q;
	char *keyword, *value;
	unsigned char *Msg = NULL, *Seed = NULL;
	long MsgLen = -1, Len = -1, SeedLen = -1;
	int ret = 0;
	int lnum = 0;

	olinebuf = OPENSSL_malloc(SHA_TEST_MAXLINELEN);
	linebuf = OPENSSL_malloc(SHA_TEST_MAXLINELEN);

	if (!linebuf || !olinebuf)
		goto error;


	while (fgets(olinebuf, SHA_TEST_MAXLINELEN, in))
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
			fputs(olinebuf, out);
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
		else if (!strcmp(keyword, "Len"))
			{
			if (Len != -1)
				goto parse_error;
			Len = atoi(value);
			if (Len < 0)
				goto parse_error;
			/* Only handle multiples of 8 bits */
			if (Len & 0x7)
				goto parse_error;
			if (Len > SHA_TEST_MAX_BITS)
				goto parse_error;
			MsgLen = Len >> 3;
			}

		else if (!strcmp(keyword, "Msg"))
			{
			long tmplen;
			if (strlen(value) & 1)
				*(--value) = '0';
			if (Msg)
				goto parse_error;
			Msg = hex2bin_m(value, &tmplen);
			if (!Msg)
				goto parse_error;
			}
		else if (!strcmp(keyword, "Seed"))
			{
			if (strlen(value) & 1)
				*(--value) = '0';
			if (Seed)
				goto parse_error;
			Seed = hex2bin_m(value, &SeedLen);
			if (!Seed)
				goto parse_error;
			}
		else if (!strcmp(keyword, "MD"))
			continue;
		else
			goto parse_error;

		fputs(olinebuf, out);

		if (md && Msg && (MsgLen >= 0))
			{
			if (!print_dgst(md, out, Msg, MsgLen))
				goto error;
			OPENSSL_free(Msg);
			Msg = NULL;
			MsgLen = -1;
			Len = -1;
			}
		else if (md && Seed && (SeedLen > 0))
			{
			if (!print_monte(md, out, Seed, SeedLen))
				goto error;
			OPENSSL_free(Seed);
			Seed = NULL;
			SeedLen = -1;
			}
	

		}


	ret = 1;


	error:

	if (olinebuf)
		OPENSSL_free(olinebuf);
	if (linebuf)
		OPENSSL_free(linebuf);
	if (Msg)
		OPENSSL_free(Msg);
	if (Seed)
		OPENSSL_free(Seed);

	return ret;

	parse_error:

	fprintf(stderr, "FATAL parse error processing line %d\n", lnum);

	goto error;

	}

static int print_dgst(const EVP_MD *emd, FILE *out,
		unsigned char *Msg, int Msglen)
	{
	int i, mdlen;
	unsigned char md[EVP_MAX_MD_SIZE];
	if (!FIPS_digest(Msg, Msglen, md, (unsigned int *)&mdlen, emd))
		{
		fputs("Error calculating HASH\n", stderr);
		return 0;
		}
	fputs("MD = ", out);
	for (i = 0; i < mdlen; i++)
		fprintf(out, "%02x", md[i]);
	fputs(RESP_EOL, out);
	return 1;
	}

static int print_monte(const EVP_MD *md, FILE *out,
		unsigned char *Seed, int SeedLen)
	{
	unsigned int i, j, k;
	int ret = 0;
	EVP_MD_CTX ctx;
	unsigned char *m1, *m2, *m3, *p;
	unsigned int mlen, m1len, m2len, m3len;

	FIPS_md_ctx_init(&ctx);

	if (SeedLen > EVP_MAX_MD_SIZE)
		mlen = SeedLen;
	else
		mlen = EVP_MAX_MD_SIZE;

	m1 = OPENSSL_malloc(mlen);
	m2 = OPENSSL_malloc(mlen);
	m3 = OPENSSL_malloc(mlen);

	if (!m1 || !m2 || !m3)
		goto mc_error;

	m1len = m2len = m3len = SeedLen;
	memcpy(m1, Seed, SeedLen);
	memcpy(m2, Seed, SeedLen);
	memcpy(m3, Seed, SeedLen);

	fputs(RESP_EOL, out);

	for (j = 0; j < 100; j++)
		{
		for (i = 0; i < 1000; i++)
			{
			FIPS_digestinit(&ctx, md);
			FIPS_digestupdate(&ctx, m1, m1len);
			FIPS_digestupdate(&ctx, m2, m2len);
			FIPS_digestupdate(&ctx, m3, m3len);
			p = m1;
			m1 = m2;
			m1len = m2len;
			m2 = m3;
			m2len = m3len;
			m3 = p;
			FIPS_digestfinal(&ctx, m3, &m3len);
			}
		fprintf(out, "COUNT = %d" RESP_EOL, j);
		fputs("MD = ", out);
		for (k = 0; k < m3len; k++)
			fprintf(out, "%02x", m3[k]);
		fputs(RESP_EOL RESP_EOL, out);
		memcpy(m1, m3, m3len);
		memcpy(m2, m3, m3len);
		m1len = m2len = m3len;
		}

	ret = 1;

	mc_error:
	if (m1)
		OPENSSL_free(m1);
	if (m2)
		OPENSSL_free(m2);
	if (m3)
		OPENSSL_free(m3);

	FIPS_md_ctx_cleanup(&ctx);

	return ret;
	}

#endif
