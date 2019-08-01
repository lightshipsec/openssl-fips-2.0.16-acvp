/* fips/rand/fips_drbgvs.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
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
 */


#define OPENSSL_FIPSAPI
#include <openssl/opensslconf.h>

#ifndef OPENSSL_FIPS
#include <stdio.h>

int main(int argc, char **argv)
{
    printf("No FIPS DRBG support\n");
    return(0);
}
#else

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/fips.h>
#include <openssl/fips_rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>

#include "fips_utl.h"

#include <assert.h>
#include "acvp.h"


static int dparse_md(char *str)
	{
	switch(atoi(str + 5))
		{
		case 1:
		return NID_sha1;

		case 224:
		return NID_sha224;

		case 256:
		return NID_sha256;

		case 384:
		return NID_sha384;

		case 512:
		return NID_sha512;

		}

	return NID_undef;
	}

static int parse_ec(char *str)
	{
	int curve_nid, md_nid;
	char *md;
	md = strchr(str, ' ');
	if (!md)
		return NID_undef;
	if (!strncmp(str, "[P-256", 6))
		curve_nid = NID_X9_62_prime256v1;
	else if (!strncmp(str, "[P-384", 6))
		curve_nid = NID_secp384r1;
	else if (!strncmp(str, "[P-521", 6))
		curve_nid = NID_secp521r1;
	else
		return NID_undef;
	md_nid = dparse_md(md);
	if (md_nid == NID_undef)
		return NID_undef;
	return (curve_nid << 16) | md_nid;
	}

static int parse_aes(char *str, int *pdf)
	{

	if (!strncmp(str + 9, "no", 2))
		*pdf = 0;
	else
		*pdf = DRBG_FLAG_CTR_USE_DF;

	switch(atoi(str + 5))
		{
		case 128:
		return NID_aes_128_ctr;

		case 192:
		return NID_aes_192_ctr;

		case 256:
		return NID_aes_256_ctr;

		default:
		return NID_undef;

		}
	}

typedef struct 
	{
	unsigned char *ent;
	size_t entlen;
	unsigned char *nonce;
	size_t noncelen;
	} TEST_ENT;

static size_t test_entropy(DRBG_CTX *dctx, unsigned char **pout,
                                int entropy, size_t min_len, size_t max_len)
	{
	TEST_ENT *t = FIPS_drbg_get_app_data(dctx);
	*pout = (unsigned char *)t->ent;
	return t->entlen;
	}

static size_t test_nonce(DRBG_CTX *dctx, unsigned char **pout,
                                int entropy, size_t min_len, size_t max_len)
	{
	TEST_ENT *t = FIPS_drbg_get_app_data(dctx);
	*pout = (unsigned char *)t->nonce;
	return t->noncelen;
	}

#ifdef FIPS_ALGVS
int fips_drbgvs_main(int argc,char **argv)
#else
int main(int argc,char **argv)
#endif
	{
	FILE *in = NULL, *out = NULL;
	DRBG_CTX *dctx = NULL;
	TEST_ENT t;
	int r, nid = 0;
	int pr = 0;
	char buf[2048], lbuf[2048];
	unsigned char randout[2048];
	char *keyword = NULL, *value = NULL;

	unsigned char *ent = NULL, *nonce = NULL, *pers = NULL, *adin = NULL;
	long entlen, noncelen, perslen, adinlen;
	int df = 0;

	enum dtype { DRBG_NONE, DRBG_CTR, DRBG_HASH, DRBG_HMAC, DRBG_DUAL_EC }
		drbg_type = DRBG_NONE;

	int randoutlen = 0;

	int gen = 0;

    int ret = 0;
    cJSON *json = NULL;
    cJSON *output = NULL;

	fips_algtest_init();

    if(select_mode() != 0)  {
        printf("Unable to determine if CAVS or ACVP mode selected.\n");
        return -1;
    }
	if (argc == 3)
		{
		in = fopen(argv[1], "r");
		if (!in)
			{
			fprintf(stderr, "Error opening input file\n");
			exit(1);
			}
		out = fopen(argv[2], "w");
		if (!out)
			{
			fprintf(stderr, "Error opening output file\n");
			exit(1);
			}
		}
	else if (argc == 1)
		{
		in = stdin;
		out = stdout;
		}
	else
		{
		fprintf(stderr,"%s (infile outfile)\n",argv[0]);
		exit(1);
		}


    if(acvp)  {
        if ((json = read_file_as_json(argv[1])) == NULL)  {
            fprintf(stderr, "Cannot open file: %s, %s\n", argc > 1 ? argv[1] : "(stdin)", strerror(errno));
            goto error_die;
        }
        /* Data is parsed already; now we need to extract everything to give to the caller. */
        /* Validate that the structure is sound and conforms with the expected structure format. */
        if (cJSON_GetArraySize(json) != 2)  {
            fprintf(stderr, "Expecting array of size 2 in top-level JSON. Check input format.\n");
            goto error_die;
        }

        /* Check version is correct */
        assert(verify_acvp_version(json, "1.0"));

        /* Initialize output structure */
        output = init_output (json);

        /* Now get the pertinent details */
        cJSON *vs = NULL;
        SAFEGET(get_array_item(&vs, json, 1), "Vector set missing in JSON\n");
        cJSON *algStr = NULL;
        SAFEGET(get_string_object(&algStr, vs, "algorithm"), "Algorithm identifier missing in JSON\n");
        cJSON *algModeStr = NULL;
        SAFEGET(get_string_object(&algModeStr, vs, "mode"), "Algorithm mode identifier missing in JSON\n");

        /* Get the DRBG handle */
        nid = NID_undef;
        if (!strcmp(algStr->valuestring, "ctrDRBG"))  {
            drbg_type = DRBG_CTR;
            if (!strcmp(algModeStr->valuestring, "AES-128"))
                nid = NID_aes_128_ctr;
            else if (!strcmp(algModeStr->valuestring, "AES-192"))
                nid = NID_aes_192_ctr;
            else if (!strcmp(algModeStr->valuestring, "AES-256"))
                nid = NID_aes_256_ctr;
        } else if (!strcmp(algStr->valuestring, "hashDRBG"))  {
            drbg_type = DRBG_HASH;
            if (!strcmp(algModeStr->valuestring, "SHA-1"))
                nid = NID_sha1;
            else if (!strcmp(algModeStr->valuestring, "SHA2-224"))
                nid = NID_sha224;
            else if (!strcmp(algModeStr->valuestring, "SHA2-256"))
                nid = NID_sha256;
            else if (!strcmp(algModeStr->valuestring, "SHA2-384"))
                nid = NID_sha256;
            else if (!strcmp(algModeStr->valuestring, "SHA2-512"))
                nid = NID_sha512;
            else if (!strcmp(algModeStr->valuestring, "SHA2-512/224"))
                nid = NID_undef;
            else if (!strcmp(algModeStr->valuestring, "SHA2-512/256"))
                nid = NID_undef;
        } else if (!strcmp(algStr->valuestring, "hmacDRBG"))  {
            drbg_type = DRBG_HMAC;
            if (!strcmp(algModeStr->valuestring, "SHA-1"))
                nid = NID_hmacWithSHA1;
            else if (!strcmp(algModeStr->valuestring, "SHA2-224"))
                nid = NID_hmacWithSHA224;
            else if (!strcmp(algModeStr->valuestring, "SHA2-256"))
                nid = NID_hmacWithSHA256;
            else if (!strcmp(algModeStr->valuestring, "SHA2-384"))
                nid = NID_hmacWithSHA384;
            else if (!strcmp(algModeStr->valuestring, "SHA2-512"))
                nid = NID_hmacWithSHA512;
            else if (!strcmp(algModeStr->valuestring, "SHA2-512/224"))
                nid = NID_undef;
            else if (!strcmp(algModeStr->valuestring, "SHA2-512/256"))
                nid = NID_undef;
        }

        if (nid == NID_undef || drbg_type == DRBG_NONE)  {
            fprintf(stderr, "DRBG type %s (mode %s) not recognised!\n", algStr->valuestring, algModeStr->valuestring);
            goto error_die;
        }


        /* For each test group
         *      For each test case
         *          Process...
         */
        cJSON *tgs = NULL;
        SAFEGET(get_object(&tgs, vs, "testGroups"), "Missing 'testGroups' in input JSON\n");

        /* Construct the (empty) response body */
        cJSON *response = cJSON_CreateObject ();
        cJSON *vsId = NULL;
        SAFEGET (get_integer_object (&vsId, vs, "vsId"), "vsId missing in JSON\n");
        SAFEPUT (put_integer ("vsId", vsId->valueint, response), "Unable to add vsId to output JSON\n");
        cJSON *tgs_output = cJSON_CreateArray ();
        SAFEPUT (put_object ("testGroups", tgs_output, response), "Unable to add testGroups to output JSON\n");

        SAFEPUT (put_array_item (response, output), "Unable to add response body to JSON\n");

        cJSON *tg = NULL;
        cJSON_ArrayForEach(tg, tgs)  {
            cJSON *tg_output = cJSON_CreateObject ();
            /* Add to output */
            SAFEPUT (put_array_item (tg_output, tgs_output), "Unable to append test group to output\n");

            if(!tg)  {
                fprintf(stderr, "Test groups array is missing test group object.\n");
                goto error_die;
            }

            /* Get test group ID */
            cJSON *tgId = NULL;
            SAFEGET(get_integer_object(&tgId, tg, "tgId"), "Missing test group id!\n");

            /* Copy tgId to output */
            SAFEPUT (put_integer ("tgId", tgId->valueint, tg_output), "Unable to add tgId to test group %d\n", tgId->valueint);

            cJSON *predictionResistence = NULL;
            cJSON *reSeed = NULL;
            cJSON *derFunc = NULL;  /* optional */
            cJSON *entropyInputLen = NULL;
            cJSON *nonceLen = NULL;
            cJSON *persoStringLen = NULL;
            cJSON *additionalInputLen = NULL;
            cJSON *returnedBitsLen = NULL;

            SAFEGET(get_boolean_object(&predictionResistence, tg, "predResistance"), "Unable to get predResistance in JSON in test group %d\n", tgId->valueint);
            pr = cJSON_IsTrue(predictionResistence);

            if (get_boolean_object(&derFunc, tg, "derFunc") < 0)  {
                /* Optional; missing, no derivation function used. */
                df = 0;
            }
            else
                df = cJSON_IsTrue(derFunc);

            SAFEGET(get_boolean_object(&reSeed, tg, "reSeed"), "Unable to get reSeed in JSON in test group %d\n", tgId->valueint);
            SAFEGET(get_integer_object(&entropyInputLen, tg, "entropyInputLen"), "Unable to get entropyInputLen in JSON in test group %d\n", tgId->valueint);
            SAFEGET(get_integer_object(&nonceLen, tg, "nonceLen"), "Unable to get nonceLen in JSON in test group %d\n", tgId->valueint);
            SAFEGET(get_integer_object(&persoStringLen, tg, "persoStringLen"), "Unable to get persoStringLen in JSON in test group %d\n", tgId->valueint);
            SAFEGET(get_integer_object(&additionalInputLen, tg, "additionalInputLen"), "Unable to get additionalInputLen in JSON in test group %d\n", tgId->valueint);
            SAFEGET(get_integer_object(&returnedBitsLen, tg, "returnedBitsLen"), "Unable to get returnedBitsLen in JSON in test group %d\n", tgId->valueint);
#if 0
            /* I have no idea what the returnedBitsLen is for... */
            randoutlen = returnedBitsLen->valueint/8;   /* In bytes */
#endif

            /* Now iterate over the test cases */
            cJSON *tests = NULL;
            SAFEGET(get_object(&tests, tg, "tests"), "Missing test cases in test group %d\n", tgId->valueint);

            cJSON *tests_output = cJSON_CreateArray ();
            SAFEPUT (put_object ("tests", tests_output, tg_output), "Unable to add tests array to output JSON for test group %d\n", tgId->valueint);

            cJSON *tc = NULL;
            cJSON_ArrayForEach(tc, tests)  {
                cJSON *tc_output = cJSON_CreateObject ();
                /* Add to output */
                SAFEPUT (put_array_item (tc_output, tests_output), "Unable to append test case to test case array for group %d in JSON output\n", tgId->valueint);
    
                if(!tc)  {
                    fprintf(stderr, "Test groups array is missing test cases.");
                    goto error_die;
                }

                /* Get test case ID */
                cJSON *tcId = NULL;
                SAFEGET(get_integer_object(&tcId, tc, "tcId"), "Missing test case id in test group %d!\n", tgId->valueint);

                /* Copy back to output */
                SAFEPUT (put_integer ("tcId", tcId->valueint, tc_output), "Unable to provide tcId to test case %d in test group %d in JSON output\n", tcId->valueint, tgId->valueint);

                cJSON *entropyInput = NULL;
                cJSON *nonce_j = NULL;
                cJSON *persoString = NULL;
                cJSON *otherInputs = NULL;   /* Is an array of objects */

                SAFEGET(get_string_object(&entropyInput, tc, "entropyInput"), "Unable to get entropyInput in JSON in test case %d in test group %d\n", tcId->valueint, tgId->valueint);
                SAFEGET(get_string_object(&nonce_j, tc, "nonce"), "Unable to get nonce in JSON in test case %d in test group %d\n", tcId->valueint, tgId->valueint);
                SAFEGET(get_string_object(&persoString, tc, "persoString"), "Unable to get persoString in JSON in test case %d in test group %d\n", tcId->valueint, tgId->valueint);
                SAFEGET(get_object(&otherInputs, tc, "otherInput"), "Unable to get otherInput in JSON in test case %d in test group %d\n", tcId->valueint, tgId->valueint);

                long int dummy = 0;
                t.ent = hex2bin_m(entropyInput->valuestring, &dummy);
                t.entlen = entropyInputLen->valueint/8;
                assert(dummy*8 == entropyInputLen->valueint);   /* I think this is invariant, but not sure */

                t.nonce = hex2bin_m(nonce_j->valuestring, &dummy);
                t.noncelen = nonceLen->valueint/8;
                assert(dummy*8 == nonceLen->valueint);   /* I think this is invariant, but not sure */

    			pers = hex2bin_m(persoString->valuestring, &dummy);
                perslen = persoStringLen->valueint/8;
                assert(dummy == perslen);    /* I think this is invariant, but not sure */


    			dctx = FIPS_drbg_new(nid, df | DRBG_FLAG_TEST);
	    		if (!dctx)  {
                    fprintf(stderr, "Unable to construct FIPS DRBG instance\n");
                    goto error_die;
                }
			    FIPS_drbg_set_callbacks(dctx, test_entropy, 0, 0, test_nonce, 0);
    			FIPS_drbg_set_app_data(dctx, &t);
	    		randoutlen = (int)FIPS_drbg_get_blocklength(dctx);
		    	r = FIPS_drbg_instantiate(dctx, pers, perslen);
			    if (!r)  {
                    fprintf(stderr, "Error instantiating DRBG\n");
                    goto error_die;
                }
	    		OPENSSL_free(pers);
			    OPENSSL_free(t.ent);
    			OPENSSL_free(t.nonce);
	    		t.ent = t.nonce = pers = NULL;
		    	gen = 0;

                /* Process additional input */
                cJSON *otherInput = NULL;
                cJSON_ArrayForEach(otherInput, otherInputs)  {
                    if(!otherInput)  {
                        fprintf(stderr, "Test case %d in test group %d is missing otherInput\n", tcId->valueint, tgId->valueint);
                        goto error_die;
                    }

                    /* There are two operations that can be done: reseed or generate. The array is designed to
                     * be read in order and executed on. 
                     */
                    cJSON *intendedUse = NULL;
                    cJSON *additionalInput = NULL;
                    cJSON *entropyInput_gen = NULL;
                    SAFEGET(get_string_object(&intendedUse, otherInput, "intendedUse"), "Unable to get intendedUse from otherInput\n");
                    SAFEGET(get_string_object(&additionalInput, otherInput, "additionalInput"), "Unable to get additionalInput from otherInput\n");
                    SAFEGET(get_string_object(&entropyInput_gen, otherInput, "entropyInput"), "Unable to get entropyInput from otherInput\n");

			        adin = hex2bin_m(additionalInput->valuestring, &dummy);
                    adinlen = additionalInputLen->valueint/8;
                    assert(dummy*8 == additionalInputLen->valueint);

                    if(t.ent) OPENSSL_free(t.ent); 
                    t.ent = NULL;
				    t.ent = hex2bin_m(entropyInput_gen->valuestring, &dummy);
				    t.entlen = entropyInputLen->valueint/8;

                    if(!strcmp(intendedUse->valuestring, "generate"))  {
                        r = FIPS_drbg_generate(dctx, randout, randoutlen, pr, adin, adinlen);
			            if (!r)  {
				            fprintf(stderr, "Error generating DRBG bits\n");
                            goto error_die;
				        }
                        gen++;
                    }
                    else if (!strcmp(intendedUse->valuestring, "reseed"))  {
			            FIPS_drbg_reseed(dctx, adin, adinlen);
                    }
			        if(t.ent) OPENSSL_free(t.ent);
			        t.ent = NULL;
        			if (adin) OPENSSL_free(adin);
	    		    adin = NULL;
                }   /* End of otherInput array processing */

                /* At this point, we had better have gen == 2, and then we can output */
                assert(gen == 2);
                unsigned char result_hex[sizeof(randout)*2+1];
                SAFEPUT(put_string("returnedBits", bin2hex(randout, randoutlen, result_hex, sizeof(result_hex)), tc_output), "Unable to add returnedBits to output test case\n");
	    		FIPS_drbg_free(dctx);
		    	dctx = NULL;
			    gen = 0;
			}
        }
        printf ("%s\n", cJSON_Print (output));
        ret = 0;
        goto cleanup;
    }

    /* CAVS stream untouched */

    while (fgets(buf, sizeof(buf), in) != NULL)
        {
		fputs(buf, out);
		if (drbg_type == DRBG_NONE)
		    {
    		if (strstr(buf, "CTR_DRBG"))
	        	drbg_type = DRBG_CTR;
		   	else if (strstr(buf, "Hash_DRBG"))
		    	drbg_type = DRBG_HASH;
    		else if (strstr(buf, "HMAC_DRBG"))
	    		drbg_type = DRBG_HMAC;
		   	else if (strstr(buf, "Dual_EC_DRBG"))
		    	drbg_type = DRBG_DUAL_EC;
    		else
	    		continue;
		   	}
		if (strlen(buf) > 4 && !strncmp(buf, "[SHA-", 5))
			{
			nid = dparse_md(buf);
			if (nid == NID_undef)
				exit(1);
			if (drbg_type == DRBG_HMAC)
				{
				switch (nid)
					{
					case NID_sha1:
					nid = NID_hmacWithSHA1;
					break;

					case NID_sha224:
					nid = NID_hmacWithSHA224;
					break;

					case NID_sha256:
					nid = NID_hmacWithSHA256;
					break;

					case NID_sha384:
					nid = NID_hmacWithSHA384;
					break;

					case NID_sha512:
					nid = NID_hmacWithSHA512;
					break;

					default:
					exit(1);
					}
				}
			}
		if (strlen(buf) > 12 && !strncmp(buf, "[AES-", 5))
			{
			nid = parse_aes(buf, &df);
			if (nid == NID_undef)
				exit(1);
			}
		if (strlen(buf) > 12 && !strncmp(buf, "[P-", 3))
			{
			nid = parse_ec(buf);
			if (nid == NID_undef)
				exit(1);
			}
		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;

		if (!strcmp(keyword, "[PredictionResistance"))
			{
			if (!strcmp(value, "True]"))
				pr = 1;
			else if (!strcmp(value, "False]"))
				pr = 0;
			else
				exit(1);
			}

		if (!strcmp(keyword, "EntropyInput"))
			{
			ent = hex2bin_m(value, &entlen);
			t.ent = ent;
			t.entlen = entlen;
			}

		if (!strcmp(keyword, "Nonce"))
			{
			nonce = hex2bin_m(value, &noncelen);
			t.nonce = nonce;
			t.noncelen = noncelen;
			}

		if (!strcmp(keyword, "PersonalizationString"))
			{
			pers = hex2bin_m(value, &perslen);
			if (nid == 0)
				{
				fprintf(stderr, "DRBG type not recognised!\n");
				exit (1);
				}
			dctx = FIPS_drbg_new(nid, df | DRBG_FLAG_TEST);
			if (!dctx)
				exit (1);
			FIPS_drbg_set_callbacks(dctx, test_entropy, 0, 0,
							test_nonce, 0);
			FIPS_drbg_set_app_data(dctx, &t);
			randoutlen = (int)FIPS_drbg_get_blocklength(dctx);
			r = FIPS_drbg_instantiate(dctx, pers, perslen);
			if (!r)
				{
				fprintf(stderr, "Error instantiating DRBG\n");
				exit(1);
				}
			OPENSSL_free(pers);
			OPENSSL_free(ent);
			OPENSSL_free(nonce);
			ent = nonce = pers = NULL;
			gen = 0;
			}

		if (!strcmp(keyword, "AdditionalInput"))
			{
			adin = hex2bin_m(value, &adinlen);
			if (pr)
				continue;
			r = FIPS_drbg_generate(dctx, randout, randoutlen, 0,
								adin, adinlen);
			if (!r)
				{
				fprintf(stderr, "Error generating DRBG bits\n");
				exit(1);
				}
			if (!r)
				exit(1);
			OPENSSL_free(adin);
			adin = NULL;
			gen++;
			}

		if (pr)
			{
			if (!strcmp(keyword, "EntropyInputPR"))
				{
				ent = hex2bin_m(value, &entlen);
				t.ent = ent;
				t.entlen = entlen;
				r = FIPS_drbg_generate(dctx,
							randout, randoutlen,
							1, adin, adinlen);
				if (!r)
					{
					fprintf(stderr,
						"Error generating DRBG bits\n");
					exit(1);
					}
				OPENSSL_free(adin);
				OPENSSL_free(ent);
				adin = ent = NULL;
				gen++;
				}
			}
		if (!strcmp(keyword, "EntropyInputReseed"))
			{
			ent = hex2bin_m(value, &entlen);
			t.ent = ent;
			t.entlen = entlen;
			}
		if (!strcmp(keyword, "AdditionalInputReseed"))
			{
			adin = hex2bin_m(value, &adinlen);
			FIPS_drbg_reseed(dctx, adin, adinlen);
			OPENSSL_free(ent);
			OPENSSL_free(adin);
			ent = adin = NULL;
			}
		if (gen == 2)
			{
			OutputValue("ReturnedBits", randout, randoutlen,
									out, 0);
			FIPS_drbg_free(dctx);
			dctx = NULL;
			gen = 0;
			}

		}
    ret = 0;
    goto cleanup;
error_die:
    ret = 1;
cleanup:
	if (in && in != stdin)
		fclose(in);
	if (out && out != stdout)
		fclose(out);
	return ret;
	}

#endif
