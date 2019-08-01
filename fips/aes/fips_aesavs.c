/**
 * ACVP modifications copyright (c) 2019 Lightship Security.
 * All rights reserved.
 */

/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 *
 */
/*---------------------------------------------
  NIST AES Algorithm Validation Suite
  Test Program

  Donated to OpenSSL by:
  V-ONE Corporation
  20250 Century Blvd, Suite 300
  Germantown, MD 20874
  U.S.A.
  ----------------------------------------------*/

#define OPENSSL_FIPSAPI

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include <openssl/err.h>
#include "e_os.h"

#include "acvp.h"


#ifndef OPENSSL_FIPS

int main(int argc, char *argv[])
{
    printf("No FIPS AES support\n");
    return(0);
}

#else

#include <openssl/fips.h>
#include "fips_utl.h"

#define AES_BLOCK_SIZE 16

#define VERBOSE 0

/*-----------------------------------------------*/

static int AESTest(EVP_CIPHER_CTX *ctx,
	    char *amode, int akeysz, unsigned char *aKey, 
	    unsigned char *iVec, 
	    int dir,  /* 0 = decrypt, 1 = encrypt */
	    unsigned char *plaintext, unsigned char *ciphertext, int len)
    {
    const EVP_CIPHER *cipher = NULL;

    if (fips_strcasecmp(amode, "CBC") == 0)
	{
	switch (akeysz)
		{
		case 128:
		cipher = EVP_aes_128_cbc();
		break;

		case 192:
		cipher = EVP_aes_192_cbc();
		break;

		case 256:
		cipher = EVP_aes_256_cbc();
		break;
		}

	}
    else if (fips_strcasecmp(amode, "ECB") == 0)
	{
	switch (akeysz)
		{
		case 128:
		cipher = EVP_aes_128_ecb();
		break;

		case 192:
		cipher = EVP_aes_192_ecb();
		break;

		case 256:
		cipher = EVP_aes_256_ecb();
		break;
		}
	}
    else if (fips_strcasecmp(amode, "CFB128") == 0)
	{
	switch (akeysz)
		{
		case 128:
		cipher = EVP_aes_128_cfb128();
		break;

		case 192:
		cipher = EVP_aes_192_cfb128();
		break;

		case 256:
		cipher = EVP_aes_256_cfb128();
		break;
		}

	}
    else if (fips_strncasecmp(amode, "OFB", 3) == 0)
	{
	switch (akeysz)
		{
		case 128:
		cipher = EVP_aes_128_ofb();
		break;

		case 192:
		cipher = EVP_aes_192_ofb();
		break;

		case 256:
		cipher = EVP_aes_256_ofb();
		break;
		}
	}
    else if(!fips_strcasecmp(amode,"CFB1"))
	{
	switch (akeysz)
		{
		case 128:
		cipher = EVP_aes_128_cfb1();
		break;

		case 192:
		cipher = EVP_aes_192_cfb1();
		break;

		case 256:
		cipher = EVP_aes_256_cfb1();
		break;
		}
	}
    else if(!fips_strcasecmp(amode,"CFB8"))
	{
	switch (akeysz)
		{
		case 128:
		cipher = EVP_aes_128_cfb8();
		break;

		case 192:
		cipher = EVP_aes_192_cfb8();
		break;

		case 256:
		cipher = EVP_aes_256_cfb8();
		break;
		}
	}
    else
	{
	printf("Unknown mode: %s\n", amode);
	return 0;
	}
    if (!cipher)
	{
	printf("Invalid key size: %d\n", akeysz);
	return 0; 
	}
    if (FIPS_cipherinit(ctx, cipher, aKey, iVec, dir) <= 0)
	return 0;
    if(!fips_strcasecmp(amode,"CFB1"))
	M_EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS);
    if (dir)
		FIPS_cipher(ctx, ciphertext, plaintext, len);
	else
		FIPS_cipher(ctx, plaintext, ciphertext, len);
    return 1;
    }

/*-----------------------------------------------*/
char *t_tag[2] = {"PLAINTEXT", "CIPHERTEXT"};
char *t_mode[6] = {"CBC","ECB","OFB","CFB1","CFB8","CFB128"};
enum Mode {CBC, ECB, OFB, CFB1, CFB8, CFB128};
enum XCrypt {XDECRYPT, XENCRYPT};

/*=============================*/
/*  Monte Carlo Tests          */
/*-----------------------------*/

/*#define gb(a,b) (((a)[(b)/8] >> ((b)%8))&1)*/
/*#define sb(a,b,v) ((a)[(b)/8]=((a)[(b)/8]&~(1 << ((b)%8)))|(!!(v) << ((b)%8)))*/

#define gb(a,b) (((a)[(b)/8] >> (7-(b)%8))&1)
#define sb(a,b,v) ((a)[(b)/8]=((a)[(b)/8]&~(1 << (7-(b)%8)))|(!!(v) << (7-(b)%8)))

int construct_acvp_mct_iter(int iter, int imode, unsigned char *key, int keylen, unsigned char *iv, int dir, unsigned char *text, int len, cJSON *node)  {
    int ret = 0;
    /* Just need key, iv, pt, ct in a new result */
    unsigned char key_hex[keylen*2+1];
    unsigned char iv_hex[AES_BLOCK_SIZE*2+1];
    unsigned char result_hex[len*2+1];

    SAFEPUT(put_string("key", bin2hex(key, keylen, &key_hex[0], sizeof(key_hex)), node), "Unable to construct key output for MCT iteration %d\n", iter);

    if (imode != ECB) /* ECB */
        SAFEPUT(put_string("iv", bin2hex(iv, AES_BLOCK_SIZE, &iv_hex[0], sizeof(iv_hex)), node), "Unable to construct IV output for MCT iteration %d\n", iter);

    if (dir == 0)  {       /* Decrypt */
        if (imode == CFB1)  {
            /* If CFB1, then need to bit output */
        }
        SAFEPUT(put_string("ct", bin2hex(text, len, &result_hex[0], sizeof (result_hex)), node), "Unable to construct CT output for MCT iteration %d\n", iter);
    } else  {       /* Encrypt */
        if (imode == CFB1)  {
            /* If CFB1, then need to bit output */
        }
        SAFEPUT(put_string("pt", bin2hex(text, len, &result_hex[0], sizeof(result_hex)), node), "Unable to construct PT output for MCT iteration %d\n", iter);
    }
    goto success;
error_die:
    ret = -1;
success:
    return ret;
}

static int do_mct(char *amode, 
	   int akeysz, unsigned char *aKey,unsigned char *iVec,
	   int dir, unsigned char *text, int len,
	   FILE *rfp, cJSON *node)
    {
    int ret = 0;
    unsigned char key[101][32];
    unsigned char iv[101][AES_BLOCK_SIZE];
    unsigned char ptext[1001][32];
    unsigned char ctext[1001][32];
    unsigned char ciphertext[64+4];
    int i, j, n, n1, n2;
    int imode = 0, nkeysz = akeysz/8;
    EVP_CIPHER_CTX ctx;
    FIPS_cipher_ctx_init(&ctx);

    if (cavs && !rfp)  {
        printf ("Missing response file for CAVS output\n");
        return -1;
    }
    if (acvp && !node)  {
        printf ("Missing JSON node for ACVP output\n");
        return -1;
    }

    if (len > 32)
	{
	printf("\n>>>> Length exceeds 32 for %s %d <<<<\n\n", 
	       amode, akeysz);
	return -1;
	}
    for (imode = 0; imode < 6; ++imode)
	if (strcmp(amode, t_mode[imode]) == 0)
	    break;
    if (imode == 6)
	{ 
	printf("Unrecognized mode: %s\n", amode);
	return -1;
	}

    memcpy(key[0], aKey, nkeysz);
    if (iVec)
	memcpy(iv[0], iVec, AES_BLOCK_SIZE);
    if (dir == XENCRYPT)
	memcpy(ptext[0], text, len);
    else
	memcpy(ctext[0], text, len);
    for (i = 0; i < 100; ++i)
	{
    cJSON *mct_iter = cJSON_CreateObject ();
    if (acvp)  {
        /* Add to output, which is an array */
        SAFEPUT(put_array_item (mct_iter, node), "Unable to allocate MCT iteration in output JSON node\n");
    }
	/* printf("Iteration %d\n", i); */
    /**
     * Note that do_mct() is called from the processing function.
     * The processing function is supposed to output all of the initial
     * values for iteration 0 before calling do_mct() via copy_line. 
     * This is why the i > 0 is done whereas down below, the 
     * ciphertext/plaintext is emitted without any other key/count/iv 
     * information on the initial iteration.
     * For ACVP, this doesn't work so well, so we need to emit the
     * initial information in the 0th iteration.
     */

    if (i == 0 && acvp)  {
        if (construct_acvp_mct_iter(i, imode, aKey, nkeysz, iVec, dir, text, len, mct_iter) != 0) 
            goto error_die;
    }
	if (i > 0)  {
        if(cavs)  {
    	    fprintf(rfp,"COUNT = %d" RESP_EOL ,i);
	        OutputValue("KEY",key[i],nkeysz,rfp,0);
	        if (imode != ECB)  /* ECB */
                OutputValue("IV",iv[i],AES_BLOCK_SIZE,rfp,0);
    	    /* Output Ciphertext | Plaintext */
	        OutputValue(t_tag[dir^1],dir ? ptext[0] : ctext[0],len,rfp,
		        imode == CFB1);
        }
        if (acvp)  {
            if (construct_acvp_mct_iter(i, imode, key[i], nkeysz, iv[i], dir, dir ? ptext[0] : ctext[0], len, mct_iter) != 0) 
                goto error_die;
        }   /* End of ACVP output for i > 0 */
	}   /* End of Check for i > 0 */

	for (j = 0; j < 1000; ++j)
	    {
	    switch (imode)
		{
	    case ECB:
		if (j == 0)
		    { /* set up encryption */
		    ret = AESTest(&ctx, amode, akeysz, key[i], NULL, 
				  dir,  /* 0 = decrypt, 1 = encrypt */
				  ptext[j], ctext[j], len);
		    if (dir == XENCRYPT)
			memcpy(ptext[j+1], ctext[j], len);
		    else
			memcpy(ctext[j+1], ptext[j], len);
		    }
		else
		    {
		    if (dir == XENCRYPT)
			{
			FIPS_cipher(&ctx, ctext[j], ptext[j], len);
			memcpy(ptext[j+1], ctext[j], len);
			}
		    else
			{
			FIPS_cipher(&ctx, ptext[j], ctext[j], len);
			memcpy(ctext[j+1], ptext[j], len);
			}
		    }
		break;

	    case CBC:
	    case OFB:  
	    case CFB128:
		if (j == 0)
		    {
		    ret = AESTest(&ctx, amode, akeysz, key[i], iv[i], 
				  dir,  /* 0 = decrypt, 1 = encrypt */
				  ptext[j], ctext[j], len);
		    if (dir == XENCRYPT)
			memcpy(ptext[j+1], iv[i], len);
		    else
			memcpy(ctext[j+1], iv[i], len);
		    }
		else
		    {
		    if (dir == XENCRYPT)
			{
			FIPS_cipher(&ctx, ctext[j], ptext[j], len);
			memcpy(ptext[j+1], ctext[j-1], len);
			}
		    else
			{
			FIPS_cipher(&ctx, ptext[j], ctext[j], len);
			memcpy(ctext[j+1], ptext[j-1], len);
			}
		    }
		break;

	    case CFB8:
		if (j == 0)
		    {
		    ret = AESTest(&ctx, amode, akeysz, key[i], iv[i], 
				  dir,  /* 0 = decrypt, 1 = encrypt */
				  ptext[j], ctext[j], len);
		    }
		else
		    {
		    if (dir == XENCRYPT)
			FIPS_cipher(&ctx, ctext[j], ptext[j], len);
		    else
			FIPS_cipher(&ctx, ptext[j], ctext[j], len);
		    }
		if (dir == XENCRYPT)
		    {
		    if (j < 16)
			memcpy(ptext[j+1], &iv[i][j], len);
		    else
			memcpy(ptext[j+1], ctext[j-16], len);
		    }
		else
		    {
		    if (j < 16)
			memcpy(ctext[j+1], &iv[i][j], len);
		    else
			memcpy(ctext[j+1], ptext[j-16], len);
		    }
		break;

	    case CFB1:
		if(j == 0)
		    {
#if 0
		    /* compensate for wrong endianness of input file */
		    if(i == 0)
			ptext[0][0]<<=7;
#endif
		    ret = AESTest(&ctx,amode,akeysz,key[i],iv[i],dir,
				ptext[j], ctext[j], len);
		    }
		else
		    {
		    if (dir == XENCRYPT)
			FIPS_cipher(&ctx, ctext[j], ptext[j], len);
		    else
			FIPS_cipher(&ctx, ptext[j], ctext[j], len);

		    }
		if(dir == XENCRYPT)
		    {
		    if(j < 128)
			sb(ptext[j+1],0,gb(iv[i],j));
		    else
			sb(ptext[j+1],0,gb(ctext[j-128],0));
		    }
		else
		    {
		    if(j < 128)
			sb(ctext[j+1],0,gb(iv[i],j));
		    else
			sb(ctext[j+1],0,gb(ptext[j-128],0));
		    }
		break;
		}
	    }
	--j; /* reset to last of range */
	/* Output Ciphertext | Plaintext */
    if(cavs)  {
    	OutputValue(t_tag[dir],dir ? ctext[j] : ptext[j],len,rfp,
		    imode == CFB1);
	    fprintf(rfp, RESP_EOL);  /* add separator */
    }
    if(acvp)  {
        /* Output the other side */
        if (!strcmp (amode, "CFB1"))  {
            /* CFB1 mode reqiures bit-oriented output */
            /* The number of bytes to accommodate n bits in output is (n+7)/8 */
            len = (len+7)/8;
        }

        if (dir == 0)  {      /* Decrypt */
            unsigned char result_hex[sizeof(ptext[j])*2+1];
            SAFEPUT(put_string("pt", bin2hex(ptext[j], len, &result_hex[0], sizeof(result_hex)), mct_iter), "Unable to construct PT output for MCT iteration %d\n", i);
        } else {            /* Encrypt */
            unsigned char result_hex[sizeof(ctext[j])*2+1];
            SAFEPUT(put_string("ct", bin2hex(ctext[j], len, &result_hex[0], sizeof(result_hex)), mct_iter), "Unable to construct CT output for MCT iteration %d\n", i);
        }
    }   /* End of ACVP/CAVS check */

	/* Compute next KEY */
	if (dir == XENCRYPT)
	    {
	    if (imode == CFB8)
		{ /* ct = CT[j-15] || CT[j-14] || ... || CT[j] */
		for (n1 = 0, n2 = nkeysz-1; n1 < nkeysz; ++n1, --n2)
		    ciphertext[n1] = ctext[j-n2][0];
		}
	    else if(imode == CFB1)
		{
		for(n1=0,n2=akeysz-1 ; n1 < akeysz ; ++n1,--n2)
		    sb(ciphertext,n1,gb(ctext[j-n2],0));
		}
	    else
		switch (akeysz)
		    {
		case 128:
		    memcpy(ciphertext, ctext[j], 16);
		    break;
		case 192:
		    memcpy(ciphertext, ctext[j-1]+8, 8);
		    memcpy(ciphertext+8, ctext[j], 16);
		    break;
		case 256:
		    memcpy(ciphertext, ctext[j-1], 16);
		    memcpy(ciphertext+16, ctext[j], 16);
		    break;
		    }
	    }
	else
	    {
	    if (imode == CFB8)
		{ /* ct = CT[j-15] || CT[j-14] || ... || CT[j] */
		for (n1 = 0, n2 = nkeysz-1; n1 < nkeysz; ++n1, --n2)
		    ciphertext[n1] = ptext[j-n2][0];
		}
	    else if(imode == CFB1)
		{
		for(n1=0,n2=akeysz-1 ; n1 < akeysz ; ++n1,--n2)
		    sb(ciphertext,n1,gb(ptext[j-n2],0));
		}
	    else
		switch (akeysz)
		    {
		case 128:
		    memcpy(ciphertext, ptext[j], 16);
		    break;
		case 192:
		    memcpy(ciphertext, ptext[j-1]+8, 8);
		    memcpy(ciphertext+8, ptext[j], 16);
		    break;
		case 256:
		    memcpy(ciphertext, ptext[j-1], 16);
		    memcpy(ciphertext+16, ptext[j], 16);
		    break;
		    }
	    }
	/* Compute next key: Key[i+1] = Key[i] xor ct */
	for (n = 0; n < nkeysz; ++n)
	    key[i+1][n] = key[i][n] ^ ciphertext[n];
	
	/* Compute next IV and text */
	if (dir == XENCRYPT)
	    {
	    switch (imode)
		{
	    case ECB:
		memcpy(ptext[0], ctext[j], AES_BLOCK_SIZE);
		break;
	    case CBC:
	    case OFB:
	    case CFB128:
		memcpy(iv[i+1], ctext[j], AES_BLOCK_SIZE);
		memcpy(ptext[0], ctext[j-1], AES_BLOCK_SIZE);
		break;
	    case CFB8:
		/* IV[i+1] = ct */
		for (n1 = 0, n2 = 15; n1 < 16; ++n1, --n2)
		    iv[i+1][n1] = ctext[j-n2][0];
		ptext[0][0] = ctext[j-16][0];
		break;
	    case CFB1:
		for(n1=0,n2=127 ; n1 < 128 ; ++n1,--n2)
		    sb(iv[i+1],n1,gb(ctext[j-n2],0));
		ptext[0][0]=ctext[j-128][0]&0x80;
		break;
		}
	    }
	else
	    {
	    switch (imode)
		{
	    case ECB:
		memcpy(ctext[0], ptext[j], AES_BLOCK_SIZE);
		break;
	    case CBC:
	    case OFB:
	    case CFB128:
		memcpy(iv[i+1], ptext[j], AES_BLOCK_SIZE);
		memcpy(ctext[0], ptext[j-1], AES_BLOCK_SIZE);
		break;
	    case CFB8:
		for (n1 = 0, n2 = 15; n1 < 16; ++n1, --n2)
		    iv[i+1][n1] = ptext[j-n2][0];
		ctext[0][0] = ptext[j-16][0];
		break;
	    case CFB1:
		for(n1=0,n2=127 ; n1 < 128 ; ++n1,--n2)
		    sb(iv[i+1],n1,gb(ptext[j-n2],0));
		ctext[0][0]=ptext[j-128][0]&0x80;
		break;
		}
	    }
	}
error_die:
    FIPS_cipher_ctx_cleanup(&ctx);
    return ret;
    }

/*================================================*/
/*----------------------------
  # Config info for v-one
  # AESVS MMT test data for ECB
  # State : Encrypt and Decrypt
  # Key Length : 256
  # Fri Aug 30 04:07:22 PM
  ----------------------------*/

static int proc_file_acvp(char *rqfile, char *rspfile)  {
    int ret = 0;
    cJSON *json = NULL;
    char afn[256], rfn[256];
    FILE *rfp = NULL;
    char *rp;
    char amode[8] = "";
    int dir = -1;
    int akeysz = 0;
    unsigned char iVec[20], aKey[40];
    unsigned char plaintext[2048];
    unsigned char ciphertext[2048];
    unsigned char result_hex[2048];

    EVP_CIPHER_CTX ctx;
    FIPS_cipher_ctx_init(&ctx);

    if (!rqfile || !(*rqfile))  {
	    printf("No req file\n");
        goto error_die;
	}
    strcpy(afn, rqfile);

    if ((json = read_file_as_json(afn)) == NULL)  {
	    printf("Cannot open file: %s, %s\n", 
	       afn, strerror(errno));
        goto error_die;
	}
    if (!rspfile)  {
	    strcpy(rfn,afn);
    	rp=strstr(rfn,"req/");
#ifdef OPENSSL_SYS_WIN32
	    if (!rp)
	        rp=strstr(rfn,"req\\");
#endif
    	assert(rp);
	    memcpy(rp,"rsp",3);
    	rp = strstr(rfn, ".req");
	    memcpy(rp, ".rsp", 4);
    	rspfile = rfn;
	}
    if ((rfp = fopen(rspfile, "w")) == NULL)  {
	    printf("Cannot open file: %s, %s\n", 
	       rfn, strerror(errno));
        goto error_die;
	}

    /* Data is parsed already; now we need to extract everything to give to the caller. */
    /* Validate that the structure is sound and conforms with the expected structure format. */
    if (cJSON_GetArraySize(json) != 2)  {
        printf("Expecting array of size 2 in top-level JSON. Check input format.\n");
        goto error_die;
    }

    /* Check version is correct */
    assert(verify_acvp_version(json, "1.0"));

    /* Initialize output structure */
    cJSON *output = init_output (json);

    /* Now get the pertinent details */
    cJSON *vs = NULL;
    SAFEGET(get_array_item(&vs, json, 1), "Vector set missing in JSON\n");
    cJSON *algStr = NULL;
    SAFEGET(get_string_object(&algStr, vs, "algorithm"), "Algorithm identifier missing in JSON\n");
    /* Algorithm mode is last chars after last hyphen. */
    strcpy(amode, strrchr(algStr->valuestring, '-')+1);

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
            printf("Test groups array is missing test group object.\n");
            goto error_die;
        }

        /* Get test group ID */
        cJSON *tgId = NULL;
        SAFEGET(get_integer_object(&tgId, tg, "tgId"), "Missing test group id!\n");

        /* Copy tgId to output */
        SAFEPUT (put_integer ("tgId", tgId->valueint, tg_output), "Unable to add tgId to test group %d\n", tgId->valueint);

        /* Get test type (used later) and direction */
        cJSON *test_type = NULL;
        SAFEGET(get_string_object(&test_type, tg, "testType"), "Missing `testType' in input JSON\n");
        cJSON *direction = NULL;
        SAFEGET(get_string_object(&direction, tg, "direction"), "Missing `direction' in input JSON\n");
        if(strncmp("encrypt", direction->valuestring, 7) == 0)
            dir = 1;
        else if (strncmp("decrypt", direction->valuestring, 7) == 0)
            dir = 0;
        else  {
            printf ("Unknown direction %s found\n", direction->valuestring);
        }

        /* Get key length */
        cJSON *keyLen = NULL;
        SAFEGET(get_integer_object(&keyLen, tg, "keyLen"), "Missing `keyLen' in input JSON\n");

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
                printf("Test groups array is missing test cases.");
                goto error_die;
            }

            /* Get test case ID */
            cJSON *tcId = NULL;
            SAFEGET(get_integer_object(&tcId, tc, "tcId"), "Missing test case id in test group %d!\n", tgId->valueint);

            /* Copy back to output */
            SAFEPUT (put_integer ("tcId", tcId->valueint, tc_output), "Unable to provide tcId to test case %d in test group %d in JSON output\n", tcId->valueint, tgId->valueint);

            /* Get key and IV */
            akeysz = keyLen->valueint;
            
            cJSON *ivStr = NULL;
		    memset(iVec, 0, sizeof(iVec));
            if (strncmp(amode, "ECB", 3) != 0)  {
                /* ECB has no IV, everything else does */
                SAFEGET(get_string_object(&ivStr, tc, "iv"), "Missing IV in test case %d in test group %d\n", tcId->valueint, tgId->valueint);
                if(hex2bin(ivStr->valuestring, iVec) < 0)  {
                    printf("IV has invalid length in test case %d in test group %d\n", tcId->valueint, tgId->valueint);
                    goto error_die;
                }
            }

            cJSON *keyStr = NULL;
            SAFEGET(get_string_object(&keyStr, tc, "key"), "Missing `key' in test case %d in test group %d\n", tcId->valueint, tgId->valueint);
            if(hex2bin(keyStr->valuestring, aKey) < 0)  {
                printf("Key has invalid length in test case %d in test group %d\n", tcId->valueint, tgId->valueint);
                goto error_die;
            }

            /* Get plaintext if encrypt; ciphertext if decrypt */
            int len = 0;
		    memset(plaintext, 0, sizeof(plaintext));
		    memset(ciphertext, 0, sizeof(ciphertext));

            /* We will use the CFB1 payloadLen later in other places, so do up here */
            cJSON *payloadLen = NULL;
            if (!strcmp(amode,"CFB1"))  {
                /* Length has to be restated as length in bits of most significant bits */
                SAFEGET(get_integer_object(&payloadLen, tc, "payloadLen"), "Missing payloadLen in CFB1 test case %d in test group %d\n", tcId->valueint, tgId->valueint);
            }

            if(dir == 0)  { /* Decrypt */
                cJSON *ctStr = NULL;
                SAFEGET(get_string_object(&ctStr, tc, "ct"), "Missing ciphertext in test case %d in test group %d\n", tcId->valueint, tgId->valueint);
                len = hex2bin(ctStr->valuestring, ciphertext);
                if (!strcmp(amode,"CFB1"))  {
                    /* Length has to be restated as length in bits of most significant bits */
                    len = payloadLen->valueint;
                }

                if(len < 0)  {
                    printf("Ciphertext did not convert properly in test case %d in test group %d\n", tcId->valueint, tgId->valueint);
                    goto error_die;
                }
                if(len >= sizeof(ciphertext))  {
                    printf("Ciphertext buffer overflow\n");
                }
            } else {
                /* Encrypt */
                cJSON *ptStr = NULL;
                SAFEGET(get_string_object(&ptStr, tc, "pt"), "Missing plaintext in test case %d in test group %d\n", tcId->valueint, tgId->valueint);
                len = hex2bin(ptStr->valuestring, plaintext);
                if (!strcmp(amode,"CFB1"))  {
                    /* Length has to be restated as length in bits of most significant bits */
                    len = payloadLen->valueint;
                }
                if(len < 0)  {
                    printf("Plaintext did not convert properly in test case %d in test group %d\n", tcId->valueint, tgId->valueint);
                    goto error_die;
                }
                if(len >= sizeof(plaintext))  {
                    printf("Plaintext buffer overflow\n");
                }
            }


            if(strncmp("AFT", test_type->valuestring, 3) == 0)  {
                /* Functional test */
                /* The calling convention is the same since AESTest will figure out the parameters */
                AESTest(&ctx, amode, akeysz, aKey, iVec,
                    dir,  /* 0 = decrypt, 1 = encrypt */
                    plaintext, ciphertext, len);

                if (!strcmp (amode, "CFB1"))  {
                    /* CFB1 mode reqiures bit-oriented output */
                    /* The number of bytes to accommodate n bits in output is (n+7)/8 */
                    len = (len+7)/8;
                }
                if(dir == 1)  {    /* Encrypt produces ciphertext */
                    SAFEPUT(put_string("ct", bin2hex(ciphertext, len, result_hex, sizeof(result_hex)), tc_output), "Unable to add ciphertext to output");
                } else {
                    SAFEPUT(put_string("pt", bin2hex(plaintext, len, result_hex, sizeof(result_hex)), tc_output), "Unable to add plaintext to output");
                }
            } else if (strncmp("MCT", test_type->valuestring, 3) == 0)  {
                /* Monte Carlo test */
                /* Add results array to structure */
                cJSON *mct_results = cJSON_CreateArray ();
                SAFEPUT(put_object ("resultsArray", mct_results, tc_output),  "Unable to allocate resultsArray for MCT in test group %d\n", tgId->valueint);
                if (dir == 0)  {    /* Decrypt */
                    if(do_mct(amode, akeysz, aKey, iVec,
                        dir, (unsigned char*)ciphertext, len,
                        NULL, mct_results) < 0) 
                        goto error_die;
                }
                else  {             /* Encrypt */
                    if(do_mct(amode, akeysz, aKey, iVec,
                        dir, (unsigned char*)plaintext, len,
                        NULL, mct_results) < 0) 
                        goto error_die;
                }
            } else  {
                printf ("Unknown test type %s found in ACVP definition.\n", test_type->valuestring);
                goto error_die;
            }
        }
    }

#if 0
    AESTest(&ctx, amode, akeysz, aKey, iVec,
            dir,  /* 0 = decrypt, 1 = encrypt */
            plaintext, ciphertext, len);
#endif
    printf ("%s\n", cJSON_Print (output));
    goto cleanup;

error_die:
    ret = -1;

cleanup:
    if(rfp)  
        fclose(rfp); 
    rfp = NULL;
    if(json) 
        cJSON_Delete(json); 
    json = NULL;
    FIPS_cipher_ctx_cleanup(&ctx);

    return ret;
}

static int proc_file_cavs(char *rqfile, char *rspfile)
    {
    char afn[256], rfn[256];
    FILE *afp = NULL, *rfp = NULL;
    char ibuf[2048];
    char tbuf[2048];
    int len;
    char algo[8] = "";
    char amode[8] = "";
    char atest[8] = "";
    int akeysz = 0;
    unsigned char iVec[20], aKey[40];
    int dir = -1, err = 0, step = 0;
    unsigned char plaintext[2048];
    unsigned char ciphertext[2048];
    char *rp;
    EVP_CIPHER_CTX ctx;
    FIPS_cipher_ctx_init(&ctx);

    if (!rqfile || !(*rqfile))
	{
	printf("No req file\n");
	return -1;
	}
    strcpy(afn, rqfile);

    if ((afp = fopen(afn, "r")) == NULL)
	{
	printf("Cannot open file: %s, %s\n", 
	       afn, strerror(errno));
	return -1;
	}
    if (!rspfile)
	{
	strcpy(rfn,afn);
	rp=strstr(rfn,"req/");
#ifdef OPENSSL_SYS_WIN32
	if (!rp)
	    rp=strstr(rfn,"req\\");
#endif
	assert(rp);
	memcpy(rp,"rsp",3);
	rp = strstr(rfn, ".req");
	memcpy(rp, ".rsp", 4);
	rspfile = rfn;
	}
    if ((rfp = fopen(rspfile, "w")) == NULL)
	{
	printf("Cannot open file: %s, %s\n", 
	       rfn, strerror(errno));
	fclose(afp);
	afp = NULL;
	return -1;
	}
    while (!err && (fgets(ibuf, sizeof(ibuf), afp)) != NULL)
	{
	tidy_line(tbuf, ibuf);
	/*      printf("step=%d ibuf=%s",step,ibuf); */
	switch (step)
	    {
	case 0:  /* read preamble */
	    if (ibuf[0] == '\n')
		{ /* end of preamble */
		if ((*algo == '\0') ||
		    (*amode == '\0') ||
		    (akeysz == 0))
		    {
		    printf("Missing Algorithm, Mode or KeySize (%s/%s/%d)\n",
			   algo,amode,akeysz);
		    err = 1;
		    }
		else
		    {
		    copy_line(ibuf, rfp);
		    ++ step;
		    }
		}
	    else if (ibuf[0] != '#')
		{
		printf("Invalid preamble item: %s\n", ibuf);
		err = 1;
		}
	    else
		{ /* process preamble */
		char *xp, *pp = ibuf+2;
		int n;
		if (akeysz)
		    {
		    copy_line(ibuf, rfp);
		    }
		else
		    {
		    copy_line(ibuf, rfp);
		    if (strncmp(pp, "AESVS ", 6) == 0)
			{
			strcpy(algo, "AES");
			/* get test type */
			pp += 6;
			xp = strchr(pp, ' ');
			n = xp-pp;
			strncpy(atest, pp, n);
			atest[n] = '\0';
			/* get mode */
			xp = strrchr(pp, ' '); /* get mode" */
			n = strlen(xp+1)-1;
			strncpy(amode, xp+1, n);
			amode[n] = '\0';
			/* amode[3] = '\0'; */
			if (VERBOSE)
				printf("Test = %s, Mode = %s\n", atest, amode);
			}
		    else if (fips_strncasecmp(pp, "Key Length : ", 13) == 0)
			{
			akeysz = atoi(pp+13);
			if (VERBOSE)
				printf("Key size = %d\n", akeysz);
			}
		    }
		}
	    break;

	case 1:  /* [ENCRYPT] | [DECRYPT] */
	    if (ibuf[0] == '[')
		{
		copy_line(ibuf, rfp);
		++step;
		if (fips_strncasecmp(ibuf, "[ENCRYPT]", 9) == 0)
		    dir = 1;
		else if (fips_strncasecmp(ibuf, "[DECRYPT]", 9) == 0)
		    dir = 0;
		else
		    {
		    printf("Invalid keyword: %s\n", ibuf);
		    err = 1;
		    }
		break;
		}
	    else if (dir == -1)
		{
		err = 1;
		printf("Missing ENCRYPT/DECRYPT keyword\n");
		break;
		}
	    else 
		step = 2;

	case 2: /* KEY = xxxx */
	    copy_line(ibuf, rfp);
	    if(*ibuf == '\n')
		break;
	    if(!fips_strncasecmp(ibuf,"COUNT = ",8))
		break;

	    if (fips_strncasecmp(ibuf, "KEY = ", 6) != 0)
		{
		printf("Missing KEY\n");
		err = 1;
		}
	    else
		{
		len = hex2bin((char*)ibuf+6, aKey);
		if (len < 0)
		    {
		    printf("Invalid KEY\n");
		    err =1;
		    break;
		    }
		PrintValue("KEY", aKey, len);
		if (strcmp(amode, "ECB") == 0)
		    {
		    memset(iVec, 0, sizeof(iVec));
		    step = (dir)? 4: 5;  /* no ivec for ECB */
		    }
		else
		    ++step;
		}
	    break;

	case 3: /* IV = xxxx */
	    copy_line(ibuf, rfp);
	    if (fips_strncasecmp(ibuf, "IV = ", 5) != 0)
		{
		printf("Missing IV\n");
		err = 1;
		}
	    else
		{
		len = hex2bin((char*)ibuf+5, iVec);
		if (len < 0)
		    {
		    printf("Invalid IV\n");
		    err =1;
		    break;
		    }
		PrintValue("IV", iVec, len);
		step = (dir)? 4: 5;
		}
	    break;

	case 4: /* PLAINTEXT = xxxx */
	    copy_line(ibuf, rfp);
	    if (fips_strncasecmp(ibuf, "PLAINTEXT = ", 12) != 0)
		{
		printf("Missing PLAINTEXT\n");
		err = 1;
		}
	    else
		{
		int nn = strlen(ibuf+12);
		if(!strcmp(amode,"CFB1"))
		    len=bint2bin(ibuf+12,nn-1,plaintext);
		else
		    len=hex2bin(ibuf+12, plaintext);
		if (len < 0)
		    {
		    printf("Invalid PLAINTEXT: %s", ibuf+12);
		    err =1;
		    break;
		    }
		if (len >= (int)sizeof(plaintext))
		    {
		    printf("Buffer overflow\n");
		    }
		PrintValue("PLAINTEXT", (unsigned char*)plaintext, len);
		if (strcmp(atest, "MCT") == 0)  /* Monte Carlo Test */
		    {
		    if(do_mct(amode, akeysz, aKey, iVec, 
			      dir, (unsigned char*)plaintext, len, 
			      rfp, NULL) < 0)
			err = 1;
		    }
		else
		    {
		    AESTest(&ctx, amode, akeysz, aKey, iVec, 
				  dir,  /* 0 = decrypt, 1 = encrypt */
				  plaintext, ciphertext, len);
		    OutputValue("CIPHERTEXT",ciphertext,len,rfp,
				!strcmp(amode,"CFB1"));
		    }
		step = 6;
		}
	    break;

	case 5: /* CIPHERTEXT = xxxx */
	    copy_line(ibuf, rfp);
	    if (fips_strncasecmp(ibuf, "CIPHERTEXT = ", 13) != 0)
		{
		printf("Missing KEY\n");
		err = 1;
		}
	    else
		{
		if(!strcmp(amode,"CFB1"))
		    len=bint2bin(ibuf+13,strlen(ibuf+13)-1,ciphertext);
		else
		    len = hex2bin(ibuf+13,ciphertext);
		if (len < 0)
		    {
		    printf("Invalid CIPHERTEXT\n");
		    err =1;
		    break;
		    }

		PrintValue("CIPHERTEXT", ciphertext, len);
		if (strcmp(atest, "MCT") == 0)  /* Monte Carlo Test */
		    {
		    do_mct(amode, akeysz, aKey, iVec, 
			   dir, ciphertext, len, rfp, NULL);
		    }
		else
		    {
		    AESTest(&ctx, amode, akeysz, aKey, iVec, 
				  dir,  /* 0 = decrypt, 1 = encrypt */
				  plaintext, ciphertext, len);
		    OutputValue("PLAINTEXT",(unsigned char *)plaintext,len,rfp,
				!strcmp(amode,"CFB1"));
		    }
		step = 6;
		}
	    break;

	case 6:
	    if (ibuf[0] != '\n')
		{
		err = 1;
		printf("Missing terminator\n");
		}
	    else if (strcmp(atest, "MCT") != 0)
		{ /* MCT already added terminating nl */
		copy_line(ibuf, rfp);
		}
	    step = 1;
	    break;
	    }
	}
    if (rfp)
	fclose(rfp);
    if (afp)
	fclose(afp);
    FIPS_cipher_ctx_cleanup(&ctx);
    return err;
    }

/*--------------------------------------------------
  Processes either a single file or 
  a set of files whose names are passed in a file.
  A single file is specified as:
    aes_test -f xxx.req
  A set of files is specified as:
    aes_test -d xxxxx.xxx
  The default is: -d req.txt
--------------------------------------------------*/
#ifdef FIPS_ALGVS
int fips_aesavs_main(int argc, char **argv)
#else
int main(int argc, char **argv)  {
#endif
    char *rqlist = "req.txt", *rspfile = NULL;
    FILE *fp = NULL;
    char fn[250] = "", rfn[256] = "";
    int d_opt = 1;
    fips_algtest_init();
    int res = 0;

    if(select_mode() != 0)  {
        printf("Unable to determine if CAVS or ACVP mode selected.\n");
        return -1;
    }
    if (argc > 1)  {
	    if (fips_strcasecmp(argv[1], "-d") == 0)  {
	        d_opt = 1;
    	}
	    else if (fips_strcasecmp(argv[1], "-f") == 0)  {
	        d_opt = 0;
    	}
	    else  {
	        printf("Invalid parameter: %s\n", argv[1]);
    	    return 0;
	    }
    	if (argc < 3)  {
	        printf("Missing parameter\n");
	        return 0;
	    }
    	if (d_opt)
	        rqlist = argv[2];
    	else  {
	        strcpy(fn, argv[2]);
	        rspfile = argv[3];
    	}
	}
    if (d_opt)  {
	    /* list of files (directory) */
	    if (!(fp = fopen(rqlist, "r")))  {
    	    printf("Cannot open req list file\n");
	        return -1;
	    }
    	while (fgets(fn, sizeof(fn), fp))  {
    	    strtok(fn, "\r\n");
	        strcpy(rfn, fn);
	        if (VERBOSE)
    	    	printf("Processing: %s\n", rfn);
	        if (proc_file_cavs(rfn, rspfile))  {
        		printf(">>> Processing failed for: %s <<<\n", rfn);
		        return 1;
    		}
	    }
	    fclose(fp);
	}
    else  { /* single file */
	    if (VERBOSE)
	        printf("Processing: %s\n", fn);
        if (cavs)
            res = proc_file_cavs(fn, rspfile);
        else if (acvp)
            res = proc_file_acvp(fn, rspfile);
        else
            printf("Unknown operational mode (CAVS or ACVP required).");

        if (res)
	        printf(">>> Processing failed for: %s <<<\n", fn);
	}

    return 0;
}

#endif
