/* crypto/dsa/dsa_lib.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* Original version from Steven Schoch <schoch@sheba.arc.nasa.gov> */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/asn1.h>
#include <openssl/engine.h>

const char *DSA_version="DSA" OPENSSL_VERSION_PTEXT;

static DSA_METHOD *default_DSA_method = NULL;
static int dsa_meth_num = 0;
static STACK_OF(CRYPTO_EX_DATA_FUNCS) *dsa_meth = NULL;

void DSA_set_default_openssl_method(DSA_METHOD *meth)
{
	ENGINE *e;
	/* We'll need to notify the "openssl" ENGINE of this
	 * change too. We won't bother locking things down at
	 * our end as there was never any locking in these
	 * functions! */
	if(default_DSA_method != meth)
		{
		default_DSA_method = meth;
		e = ENGINE_by_id("openssl");
		if(e)
			{
			ENGINE_set_DSA(e, meth);
			ENGINE_free(e);
			}
		}
}

DSA_METHOD *DSA_get_default_openssl_method(void)
{
	if(!default_DSA_method) default_DSA_method = DSA_OpenSSL();
	return default_DSA_method;
}

DSA *DSA_new(void)
{
	return DSA_new_method(NULL);
}

#if 0
DSA_METHOD *DSA_set_method(DSA *dsa, DSA_METHOD *meth)
{
        DSA_METHOD *mtmp;
        mtmp = dsa->meth;
        if (mtmp->finish) mtmp->finish(dsa);
        dsa->meth = meth;
        if (meth->init) meth->init(dsa);
        return mtmp;
}
#else
int DSA_set_method(DSA *dsa, ENGINE *engine)
	{
	ENGINE *mtmp;
	DSA_METHOD *meth;
	mtmp = dsa->engine;
	meth = ENGINE_get_DSA(mtmp);
	if (!ENGINE_init(engine))
		return 0;
	if (meth->finish) meth->finish(dsa);
	dsa->engine = engine;
	meth = ENGINE_get_DSA(engine);
	if (meth->init) meth->init(dsa);
	/* SHOULD ERROR CHECK THIS!!! */
	ENGINE_finish(mtmp);
	return 1;
	}
#endif


#if 0
DSA *DSA_new_method(DSA_METHOD *meth)
#else
DSA *DSA_new_method(ENGINE *engine)
#endif
	{
	DSA_METHOD *meth;
	DSA *ret;

	ret=(DSA *)OPENSSL_malloc(sizeof(DSA));
	if (ret == NULL)
		{
		DSAerr(DSA_F_DSA_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	if(engine)
		ret->engine = engine;
	else
		{
		if((ret->engine=ENGINE_get_default_DSA()) == NULL)
			{
			OPENSSL_free(ret);
			return NULL;
			}
		}
	meth = ENGINE_get_DSA(ret->engine);
	ret->pad=0;
	ret->version=0;
	ret->write_params=1;
	ret->p=NULL;
	ret->q=NULL;
	ret->g=NULL;

	ret->pub_key=NULL;
	ret->priv_key=NULL;

	ret->kinv=NULL;
	ret->r=NULL;
	ret->method_mont_p=NULL;

	ret->references=1;
	ret->flags=meth->flags;
	CRYPTO_new_ex_data(dsa_meth,ret,&ret->ex_data);
	if ((meth->init != NULL) && !meth->init(ret))
		{
		CRYPTO_free_ex_data(dsa_meth,ret,&ret->ex_data);
		OPENSSL_free(ret);
		ret=NULL;
		}
	
	return(ret);
	}

void DSA_free(DSA *r)
	{
	DSA_METHOD *meth;
	int i;

	if (r == NULL) return;

	i=CRYPTO_add(&r->references,-1,CRYPTO_LOCK_DSA);
#ifdef REF_PRINT
	REF_PRINT("DSA",r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"DSA_free, bad reference count\n");
		abort();
		}
#endif

	meth = ENGINE_get_DSA(r->engine);
	if(meth->finish) meth->finish(r);
	ENGINE_finish(r->engine);

	CRYPTO_free_ex_data(dsa_meth, r, &r->ex_data);

	if (r->p != NULL) BN_clear_free(r->p);
	if (r->q != NULL) BN_clear_free(r->q);
	if (r->g != NULL) BN_clear_free(r->g);
	if (r->pub_key != NULL) BN_clear_free(r->pub_key);
	if (r->priv_key != NULL) BN_clear_free(r->priv_key);
	if (r->kinv != NULL) BN_clear_free(r->kinv);
	if (r->r != NULL) BN_clear_free(r->r);
	OPENSSL_free(r);
	}

int DSA_size(DSA *r)
	{
	int ret,i;
	ASN1_INTEGER bs;
	unsigned char buf[4];

	i=BN_num_bits(r->q);
	bs.length=(i+7)/8;
	bs.data=buf;
	bs.type=V_ASN1_INTEGER;
	/* If the top bit is set the asn1 encoding is 1 larger. */
	buf[0]=0xff;	

	i=i2d_ASN1_INTEGER(&bs,NULL);
	i+=i; /* r and s */
	ret=ASN1_object_size(1,i,V_ASN1_SEQUENCE);
	return(ret);
	}

int DSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
	     CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
        {
	dsa_meth_num++;
	return(CRYPTO_get_ex_new_index(dsa_meth_num-1,
		&dsa_meth,argl,argp,new_func,dup_func,free_func));
        }

int DSA_set_ex_data(DSA *d, int idx, void *arg)
	{
	return(CRYPTO_set_ex_data(&d->ex_data,idx,arg));
	}

void *DSA_get_ex_data(DSA *d, int idx)
	{
	return(CRYPTO_get_ex_data(&d->ex_data,idx));
	}

#ifndef NO_DH
DH *DSA_dup_DH(DSA *r)
	{
	/* DSA has p, q, g, optional pub_key, optional priv_key.
	 * DH has p, optional length, g, optional pub_key, optional priv_key.
	 */ 

	DH *ret = NULL;

	if (r == NULL)
		goto err;
	ret = DH_new();
	if (ret == NULL)
		goto err;
	if (r->p != NULL) 
		if ((ret->p = BN_dup(r->p)) == NULL)
			goto err;
	if (r->q != NULL)
		ret->length = BN_num_bits(r->q);
	if (r->g != NULL)
		if ((ret->g = BN_dup(r->g)) == NULL)
			goto err;
	if (r->pub_key != NULL)
		if ((ret->pub_key = BN_dup(r->pub_key)) == NULL)
			goto err;
	if (r->priv_key != NULL)
		if ((ret->priv_key = BN_dup(r->priv_key)) == NULL)
			goto err;

	return ret;

 err:
	if (ret != NULL)
		DH_free(ret);
	return NULL;
	}
#endif
