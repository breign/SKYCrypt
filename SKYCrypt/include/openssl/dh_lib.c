/* crypto/dh/dh_lib.c */
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

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/engine.h>

const char *DH_version="Diffie-Hellman" OPENSSL_VERSION_PTEXT;

static DH_METHOD *default_DH_method = NULL;
static int dh_meth_num = 0;
static STACK_OF(CRYPTO_EX_DATA_FUNCS) *dh_meth = NULL;

void DH_set_default_openssl_method(DH_METHOD *meth)
{
	ENGINE *e;
	/* We'll need to notify the "openssl" ENGINE of this
	 * change too. We won't bother locking things down at
	 * our end as there was never any locking in these
	 * functions! */
	if(default_DH_method != meth)
		{
		default_DH_method = meth;
		e = ENGINE_by_id("openssl");
		if(e)
			{
			ENGINE_set_DH(e, meth);
			ENGINE_free(e);
			}
		}
}

DH_METHOD *DH_get_default_openssl_method(void)
{
	if(!default_DH_method) default_DH_method = DH_OpenSSL();
	return default_DH_method;
}

#if 0
DH_METHOD *DH_set_method(DH *dh, DH_METHOD *meth)
{
        DH_METHOD *mtmp;
        mtmp = dh->meth;
        if (mtmp->finish) mtmp->finish(dh);
        dh->meth = meth;
        if (meth->init) meth->init(dh);
        return mtmp;
}
#else
int DH_set_method(DH *dh, ENGINE *engine)
{
	ENGINE *mtmp;
	DH_METHOD *meth;
	mtmp = dh->engine;
	meth = ENGINE_get_DH(mtmp);
	if (!ENGINE_init(engine))
		return 0;
	if (meth->finish) meth->finish(dh);
	dh->engine= engine;
	meth = ENGINE_get_DH(engine);
	if (meth->init) meth->init(dh);
	/* SHOULD ERROR CHECK THIS!!! */
	ENGINE_finish(mtmp);
	return 1;
}
#endif

DH *DH_new(void)
{
	return DH_new_method(NULL);
}

#if 0
DH *DH_new_method(DH_METHOD *meth)
#else
DH *DH_new_method(ENGINE *engine)
#endif
	{
	DH_METHOD *meth;
	DH *ret;
	ret=(DH *)OPENSSL_malloc(sizeof(DH));

	if (ret == NULL)
		{
		DHerr(DH_F_DH_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	if(engine)
		ret->engine = engine;
	else
		{
		if((ret->engine=ENGINE_get_default_DH()) == NULL)
			{
			OPENSSL_free(ret);
			return NULL;
			}
		}
	meth = ENGINE_get_DH(ret->engine);
	ret->pad=0;
	ret->version=0;
	ret->p=NULL;
	ret->g=NULL;
	ret->length=0;
	ret->pub_key=NULL;
	ret->priv_key=NULL;
	ret->q=NULL;
	ret->j=NULL;
	ret->seed = NULL;
	ret->seedlen = 0;
	ret->counter = NULL;
	ret->method_mont_p=NULL;
	ret->references = 1;
	ret->flags=meth->flags;
	CRYPTO_new_ex_data(dh_meth,ret,&ret->ex_data);
	if ((meth->init != NULL) && !meth->init(ret))
		{
		CRYPTO_free_ex_data(dh_meth,ret,&ret->ex_data);
		OPENSSL_free(ret);
		ret=NULL;
		}
	return(ret);
	}

void DH_free(DH *r)
	{
	DH_METHOD *meth;
	int i;
	if(r == NULL) return;
	i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_DH);
#ifdef REF_PRINT
	REF_PRINT("DH",r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"DH_free, bad reference count\n");
		abort();
	}
#endif

	meth = ENGINE_get_DH(r->engine);
	if(meth->finish) meth->finish(r);
	ENGINE_finish(r->engine);

	CRYPTO_free_ex_data(dh_meth, r, &r->ex_data);

	if (r->p != NULL) BN_clear_free(r->p);
	if (r->g != NULL) BN_clear_free(r->g);
	if (r->q != NULL) BN_clear_free(r->q);
	if (r->j != NULL) BN_clear_free(r->j);
	if (r->seed) OPENSSL_free(r->seed);
	if (r->counter != NULL) BN_clear_free(r->counter);
	if (r->pub_key != NULL) BN_clear_free(r->pub_key);
	if (r->priv_key != NULL) BN_clear_free(r->priv_key);
	OPENSSL_free(r);
	}

int DH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
	     CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
        {
	dh_meth_num++;
	return(CRYPTO_get_ex_new_index(dh_meth_num-1,
		&dh_meth,argl,argp,new_func,dup_func,free_func));
        }

int DH_set_ex_data(DH *d, int idx, void *arg)
	{
	return(CRYPTO_set_ex_data(&d->ex_data,idx,arg));
	}

void *DH_get_ex_data(DH *d, int idx)
	{
	return(CRYPTO_get_ex_data(&d->ex_data,idx));
	}

int DH_size(DH *dh)
	{
	return(BN_num_bytes(dh->p));
	}
