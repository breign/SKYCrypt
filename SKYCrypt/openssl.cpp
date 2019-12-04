#include <assert.h>
#include <string>
#include <sstream>

#include <Windows.h>

#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/pkcs12.h"
#include "openssl/opensslv.h"
#include "openssl/md5.h"

#include "openssl.h"

#include "StrUtils.h"


BOOL CERT_PARSED = FALSE;
EVP_PKEY *pkey = NULL;

void initOpenSSL() {
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
}

bool certificateParsed() {
	if (CERT_PARSED) 
		return TRUE;
	return false;
}

int P122PEM(char* _file_path,char* _file_password,char* _out_file_path) {
	EVP_PKEY *pkey;
	X509 *cert;
	STACK_OF(X509) *ca = NULL;
	PKCS12 *p12;
	int i;

	BIO *in = BIO_new_file(_file_path, "rb");
	p12 = d2i_PKCS12_bio(in, NULL);
	if (!p12) {
		//Error reading PKCS#12 data
		return 2;
	}
	if (!PKCS12_parse(p12, _file_password, &pkey, &cert, &ca)) {
		//Error unlocking PKCS#12 data
		return 3;
	}
	PKCS12_free(p12);

	BIO *out;
	out = BIO_new_file(_out_file_path, "w");
	if (!out) {
		//Error writing _out_file_path
		return 4;
	}
	if (pkey) {
		//fprintf(fp, "***Private Key***\n");
		//using no password
		//PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL);
		PEM_write_bio_PrivateKey(out, pkey, EVP_des_ede3_cbc(), NULL, 0, NULL, _file_password);
	}
	if (cert) {
		//fprintf(fp, "***User Certificate***\n");
		PEM_write_bio_X509_AUX(out, cert);
	}
	if (ca && sk_X509_num(ca)) {
		//fprintf(fp, "***Other Certificates***\n");
		for (i = 0; i < sk_X509_num(ca); i++) 
			PEM_write_bio_X509_AUX(out, sk_X509_value(ca, i));
			//PEM_write_X509() for unencrypted cert - not trusted
	}

	sk_X509_pop_free(ca, X509_free);
	X509_free(cert);
	EVP_PKEY_free(pkey);

	BIO_free(out);
	return 0;
}

certDetail* PrepairCertificate(char* _file_path,char* _file_password) {

	X509 *cert;
	STACK_OF(X509) *ca = NULL;
	PKCS12 *p12;
	certDetail *retval = new certDetail();

	BIO *in = BIO_new_file(_file_path, "rb");
	p12 = d2i_PKCS12_bio(in, NULL);
	if (!p12) {
		//Error reading PKCS#12 data
		retval->error = 2;
		return retval;
	}

	//store pkey to global here
	if (!PKCS12_parse(p12, _file_password, &pkey, &cert, &ca)) {
		//Error unlocking PKCS#12 data
		retval->error = 3;
		return retval;
	}

	PKCS12_free(p12);
	// populate certificate details
	if (cert) {
		//get subject
		char buf[256];
		char *_out_buffer;

		//get subject
		X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
		buf[strlen(buf)]='\0';
		//char _out_buffer[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
		_out_buffer = str_replace(buf, "/", ", ");
		retval->subject_name = (char *)malloc(sizeof(char)*strlen(_out_buffer)+1);
		strcpy(retval->subject_name, _out_buffer);
//		free(_out_buffer);

		//get issuer
		X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
		buf[strlen(buf)]='\0';
		//char _out_buffer[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
		_out_buffer = str_replace(buf, "/", ", ");
		retval->issuer_name = (char *)malloc(sizeof(char)*strlen(_out_buffer)+1);
		strcpy(retval->issuer_name, _out_buffer);

		//get valid before and not_after
		//ASN1_TIME *not_before = X509_get_notBefore(cert);
		ASN1_TIME *not_after = X509_get_notAfter(cert);
		char not_after_str[128];
		convert_ASN1TIME(not_after, not_after_str, 128);
		not_after_str[strlen(not_after_str)]='\0';
		retval->not_after = (char *)malloc(sizeof(char)*strlen(not_after_str)+1);
		strcpy(retval->not_after, not_after_str);

		//get serial - is BIGNUM integer
		ASN1_INTEGER *serial = X509_get_serialNumber(cert);
		BIGNUM *bnser = ASN1_INTEGER_to_BN(serial, NULL);
		BIGNUM *bn = NULL;
		BN_hex2bn(&bn, (const char*) BN_bn2hex(bnser));
		char *dec = BN_bn2dec(bn);
		retval->serial = (char *)malloc(sizeof(char)*strlen(dec)+1);
		strcpy(retval->serial, dec);

		//free
		BN_free(bn);
		X509_free(cert);
		free(_out_buffer);
	} else {
		//Error retrieving certificate
		retval->error = 4;
		return retval;
	}
	CERT_PARSED = TRUE;
	return retval;

}

int RSASign(char* _in_buffer, char *_out_buffer_md5) {
	if (pkey == NULL) 
		return 1;

	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	const EVP_MD *md = EVP_get_digestbyname("SHA256");
	if (!md) {
		//Error creating message digest
		ERR_print_errors_fp(stderr);
		return 2;
	}
	if (!EVP_SignInit(ctx, md)) {
		//EVP_SignInit: failed
		return 3;
	}
	if (!EVP_SignUpdate(ctx, _in_buffer, strlen(_in_buffer))) {
		//EVP_SignUpdate: failed
		return 4;
	}
	unsigned int sig_len;
	unsigned char *sig = (unsigned char *)malloc(EVP_PKEY_size(pkey)+1);

	if (!EVP_SignFinal(ctx, sig, &sig_len, pkey)){
		//EVP_SignFinal: failed
		free(sig);
		return 5;
	}

	//we have to use this MD5 implementation here
	unsigned char result[MD5_DIGEST_LENGTH];
	MD5(sig, sig_len, result);
	int i;
	for(i=0; i < MD5_DIGEST_LENGTH; i++) {
		char temp[3];
		sprintf_s(temp,"%02x",result[i]);
		if (i == 0)
			strncpy(_out_buffer_md5,temp,3);
		else
			strncat(_out_buffer_md5,temp,MD5_DIGEST_LENGTH);
	}
	_out_buffer_md5[32] = '\0';

	OPENSSL_free(ctx);
	free(sig);

	return 0;
}

int RSASigntoB64(char* _in_buffer, char **_out_buffer_base64_encoded) {
	if (pkey == NULL) 
		return 1;

	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	const EVP_MD *md = EVP_get_digestbyname("SHA256");
	if (!md) {
		//Error creating message digest
		ERR_print_errors_fp(stderr);
		return 2;
	}
	if (!EVP_SignInit(ctx, md)) {
		//EVP_SignInit: failed
		return 3;
	}
	if (!EVP_SignUpdate(ctx, _in_buffer, strlen(_in_buffer))) {
		//EVP_SignUpdate: failed
		return 4;
	}
	unsigned int sig_len;
	unsigned char *sig = (unsigned char *)malloc(EVP_PKEY_size(pkey)+1);

	if (!EVP_SignFinal(ctx, sig, &sig_len, pkey)){
		//EVP_SignFinal: failed
		free(sig);
		return 5;
	}

	//base64 encode rsa signed bytes
	char *b64 = base64_bytes(sig_len, (char*)sig);
	*_out_buffer_base64_encoded = (char *)malloc(sizeof(char)*strlen(b64)+1);
	sprintf(*_out_buffer_base64_encoded, "%s", b64);

	OPENSSL_free(ctx);
	free(sig);

	return 0;
}

void md5sum(char* _in_buffer, size_t _in_buffer_len, char* _out_buffer) {
	unsigned char digest[MD5_DIGEST_LENGTH];
	MD5_CTX ctx;
	char md5string[33];
	MD5_Init(&ctx);
	MD5_Update(&ctx, _in_buffer, _in_buffer_len); 
	MD5_Final(digest, &ctx);
	for(int i = 0; i < MD5_DIGEST_LENGTH; ++i)
		sprintf(&md5string[i*2], "%02x", (unsigned int)digest[i]);
	memcpy(_out_buffer, md5string, 33);
	_out_buffer[33] = 0;
	OPENSSL_cleanse(&ctx,sizeof(ctx));
}

void md5file(char* filename, char* _out_buffer) {
	unsigned char digest[MD5_DIGEST_LENGTH];
	int i;
	MD5_CTX ctx;
	char md5string[33];
	int bytes;
	FILE *inFile = fopen (filename, "rb");
	unsigned char data[4096];
	if (inFile == NULL) {
		//filename can't be opened
		sprintf(_out_buffer, "Error: %s can't be opened", filename);
		return;
	}
	MD5_Init (&ctx);
	while ((bytes = fread (data, 1, 4096, inFile)) != 0)
	MD5_Update (&ctx, data, bytes);
	MD5_Final (digest,&ctx);
	for(i = 0; i < MD5_DIGEST_LENGTH; i++) 
		sprintf(&md5string[i*2], "%02x", (unsigned int)digest[i]);
	memcpy(_out_buffer, md5string, 33);
	_out_buffer[33] = 0;
}

/**
	* Use tihs function only for string encoding, for bytes, use base64_bytes below
	*/
int base64encode(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
	BIO *bio, *b64;
	BUF_MEM *bufferPtr64;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_write(bio, "\0", 1);
	BIO_get_mem_ptr(bio, &bufferPtr64);
	
	*b64text = (char *)malloc(sizeof(char)*bufferPtr64->length+1);
	sprintf(*b64text, "%s", bufferPtr64->data);

	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	return (0); //success
}

static char* base64_bytes(int size, char *input) {
	char *buff = (char*)malloc(size + 1);
	char *bytes = NULL;
	BIO *b64, *out;
	BUF_MEM *bptr;

	// Create a base64 filter/sink
	if ((b64 = BIO_new(BIO_f_base64())) == NULL)
		return NULL;

	// Create a memory source
	if ((out = BIO_new(BIO_s_mem())) == NULL) 
		return NULL;

	// Chain them
	out = BIO_push(b64, out);
	BIO_set_flags(out, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line

	// Write the bytes
	BIO_write(out, input, size);
	BIO_flush(out);

	// Now remove the base64 filter
	out = BIO_pop(b64);

	// Write the null terminating character
	BIO_write(out, "\0", 1);
	BIO_get_mem_ptr(out, &bptr);

	// Allocate memory for the output and copy it to the new location
	bytes = (char*)malloc(bptr->length);
	strncpy(bytes, bptr->data, bptr->length);

	// Cleanup
	BIO_set_close(out, BIO_CLOSE);
	BIO_free_all(out);
	free(buff);

	return bytes;
}

size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len-1] == '=') //last char is =
		padding = 1;

	return (len*3)/4 - padding;
}
int base64decode(char* b64message, unsigned char** buffer, size_t* length) { //Decodes a base64 encoded string
	BIO *bio, *b64;
		
	remove_all_chars(b64message,'\n');
	int decodeLen = calcDecodeLength(b64message);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	*length = BIO_read(bio, *buffer, strlen(b64message));
	assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
	BIO_free_all(bio);

	return (0); //success
}
void sha256sum(char *_in_buffer, size_t _in_buffer_len, char* _out_buffer) {
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	char sha256string[65];
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, _in_buffer, _in_buffer_len);
	SHA256_Final(digest, &ctx);
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(&sha256string[i*2], "%02x", (unsigned int)digest[i]);
	memcpy(_out_buffer, sha256string, 65);
	_out_buffer[65] = 0;
	OPENSSL_cleanse(&ctx,sizeof(ctx));
}

int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len) {
	int rc;
	BIO *b = BIO_new(BIO_s_mem());
	rc = ASN1_TIME_print(b, t);
	if (rc <= 0) {
		BIO_free(b);
		return EXIT_FAILURE;
	}
	rc = BIO_gets(b, buf, len);
	if (rc <= 0) {
		BIO_free(b);
		return EXIT_FAILURE;
	}
	BIO_free(b);
	return EXIT_SUCCESS;
}
