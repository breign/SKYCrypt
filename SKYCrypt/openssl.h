#include "openssl/pkcs12.h"
#include "openssl/opensslv.h"
#include <string.h>
#include <fstream>


void initOpenSSL();

void md5sum(char* _in_buffer, size_t _in_buffer_len, char* _out_buffer);
void md5file(char* filename, char* _out_buffer);

int base64encode(const unsigned char* buffer, size_t length, char** b64text);
int base64decode(char* b64message, unsigned char** buffer, size_t* length);
static char* base64_bytes(int size, char *input);

void sha256sum(char *_in_buffer, size_t _in_buffer_len, char* _out_buffer);
void sha256file(char *filename, char* _out_buffer);

bool certificateParsed();

int P122PEM(char* _file_path,char* _file_password,char* _out_file_path);

typedef struct {
	int error;
	char *subject_name;
	char *issuer_name;
	char *serial;
	char *not_after;
} certDetail;

certDetail* PrepairCertificate(char* _file_path, char* _file_password);

int RSASign(char* _in_buffer, char *_out_buffer_md5);
int RSASigntoB64(char* _in_buffer, char **_out_buffer_base64_encoded);

int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len);

