// SKY2FURS.cpp : Defines the entry point for the console application.
//

#include "curl.h"

//#define MY_DEBUG

struct string {
	char *ptr;
	size_t len;
};

void init_string(struct string *s) {
	s->len = 0;
	s->ptr = (char*)malloc(s->len+1);
	if (s->ptr == NULL) {
		fprintf(stderr, "malloc() failed\n");
		exit(EXIT_FAILURE);
	}
	s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
	size_t new_len = s->len + size*nmemb;
	s->ptr = (char*)realloc(s->ptr, new_len+1);
	if (s->ptr == NULL) {
		fprintf(stderr, "realloc() failed\n");
		exit(EXIT_FAILURE);
	}
	memcpy(s->ptr+s->len, ptr, size*nmemb);
	s->ptr[new_len] = '\0';
	s->len = new_len;

	return size*nmemb;
}

int SendCurl(char* URL, char* message, char** response
				, char* certificatePath, char*certificatePass, char* userAgent, char* timeOut_conn, char* timeOut_read, char* additionalHeaders
	) {

#ifdef MY_DEBUG
	FILE *file_debug=NULL;
	file_debug = fopen("C:\\Users\\Breign\\Documents\\skypos-tls.log", "a+");
	curl_version_info_data * vinfo = curl_version_info( CURLVERSION_NOW );
	if( vinfo->features & CURL_VERSION_SSL ) {
		fprintf(file_debug,"INFO: USING OpenSSL support, version: ");
		fprintf(file_debug,vinfo->ssl_version);
		fprintf(file_debug,"\n");
	} else {
		fprintf(file_debug,"WARNING: NO OpenSSL support\n");
	}
#endif

	CURL *c_hd;
	CURLcode res;
	struct curl_slist *headers_list = NULL;

	struct string s;
	init_string(&s);

	curl_global_init(CURL_GLOBAL_ALL);
	c_hd = curl_easy_init();

	curl_easy_setopt(c_hd, CURLOPT_URL,				URL);
	curl_easy_setopt(c_hd, CURLOPT_NOPROGRESS,		1);
	curl_easy_setopt(c_hd, CURLOPT_POST,			1);
	curl_easy_setopt(c_hd, CURLOPT_POSTFIELDS,		message);
	curl_easy_setopt(c_hd, CURLOPT_POSTFIELDSIZE,	strlen(message));
	(strlen(userAgent)) ? curl_easy_setopt(c_hd, CURLOPT_USERAGENT,	userAgent) : curl_easy_setopt(c_hd, CURLOPT_USERAGENT, "");
	(timeOut_conn) ? curl_easy_setopt(c_hd, CURLOPT_CONNECTTIMEOUT, atoi(timeOut_conn)) : curl_easy_setopt(c_hd, CURLOPT_CONNECTTIMEOUT, atoi("5"));
	(timeOut_read) ? curl_easy_setopt(c_hd, CURLOPT_TIMEOUT, atoi(timeOut_read)) : curl_easy_setopt(c_hd, CURLOPT_TIMEOUT, atoi("10"));
	if (additionalHeaders) {
		headers_list = curl_slist_append(headers_list,	additionalHeaders);
		curl_easy_setopt(c_hd, CURLOPT_HTTPHEADER,		headers_list);
	}
	if (certificatePath) {
		curl_easy_setopt(c_hd, CURLOPT_SSLKEY,		certificatePath);
		curl_easy_setopt(c_hd, CURLOPT_SSLCERT,		certificatePath);
		curl_easy_setopt(c_hd, CURLOPT_KEYPASSWD,	certificatePass);
	}
	curl_easy_setopt(c_hd, CURLOPT_WRITEFUNCTION,	writefunc);
	curl_easy_setopt(c_hd, CURLOPT_WRITEDATA,		&s);
	curl_easy_setopt(c_hd, CURLOPT_SSL_VERIFYHOST,	0);
	curl_easy_setopt(c_hd, CURLOPT_SSL_VERIFYPEER,	0);
	curl_easy_setopt(c_hd, CURLOPT_SSL_VERIFYSTATUS,0);
	curl_easy_setopt(c_hd, CURLOPT_FOLLOWLOCATION,	1);
//	curl_easy_setopt(c_hd, CURLOPT_SSL_CIPHER_LIST, "ALL:!EXPORT:!EXPORT40:!EXPORT56:!aNULL:!LOW:!RC4:!SSLv3:@STRENGTH");
	curl_easy_setopt(c_hd, CURLOPT_SSLVERSION,		CURL_SSLVERSION_TLSv1_2);

#ifdef MY_DEBUG
	curl_easy_setopt(c_hd, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(c_hd, CURLOPT_STDERR, file_debug);
#endif // DEBUG


//	curl_easy_setopt(c_hd, CURLOPT_SSLCERT,			"C:\\Users\\Breign\\Documents\\Visual Studio 2012\\Projects\\SKYCrypt\\Debug\\cert.pem");
//	curl_easy_setopt(c_hd, CURLOPT_SSLCERTPASSWD,		"4564561");
	res = curl_easy_perform(c_hd);

	if ( res != CURLE_OK) {
		curl_slist_free_all(headers_list);
		curl_easy_cleanup(c_hd);
#ifdef MY_DEBUG
		fclose(file_debug);
#endif  // DEBUG
		return res;
	}
	*response = (char *)malloc(sizeof(char)*s.len+1);
	sprintf(*response, "%s", s.ptr);

	curl_slist_free_all(headers_list);
	curl_easy_cleanup(c_hd);
#ifdef MY_DEBUG
	fclose(file_debug);
#endif // DEBUG

	return 0;

}
