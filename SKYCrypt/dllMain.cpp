#include <assert.h>
#include <FlashRuntimeExtensions.h>

#include "openssl.h"
#include "SKY2FURS.h"
#include "WinApi.h"

#include "curl.h"
#include "StrUtils.h"
#include "HexUtils.h"

char *SKYCRYPT_VER = __TIMESTAMP__;

/* curl 7.60 and openssl-1.1.0 */

FREObject ASWinExec( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	uint32_t strLength = 0;
	const uint8_t *command = NULL;
	FREResult status = FREGetObjectAsUTF8( argv[ 0 ], &strLength, &command );
		
	char *output = 0;
	int wexec = WinExec((char *)command, output);
	switch (wexec) {
	case 0:
		//all ok
		FRENewObjectFromUTF8( strlen(output), (const uint8_t*)output, &retObj );
		break;
	case 1:
		//nek error 1
		FRENewObjectFromUTF8( strlen("Error: WinExec returned error 1"), (const uint8_t*)"Error: WinExec error 1", &retObj );
		break;
	default:
		//nek unknown error
		FRENewObjectFromUTF8( strlen("Error: WinExec returned unknown error"), (const uint8_t*)"Error: WinExec returned unknown error", &retObj );
	}
		
	return retObj;
}
FREObject ASDEC2HEX( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	uint32_t strLength = 0;
	const uint8_t *decimals = NULL;
	FREResult status = FREGetObjectAsUTF8( argv[ 0 ], &strLength, &decimals );
	//make base conversion from dec to hex and store result to 
	BIGNUM *bn = NULL;
	BN_dec2bn(&bn, (const char*)decimals);
	char *hex = BN_bn2hex(bn);
	//we want small caps hex
	for(uint32_t i=0;i<strlen(hex);i++)
		hex[i]=tolower(hex[i]);
	FRENewObjectFromUTF8( strlen(hex), (const uint8_t*)hex, &retObj );
	return retObj;
}

FREObject ASHEX2DEC( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	uint32_t strLength = 0;
	const uint8_t *hex = NULL;
	FREResult status = FREGetObjectAsUTF8( argv[ 0 ], &strLength, &hex );
	//make base conversion from hex to dec and store result to 
	BIGNUM *bn = NULL;
	BN_hex2bn(&bn, (const char*) hex);
	char *dec = BN_bn2dec(bn);
	FRENewObjectFromUTF8( strlen(dec), (const uint8_t*)dec, &retObj );
	return retObj;
}

FREObject ASHEX2ARRAY( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	FREByteArray byteArray;
	uint32_t strLength = 0;
	const uint8_t * hexStr = NULL;
	FREResult status = FREGetObjectAsUTF8( argv[ 0 ], &strLength, &hexStr );

	remove_all_chars((char*)hexStr,':');

	/* buggy, if hex has 00 in front, we don't get true bytes
	BIGNUM *input = BN_new();
	int input_length = BN_hex2bn(&input, (const char*)hexStr);
	input_length = (input_length + 1) / 2; // BN_hex2bn() returns number of hex digits
	unsigned char *input_buffer = (unsigned char*)malloc(input_length);
	BN_bn2bin(input, input_buffer);
	*/

	//Get Byte Array from flash and modify it's length accordingly
	FREObject length;
	size_t byteLen = strlen((const char*)hexStr)/2;
	uint8_t *bytes = hexStringToBytes((char *)hexStr);
	FRENewObjectFromUint32(strlen((const char*)hexStr)/2, &length);
	FRESetObjectProperty(argv[1], (const uint8_t*) "length", length, NULL);
	FREAcquireByteArray(argv[1], &byteArray);
	//store hex bytes to AS byteArray
	memcpy(byteArray.bytes, bytes, strlen((const char*)hexStr)/2);
	FREReleaseByteArray(argv[1]);
	free(bytes);

	FRENewObjectFromUTF8( strlen("OK"), (const uint8_t*)"OK", &retObj );
	return retObj;
}

FREObject ASARRAY2HEX( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	FREByteArray byteArray; 
	int status; 
	status = FREAcquireByteArray(argv[0], &byteArray); 
		
	/* buggy, if bytes has 00 in front, we don't get true hex
	BIGNUM *ret = BN_new();
	BN_bin2bn(byteArray.bytes, byteArray.length, ret);
	char *hexStr = BN_bn2hex(ret);
	//we want small caps hex
	for(uint32_t i=0;i<strlen(hexStr);i++)
		hexStr[i]=tolower(hexStr[i]);
	*/

	char *hexStr = bytesToHexString(byteArray.bytes, byteArray.length);
	status = FREReleaseByteArray(argv[0]); 
	FRENewObjectFromUTF8( strlen(hexStr), (const uint8_t*)hexStr, &retObj );
	free(hexStr);

	return retObj;
}

FREObject ASsha256( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	char sha256hex[65];
	uint32_t strLength = 0;
	const uint8_t * nativeCharArray = NULL;
	FREResult status = FREGetObjectAsUTF8( argv[ 0 ], &strLength, &nativeCharArray );
	sha256sum((char*)nativeCharArray, strLength, sha256hex);
	FRENewObjectFromUTF8( strlen(sha256hex), (const uint8_t*)sha256hex, &retObj );
	return retObj;
}
FREObject ASsha256bytes( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	char sha256hex[65];
	FREByteArray byteArray; 
	int status; 
	status = FREAcquireByteArray(argv[0], &byteArray); 
	if (byteArray.length>0) {
		sha256sum((char*)byteArray.bytes, byteArray.length, sha256hex);
	} else {
		sha256sum((char*)"", 0, sha256hex);
	}
	FRENewObjectFromUTF8( strlen(sha256hex), (const uint8_t*)sha256hex, &retObj );
	status = FREReleaseByteArray(argv[0]); 
	return retObj;
}
FREObject ASmd5( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	char md5hex[33];
	uint32_t strLength = 0;
	const uint8_t * nativeCharArray = NULL;
	FREResult status = FREGetObjectAsUTF8( argv[ 0 ], &strLength, &nativeCharArray );
	md5sum((char*)nativeCharArray, strLength, md5hex);
	FRENewObjectFromUTF8( strlen(md5hex), (const uint8_t*)md5hex, &retObj );
	return retObj;
}
FREObject ASmd5file( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	char md5hex[33];
	uint32_t strLength = 0;
	const uint8_t * nativeCharArray = NULL;
	FREResult status = FREGetObjectAsUTF8( argv[ 0 ], &strLength, &nativeCharArray );
	md5file((char*)nativeCharArray, md5hex);
	FRENewObjectFromUTF8( strlen(md5hex), (const uint8_t*)md5hex, &retObj );
	return retObj;
}
FREObject ASmd5bytes( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	char md5hex[33];
	FREByteArray byteArray; 
	int status; 
	status = FREAcquireByteArray(argv[0], &byteArray); 
	if (byteArray.length>0) {
		md5sum((char*)byteArray.bytes, byteArray.length, md5hex);
	} else {
		md5sum((char*)"", 0, md5hex);
	}
	FRENewObjectFromUTF8( strlen(md5hex), (const uint8_t*)md5hex, &retObj );
	status = FREReleaseByteArray(argv[0]); 
	return retObj;
}
FREObject ASBase64encode( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	char *base64str = NULL;
	uint32_t strLength = 0;
	const uint8_t * nativeCharArray = NULL;
	FREResult status = FREGetObjectAsUTF8( argv[ 0 ], &strLength, &nativeCharArray );
		
	base64encode((const unsigned char*)nativeCharArray, strLength, &base64str);
		
	FRENewObjectFromUTF8( strlen(base64str), (const uint8_t*)base64str, &retObj );
	return retObj;
}
FREObject ASBase64encodeBytes( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREByteArray byteArray;
	FREObject retObj = NULL;
	char *base64str = NULL;
	uint32_t strLength = 0;

	FREAcquireByteArray(argv[0], &byteArray);
	base64encode((const unsigned char*)byteArray.bytes, byteArray.length, &base64str);	
	FREReleaseByteArray(argv[0]);

	FRENewObjectFromUTF8( strlen(base64str), (const uint8_t*)base64str, &retObj );
	return retObj;
}

FREObject ASBase64decode( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	FREByteArray byteArray;
	unsigned char* base64decoded;
	size_t base64decodedLength;
	uint32_t strLength = 0;
	const uint8_t * nativeCharArray = NULL;
	FREResult status = FREGetObjectAsUTF8( argv[ 0 ], &strLength, &nativeCharArray );
		
	base64decode((char*)nativeCharArray, &base64decoded, &base64decodedLength);
		
	//Get Byte Array from flash and modify it's length accordingly
	FREObject length;
	FRENewObjectFromUint32(base64decodedLength, &length);
	FRESetObjectProperty(argv[1], (const uint8_t*) "length", length, NULL);
	FREAcquireByteArray(argv[1], &byteArray);
	//store base64 decoded bytes to AS byteArray
	memcpy(byteArray.bytes, base64decoded, base64decodedLength);
	FREReleaseByteArray(argv[1]);

	FRENewObjectFromUTF8( strlen("OK"), (const uint8_t*)"OK", &retObj );
	return retObj;
}
FREObject ASSendViaCurl( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	uint32_t strLength = 0;
	const uint8_t * URL = NULL;
	const uint8_t * sendMessage = NULL;
	const uint8_t * certificatePath = NULL;
	const uint8_t * certificatePass = NULL;
	const uint8_t * userAgent = NULL;
	const uint8_t * timeOut_conn = NULL;
	const uint8_t * timeOut_read = NULL;
	const uint8_t * additionalHeaders = NULL;
	FREResult status;
	status = FREGetObjectAsUTF8( argv[ 0 ], &strLength, &URL );
	status = FREGetObjectAsUTF8( argv[ 1 ], &strLength, &sendMessage );
	status = FREGetObjectAsUTF8( argv[ 2 ], &strLength, &certificatePath );
	status = FREGetObjectAsUTF8( argv[ 3 ], &strLength, &certificatePass );
	status = FREGetObjectAsUTF8( argv[ 4 ], &strLength, &userAgent );
	status = FREGetObjectAsUTF8( argv[ 5 ], &strLength, &timeOut_conn );
	status = FREGetObjectAsUTF8( argv[ 6 ], &strLength, &timeOut_read );
	status = FREGetObjectAsUTF8( argv[ 7 ], &strLength, &additionalHeaders );
		
//		FRENewObjectFromUTF8( strlen("OejK"), (const uint8_t*)"OejK", &retObj );
//		return retObj;

	char *response = NULL; //will return data here if curlOK 0
	int curlOK = -1;
//		for (int i=0; i<10; i++) {
		curlOK = SendCurl(
			(char*)URL
			,(char*)sendMessage
			,&response
			,(char*)certificatePath
			,(char*)certificatePass
			,(char*)userAgent
			,(char*)timeOut_conn
			,(char*)timeOut_read
			,(char*)additionalHeaders
		);
//		}
	switch (curlOK) {
	case 0:
		FRENewObjectFromUTF8( strlen(response), (const uint8_t*)response, &retObj );
		break;
	default:
		char retErr[128];
		sprintf_s(retErr, "Error: Curl returned=%d", curlOK);
		FRENewObjectFromUTF8( strlen(retErr), (const uint8_t*)retErr, &retObj );
	}

	return retObj;
}

FREObject ASsignRSASHA256( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	if (!certificateParsed()) {
		const char *status = "Error: must call setCertificate('cert bas64 encoded','password of the private key')";
		FRENewObjectFromUTF8( strlen(status), (const uint8_t*)status, &retObj );
		return retObj;
	}
	char md5hex[33];
	uint32_t strLength = 0;
	const uint8_t * nativeCharArray = NULL;
	FREResult status = FREGetObjectAsUTF8( argv[ 0 ], &strLength, &nativeCharArray );
	int rsaOK = RSASign((char*)nativeCharArray, md5hex);
	switch (rsaOK) {
	case 1:
		FRENewObjectFromUTF8( strlen("Error: private key not loaded"), (const uint8_t*)"Error: private key not loaded", &retObj );
		break;
	case 2:
		FRENewObjectFromUTF8( strlen("Error: creating message digest"), (const uint8_t*)"Error: creating message digest", &retObj );
		break;
	case 3:
		FRENewObjectFromUTF8( strlen("EVP_SignInit: failed"), (const uint8_t*)"EVP_SignInit: failed", &retObj );
		break;
	case 4:
		FRENewObjectFromUTF8( strlen("EVP_SignUpdate: failed"), (const uint8_t*)"EVP_SignUpdate: failed", &retObj );
		break;
	case 5:
		FRENewObjectFromUTF8( strlen("EVP_SignFinal: failed"), (const uint8_t*)"EVP_SignFinal: failed", &retObj );
		break;
	case 0:
		FRENewObjectFromUTF8( strlen(md5hex), (const uint8_t*)md5hex, &retObj );
		break;
	default:
		FRENewObjectFromUTF8( strlen("Error: unknown"), (const uint8_t*)"Error: unknown", &retObj );
	}
	return retObj;
}

FREObject ASsignRSASHA256toB64( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	if (!certificateParsed()) {
		const char *status = "Error: must call setCertificate('cert bas64 encoded','password of the private key')";
		FRENewObjectFromUTF8( strlen(status), (const uint8_t*)status, &retObj );
		return retObj;
	}
	char *base64 = NULL;
	uint32_t strLength = 0;
	const uint8_t * nativeCharArray = NULL;
	FREResult status = FREGetObjectAsUTF8( argv[ 0 ], &strLength, &nativeCharArray );
		
	int rsaOK = RSASigntoB64((char*)nativeCharArray, &base64);
		
	switch (rsaOK) {
	case 1:
		FRENewObjectFromUTF8( strlen("Error: private key not loaded"), (const uint8_t*)"Error: private key not loaded", &retObj );
		break;
	case 2:
		FRENewObjectFromUTF8( strlen("Error: creating message digest"), (const uint8_t*)"Error: creating message digest", &retObj );
		break;
	case 3:
		FRENewObjectFromUTF8( strlen("EVP_SignInit: failed"), (const uint8_t*)"EVP_SignInit: failed", &retObj );
		break;
	case 4:
		FRENewObjectFromUTF8( strlen("EVP_SignUpdate: failed"), (const uint8_t*)"EVP_SignUpdate: failed", &retObj );
		break;
	case 5:
		FRENewObjectFromUTF8( strlen("EVP_SignFinal: failed"), (const uint8_t*)"EVP_SignFinal: failed", &retObj );
		break;
	case 0:
		FRENewObjectFromUTF8( strlen(base64), (const uint8_t*)base64, &retObj );
		break;
	default:
		FRENewObjectFromUTF8( strlen("Error: unknown"), (const uint8_t*)"Error: unknown", &retObj );
	}

	return retObj;
}

FREObject ASsetCertificate( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	char * status = NULL;
	if (argc<2) {
		status = "Error: call setCertificate('cert bas64 encoded','password of the private key')";
		FRENewObjectFromUTF8( strlen(status), (const uint8_t*)status, &retObj );
		return retObj;
	}

	//check cert and pass
	uint32_t strLength = 0;
	const uint8_t * certPath = NULL;
	FREResult status_cert = FREGetObjectAsUTF8( argv[ 0 ], &strLength, &certPath );
	if ( ( FRE_OK == status_cert ) && ( 0 < strLength ) && ( NULL != certPath ) )
	{
		NULL; //all OK
	} else {
		status = "Error: cert";
		FRENewObjectFromUTF8( strlen(status), (const uint8_t*)status, &retObj );
		return retObj;
	}
	strLength = 0;
	const uint8_t * pass = NULL;
	FREResult status_pass = FREGetObjectAsUTF8( argv[ 1 ], &strLength, &pass );
	if ( ( FRE_OK == status_pass ) && ( 0 < strLength ) && ( NULL != pass ) )
	{
		NULL; //all OK
	} else {
		status = "Error: pass";
		FRENewObjectFromUTF8( strlen(status), (const uint8_t*)status, &retObj );
		return retObj;
	}
	//try to parse certificate and populate it's details
	certDetail* certificateDetails = new certDetail();
	certificateDetails = PrepairCertificate((char*)certPath, (char*)pass);
	switch (certificateDetails->error) {
	case 1:
		FRENewObjectFromUTF8( strlen("Error: opening file"), (const uint8_t*)"Error: opening file", &retObj );
		break;
	case 2:
		FRENewObjectFromUTF8( strlen("Error: reading PKCS#12 data"), (const uint8_t*)"Error: reading PKCS#12 data", &retObj );
		break;
	case 3:
		FRENewObjectFromUTF8( strlen("Error: unlocking PKCS#12 data"), (const uint8_t*)"Error: unlocking PKCS#12 data", &retObj );
		break;
	case 4:
		FRENewObjectFromUTF8( strlen("Error: reading PKCS#12 as certificate"), (const uint8_t*)"Error: reading PKCS#12 as certificate", &retObj );
		break;
	case 0:
		//do P12 to PEM conversion of the P12 cert if the PEM file doesn't exist
		FILE *fp;
		char certPathPEM[1024];
		sprintf(certPathPEM, "%s.pem", certPath);
		if ( !(fp = fopen(certPathPEM, "rb")) ) {
			int convertOK = P122PEM((char*)certPath, (char*)pass, certPathPEM);
			switch (convertOK) {
			case 1:
				FRENewObjectFromUTF8( strlen("Error: P122PEM - opening file"), (const uint8_t*)"Error: P122PEM - opening file", &retObj );
				break;
			case 2:
				FRENewObjectFromUTF8( strlen("Error: P122PEM - reading PKCS#12 data"), (const uint8_t*)"Error: P122PEM - reading PKCS#12 data", &retObj );
				break;
			case 3:
				FRENewObjectFromUTF8( strlen("Error: P122PEM - unlocking PKCS#12 data"), (const uint8_t*)"Error: P122PEM - unlocking PKCS#12 data", &retObj );
				break;
			case 4:
				FRENewObjectFromUTF8( strlen("Error: P122PEM - writing PEM data"), (const uint8_t*)"Error: P122PEM - writing PEM data", &retObj );
				break;
			case 0:
				//all ok, let's NOT fill in retObj, we check if it is empty later down and if it is empty, we parse the cert
				break;
			default:
				FRENewObjectFromUTF8( strlen("Error: unknown converting to PEM"), (const uint8_t*)"Error: unknown converting to PEM", &retObj );
				break;
			}
		}
		break;
	default:
		FRENewObjectFromUTF8( strlen("Error: unknown"), (const uint8_t*)"Error: unknown", &retObj );
	}

	//we haven't any error so far... let's parse the certificate and return proper values
	if (retObj==NULL) {
		int retJSON_len = _scprintf(
			"{\"subject_name\":\"%s\", \"issuer_name\":\"%s\", \"serial\":\"%s\", \"not_after\":\"%s\"}"
			,str_replace(certificateDetails->subject_name,"\\xC2\\xB4","´")
			,certificateDetails->issuer_name
			,certificateDetails->serial
			,certificateDetails->not_after
			);
		char *retJSON = (char *)malloc(retJSON_len + 1);
		sprintf(retJSON
			,"{\"subject_name\":\"%s\", \"issuer_name\":\"%s\", \"serial\":\"%s\", \"not_after\":\"%s\"}"
			,str_replace(certificateDetails->subject_name,"\\xC2\\xB4","´")
			,certificateDetails->issuer_name
			,certificateDetails->serial
			,certificateDetails->not_after
		);
		FRENewObjectFromUTF8( strlen(retJSON), (const uint8_t*)retJSON, &retObj );
		free(retJSON);
	}

	//should be OK on success
	return retObj;
}
FREObject ASversion( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	FREObject retObj = NULL;
	FRENewObjectFromUTF8( strlen(SKYCRYPT_VER), (const uint8_t*)SKYCRYPT_VER, &retObj );
	return retObj;
}

FREObject ASHello( FREContext ctx, void* funcData, uint32_t argc, FREObject argv[] )
{
	// What this function does: reads a string passed in from ActionScript,
	// outputs it to the console, then sends it back to ActionScript.

	// This enumerator helps keep track of the parameters
	// we expect from ActionScript and their order. 
	// Not technically necessary, but a good habit:
	// saves you havhavnig to remember which parameter you should access as argv[ 3 ].
	enum 
	{
		ARG_STRING_ARGUMENT = 0,
		ARG_COUNT
	};

	// Another good habit, though not a requirement:
	// ARG_COUNT will have the value of the number of arguments you expect.
	// The assertion will fire (in a debug build) to tell you
	// if you mistakenly passed the wrong number of arguments
	// from ActionScritpt.
	assert( ARG_COUNT == argc );

	// Read the ActionScript String object, packed here as a FREObject,
	// into a character array:
	uint32_t strLength = 0;
	const uint8_t * nativeCharArray = NULL;
	FREResult status = FREGetObjectAsUTF8( argv[ ARG_STRING_ARGUMENT ], &strLength, &nativeCharArray );

	FREObject retObj;

	if ( ( FRE_OK == status ) && ( 0 < strLength ) && ( NULL != nativeCharArray ) )
	{
		// Read the characters into a c string... 
		//std::string nativeString( ( const char * ) nativeCharArray );

		// ...and output it into the console to see what we received:
		//std::stringstream  stros;
		//stros << "This is the string we received from ActionScript: ";
		//stros << nativeString;

		// Now let's put the characters back into a FREObject...
		FRENewObjectFromUTF8( strLength, nativeCharArray, &retObj );
	}

	// ... and send them back to ActionScript:
	return retObj;
}
extern "C" {
	void contextInitializer( 
		void					 * extData, 
		const uint8_t			 * ctxType, 
		FREContext				   ctx, 
		uint32_t				 * numFunctionsToSet, 
		const FRENamedFunction	** functionsToSet )
	{
		// Create mapping between function names and pointers in an array of FRENamedFunction.
		// These are the functions that you will call from ActionScript -
		// effectively the interface of your native library.
		// Each member of the array contains the following information:
		// { function name as it will be called from ActionScript,
		//   any data that should be passed to the function,
		//   a pointer to the implementation of the function in the native library }
		static FRENamedFunction extensionFunctions[] =
		{
			{ (const uint8_t*) "as_Hello", NULL, &ASHello }
			,{ (const uint8_t*) "as_version", NULL, &ASversion }
			,{ (const uint8_t*) "as_md5", NULL, &ASmd5 }
			,{ (const uint8_t*) "as_md5file", NULL, &ASmd5file }
			,{ (const uint8_t*) "as_md5bytes", NULL, &ASmd5bytes }
			,{ (const uint8_t*) "as_sha256", NULL, &ASsha256 }
			,{ (const uint8_t*) "as_sha256bytes", NULL, &ASsha256bytes }
			,{ (const uint8_t*) "as_setCertificate", NULL, &ASsetCertificate }
			,{ (const uint8_t*) "as_signRSASHA256", NULL, &ASsignRSASHA256 }
			,{ (const uint8_t*) "as_signRSASHA256toB64", NULL, &ASsignRSASHA256toB64 }
			,{ (const uint8_t*) "as_base64encode", NULL, &ASBase64encode }
			,{ (const uint8_t*) "as_base64encodeBytes", NULL, &ASBase64encodeBytes }
			,{ (const uint8_t*) "as_base64decode", NULL, &ASBase64decode }
			,{ (const uint8_t*) "as_sendViaCurl", NULL, &ASSendViaCurl }
			,{ (const uint8_t*) "as_DEC2HEX", NULL, &ASDEC2HEX }
			,{ (const uint8_t*) "as_HEX2DEC", NULL, &ASHEX2DEC }
			,{ (const uint8_t*) "as_hex2Array", NULL, &ASHEX2ARRAY }
			,{ (const uint8_t*) "as_array2Hex", NULL, &ASARRAY2HEX }
			,{ (const uint8_t*) "as_WinExec", NULL, &ASWinExec }
		};

		// Tell AIR how many functions there are in the array:
		*numFunctionsToSet = sizeof( extensionFunctions ) / sizeof( FRENamedFunction );

		// Set the output parameter to point to the array we filled in:
		*functionsToSet = extensionFunctions;
	}
	void contextFinalizer(FREContext ctx)
	{
		curl_global_cleanup();
		return;
	}

	__declspec(dllexport) void ExtensionInitializer(void** extData, FREContextInitializer* ctxInitializer, FREContextFinalizer* ctxFinalizer)
	{
		initOpenSSL();

		*ctxInitializer = &contextInitializer; // The name of function that will intialize the extension context
		*ctxFinalizer = &contextFinalizer; // The name of function that will finalize the extension context
	}

	__declspec(dllexport) void ExtensionFinalizer(void* extData)
	{
		return;
	}
}