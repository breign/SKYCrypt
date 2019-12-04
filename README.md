# SKYCrypt
ANE extension using openssl &amp; curl for TLS and other crypto "intensive" stuff.

Win32 dll.

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
