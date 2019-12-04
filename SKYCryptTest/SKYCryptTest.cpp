// SKYCryptTest.cpp : Defines the entry point for the console application.
//
#include <Windows.h>
#include "stdafx.h"
#include <afx.h>

#include <afxwin.h> // MFC core and standard components

#include <afxext.h> // MFC extensions

int _tmain(int argc, _TCHAR* argv[])
{
	
    wprintf(L"Main, loading library\n");
    HMODULE h = LoadLibrary(L"SKYCrypt.dll");
    if (h)
    {
        wprintf(L"Main, freeing library\n");
        FreeLibrary(h);
    }

    wprintf(L"Main, exiting\n");
	
	return 0;
}

