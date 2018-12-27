#define STRSAFE_LIB

/*************************************************************************************************************************************/
//	gcfc - Gape cleaner & filler console utility ver. 1.0.0.1
//	Options:
//		-V(erbose)			-		verbose output
//		-C(lean)			-		clean gapes between sections (default filler is 0x00)
//		-F(iller):Value		-		set user defined filler value (byte)
//		-S(um)				-		calculate PE image checksum
/*************************************************************************************************************************************/

#include <Windows.h>
#include <strsafe.h>
#include "resource.h"
#include <shlwapi.h>
#include <Softpub.h>
#include <mscat.h>
#include <Aclapi.h>
#include <ImageHlp.h>
#include <Psapi.h>
#include "MsgTbl.h"
#include <Wincrypt.h>
#pragma hdrstop

#pragma comment(lib, "Version.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Imagehlp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Crypt32.lib")

#ifndef MAX_KEY_LENGTH
#define MAX_KEY_LENGTH								255
#endif

#ifndef MAX_VALUE_NAME
#define MAX_VALUE_NAME								16383
#endif

#define CONSOLE_PROCESS_LIST_LAMBDA					16UL

//	Keys' names definitions for event logging
const __wchar_t lpwszEventMessageFile[] = L"EventMessageFile";
const __wchar_t lpwszTypesSupported[] = L"TypesSupported";
const __wchar_t lpwszCategoryMessageFile[] = L"CategoryMessageFile";
const __wchar_t lpwszCategoryCount[] = L"CategoryCount";
const __wchar_t lpwszEventLoggerRootKey[] = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application";

//	Idents for display version info
const __wchar_t lpwszProductIdent[] = L"\\StringFileInfo\\040004b0\\ProductIdent";
const __wchar_t lpwszFileDescription[] = L"\\StringFileInfo\\040004b0\\FileDescription";
const __wchar_t lpwszFileVersion[] = L"\\StringFileInfo\\040004b0\\FileVersion";
const __wchar_t lpwszLegalCopyright[] = L"\\StringFileInfo\\040004b0\\LegalCopyright";

//	Types for utility
typedef enum
{
	nbOct,
	nbDec,
	nbHex
}
E_NOTATION_BASE;

#define MEM_PARAGRAPH_SIZE							16
#define DISPOSE_BUF(p)								DisposeBuffer(reinterpret_cast<void**>((p)));

/******************************************************************************************/
/*   Function name: DisposeBuffer                                                         */
/*   Description: Release memory buffer to process default heap                           */
/*   Parameters:                                                                          */
/*      [in, out] lppArray (type of void**) - pointer to buffer's pointer                 */
/******************************************************************************************/
void DisposeBuffer(__inout void** lppArray)
{
	HANDLE hDefHeap(::GetProcessHeap());
	if (hDefHeap && lppArray && *lppArray)
	{
		if (::HeapFree(hDefHeap, 0, *lppArray))
			*lppArray = nullptr;
	}
}

/******************************************************************************************/
/*   Function name: AllocBufferEx                                                         */
/*   Description: Allocate memory buffer from process default heap                        */
/*   Parameters:                                                                          */
/*      [in] dwNewArrayLen (type DWORD) - items total in buffer                           */
/*      [in] dwItemSize (type DWORD) - size of item                                       */
/*      [in, out] lppArray (type of void**) - pointer to buffer's pointer                 */
/*   Side effects: Release buffer pointed to by (*lppArray)                               */
/******************************************************************************************/
bool AllocBufferEx(__in DWORD dwNewArrayLen, __in DWORD dwItemSize, __inout void** lppArray)
{
	bool fbDone(false);
	HANDLE hDefHeap(::GetProcessHeap());
	if (hDefHeap && lppArray)
	{
		if (*lppArray)
			DisposeBuffer(lppArray);

		if (!(*lppArray) && dwNewArrayLen && dwItemSize)
		{
			*lppArray = ::HeapAlloc(hDefHeap, HEAP_ZERO_MEMORY, dwNewArrayLen * dwItemSize);
			if (*lppArray)
				fbDone = true;
		}
	}
	return fbDone;
}

/******************************************************************************************/
/*   Function name: [inline] AllocBuffer                                                  */
/*   Description: Helper for DWORD[] buffers                                              */
/******************************************************************************************/
__inline bool AllocBuffer(__in DWORD dwNewArrayLen, __inout LPDWORD* lpdwArray)
{
	return AllocBufferEx(dwNewArrayLen, sizeof(DWORD), reinterpret_cast<void**>(lpdwArray));
}

/******************************************************************************************/
/*   Function name: IsFileDigitallySigned                                                 */
/*   Description: Performs trust verification action on specified PE image                */
/*   Parameters:                                                                          */
/*      [in] wszFilePath (type __wchar_t*) - full PE image name                           */
/*      [in, opt] hFile (type HANDLE) - PE image file name (in case of exist)             */
/******************************************************************************************/
bool IsFileDigitallySigned(__in __notnull __wchar_t* wszFilePath, __in_opt HANDLE hFile)
{
    PVOID Context;
    HANDLE FileHandle(hFile);
	BOOL fbNeedToClose(FALSE);
    DWORD HashSize(0);
    PBYTE Buffer;
    PVOID CatalogContext;
	CATALOG_INFO InfoStruct = { 0 };
	WINTRUST_DATA WintrustStructure = { 0 };
	WINTRUST_CATALOG_INFO WintrustCatalogStructure = { 0 };
	WINTRUST_FILE_INFO WintrustFileStructure = { 0 };
    __wchar_t* MemberTag;
    bool ReturnFlag(false);
    ULONG ReturnVal;
    GUID ActionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	HANDLE hProcessHeap(::GetProcessHeap());
	if (!hProcessHeap)
		return false;

    //	Zero structures.

    InfoStruct.cbStruct = sizeof(CATALOG_INFO);
    WintrustCatalogStructure.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
    WintrustFileStructure.cbStruct = sizeof(WINTRUST_FILE_INFO);

    //	Get a context for signature verification.

    if (!::CryptCATAdminAcquireContext(&Context, nullptr, 0))
        return false;

    //	Open file.
	if (!FileHandle)
	{
		FileHandle = ::CreateFileW(wszFilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);	// 7
		fbNeedToClose = TRUE;
	}

    if (INVALID_HANDLE_VALUE == FileHandle)
    {
       ::CryptCATAdminReleaseContext(Context, 0);
		return false;
    }

    //	Get the size we need for our hash.
    ::CryptCATAdminCalcHashFromFileHandle(FileHandle, &HashSize, nullptr, 0);
    if (HashSize == 0)
    {
		//0-sized has means error!
        ::CryptCATAdminReleaseContext(Context, 0);
		if (fbNeedToClose)
			::CloseHandle(FileHandle); 
		return false;
    }

    //	Allocate memory.
    Buffer = reinterpret_cast<PBYTE>(::HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, HashSize));

    //	Actually calculate the hash
    if (!::CryptCATAdminCalcHashFromFileHandle(FileHandle, &HashSize, Buffer, 0))
    {
		::CryptCATAdminReleaseContext(Context, 0);
		::HeapFree(hProcessHeap, 0, Buffer);
		if (fbNeedToClose)
			::CloseHandle(FileHandle);
		return false;
    }
	   
    //	Convert the hash to a string.
    MemberTag = reinterpret_cast<PWCHAR>(::HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, ((HashSize * 2) + 1) * sizeof(__wchar_t)));
    for (unsigned int i = 0; i < HashSize; i++)
        //swprintf(&MemberTag[i * 2], L"%02X", Buffer[i]);
		::StringCchPrintfW(&MemberTag[i * 2], 3, L"%02X", Buffer[i]);

    //	Get catalog for our context.
    CatalogContext = ::CryptCATAdminEnumCatalogFromHash(Context, Buffer, HashSize, 0, nullptr);

    if (CatalogContext)
    {
            //If we couldn�t get information
        if (!::CryptCATCatalogInfoFromContext(CatalogContext, &InfoStruct, 0))
        {
            //Release the context and set the context to null so it gets picked up below.
            ::CryptCATAdminReleaseCatalogContext(Context, CatalogContext, 0); 
			CatalogContext = nullptr;
        }
    }

    //	If we have a valid context, we got our info.
    //	Otherwise, we attempt to verify the internal signature.

    if (!CatalogContext)
    {
        WintrustFileStructure.cbStruct = sizeof(WINTRUST_FILE_INFO);
        WintrustFileStructure.pcwszFilePath = wszFilePath;
        WintrustFileStructure.hFile = nullptr;
        WintrustFileStructure.pgKnownSubject = nullptr;
        WintrustStructure.cbStruct = sizeof(WINTRUST_DATA);
        WintrustStructure.dwUnionChoice = WTD_CHOICE_FILE;
        WintrustStructure.pFile = &WintrustFileStructure;
        WintrustStructure.dwUIChoice = WTD_UI_NONE;
        WintrustStructure.fdwRevocationChecks = WTD_REVOKE_NONE;
        WintrustStructure.dwStateAction = WTD_STATEACTION_IGNORE;
        WintrustStructure.dwProvFlags = WTD_SAFER_FLAG;
        WintrustStructure.hWVTStateData = nullptr;
        WintrustStructure.pwszURLReference = nullptr;
    }
    else
    {
        //	If we get here, we have catalog info! Verify it.
        WintrustStructure.cbStruct = sizeof(WINTRUST_DATA);
        WintrustStructure.pPolicyCallbackData = 0;
        WintrustStructure.pSIPClientData = 0;
        WintrustStructure.dwUIChoice = WTD_UI_NONE;
        WintrustStructure.fdwRevocationChecks = WTD_REVOKE_NONE;
        WintrustStructure.dwUnionChoice = WTD_CHOICE_CATALOG;
        WintrustStructure.pCatalog = &WintrustCatalogStructure;
        WintrustStructure.dwStateAction = WTD_STATEACTION_VERIFY;
        WintrustStructure.hWVTStateData = nullptr;
        WintrustStructure.pwszURLReference = nullptr;
        WintrustStructure.dwProvFlags = 0;
        WintrustStructure.dwUIContext = WTD_UICONTEXT_EXECUTE;

        //	Fill in catalog info structure.
        WintrustCatalogStructure.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
        WintrustCatalogStructure.dwCatalogVersion = 0;
        WintrustCatalogStructure.pcwszCatalogFilePath = InfoStruct.wszCatalogFile;
        WintrustCatalogStructure.pcwszMemberTag = MemberTag;
        WintrustCatalogStructure.pcwszMemberFilePath = wszFilePath;
        WintrustCatalogStructure.hMemberFile = nullptr;
    }

    //	Call verification function.
    ReturnVal = ::WinVerifyTrust(0, &ActionGuid, &WintrustStructure);

    //	Check return.
	if (0  == ReturnVal)
		ReturnFlag = true;

    //	Free context.
    if (CatalogContext) 
		::CryptCATAdminReleaseCatalogContext(Context, CatalogContext, 0);

    //	If we successfully verified - we need to free.
    if (ReturnFlag)
    {
		WintrustStructure.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(0, &ActionGuid, &WintrustStructure);
    } 

    //	Free memory.
    ::HeapFree(hProcessHeap, 0, MemberTag);
    ::HeapFree(hProcessHeap, 0, Buffer);

	if (fbNeedToClose)
		::CloseHandle(FileHandle);

    ::CryptCATAdminReleaseContext(Context, 0);
    return ReturnFlag;
}

/******************************************************************************************/
/*   Function name: LoadErrorMessageW                                                     */
/*   Description: Loads system error message for error code being passed                  */
/*   Parameters:                                                                          */
/*      [in] LangID (type LANGID) - Language ID for message text                          */
/*      [in] dwOSErrorCode (type DWORD) - System error code value                         */
/*      [in] lpwszErrorMsgBuf (type __wchar_t*) - Buffer for message text                 */
/*      [in] ncBufLen (type size_t) - Size of buffer for message text                     */
/******************************************************************************************/
bool LoadErrorMessageW(__in LANGID LangID, __in DWORD dwOSErrorCode, __out __wchar_t* lpwszErrorMsgBuf, __in size_t ncBufLen)
{
	bool fbDone(false);
	if (lpwszErrorMsgBuf && ncBufLen)
	{
		LPVOID lpMsgBuf(nullptr);	

		if ((dwOSErrorCode >= 12000) && (dwOSErrorCode <= 12174))
			::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
			::GetModuleHandleW(L"WININET.DLL"), dwOSErrorCode, LangID, reinterpret_cast<LPWSTR>(&lpMsgBuf), 0, nullptr);
		else
			::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr, dwOSErrorCode, LangID, reinterpret_cast<LPWSTR>(&lpMsgBuf), 0, nullptr);

		if (lpMsgBuf)
		{
			 fbDone = SUCCEEDED(::StringCchCopyW(lpwszErrorMsgBuf, ncBufLen, reinterpret_cast<__wchar_t*>(lpMsgBuf)));
			::LocalFree(lpMsgBuf);
		}
	}

	return (fbDone);
}

/******************************************************************************************/
/*   Function name: StrLen                                                                */
/*   Description: Wrapper for StringCchLengthW                                            */
/*   Parameters:                                                                          */
/*      [in] lpwszStr (type __wchar_t*) - Pointer to string buffer                        */
/*   Returen value:                                                                       */
/*      String length in chars (type size_t)                                              */
/******************************************************************************************/
size_t StrLen(__in __wchar_t* const lpwszStr)
{
	size_t cnStrLen(0);
	if (lpwszStr)
		::StringCchLengthW(lpwszStr, STRSAFE_MAX_CCH, &cnStrLen);
	return (cnStrLen);
}

/******************************************************************************************/
/*   Function name: LoadStringEx                                                          */
/*   Description: Enhanced version of LoadStringW function                                */
/*   !Important: function may crachs if invalid string ID is passed                       */
/*   Parameters:                                                                          */
/*      [in] hInstance (type HINSTANCE) - String table container instance                 */
/*      [in] dwMessageID (type DWORD) - Target string ID                                  */
/*      [in] wLangID (type WORD) - Language ID for resource                               */
/*   Returen value:                                                                       */
/*      Pointer to null-terminated string (type __wchar_t*)                               */
/******************************************************************************************/
__wchar_t* LoadStringEx(__in HINSTANCE hInstance, __in DWORD dwMessageID, __in WORD wLangID)
{
	__wchar_t* lpStr(nullptr);
	//	Find resource ...
	HRSRC hResource(::FindResourceExW(hInstance, RT_STRING, MAKEINTRESOURCEW(dwMessageID / 16 + 1), wLangID));
	if (hResource) 
	{
		//	Locate resource ...
		HGLOBAL hGlobal(::LoadResource(hInstance, hResource));
		if (hGlobal) 
		{
			const __wchar_t* pwszRes(reinterpret_cast<const __wchar_t*>(::LockResource(hGlobal)));
			if (pwszRes) 
			{
				//	Locate valid string bunch ...
				for (DWORD i = 0; i < (dwMessageID & 15); i++) 
					pwszRes += 1 + *(WORD*)(pwszRes);

				//	Allocate string buffer and copy string ...
				if (AllocBufferEx(*reinterpret_cast<WORD*>(const_cast<__wchar_t*>(pwszRes)) + 1, sizeof(__wchar_t), reinterpret_cast<void**>(&lpStr)) && lpStr != nullptr) 
				{
					lpStr[*reinterpret_cast<WORD*>(const_cast<__wchar_t*>(pwszRes))] = L'\0';
					::CopyMemory(lpStr, pwszRes + 1, *reinterpret_cast<WORD*>(const_cast<__wchar_t*>(pwszRes)) * sizeof(__wchar_t));
				}

				UnlockResource(pwszRes);
			}
			::FreeResource(hGlobal);
		}
	} 
	return lpStr;
}

/******************************************************************************************/
/*   Function name: ReleaseLoadedString                                                   */
/*   Description: Helper for __wchar_t* buffers                                           */
/******************************************************************************************/
void ReleaseLoadedString(__in __wchar_t* const lpwszString)
{
	void* lpBuffer(reinterpret_cast<void*>(const_cast<__wchar_t*>(lpwszString)));
	DISPOSE_BUF(&lpBuffer)
}

/******************************************************************************************/
/*   Function name: ShowString                                                            */
/*   Description: Copy null-terminates string to console with current console's           */ 
/*      attributes                                                                        */
/*   Parameters:                                                                          */
/*      [in] hStdOut (type HANDLE) - Console handle                                       */
/*      [in] lpwszString (type __wchar_t*) - Pointer to string buffer                     */
/*   Returen value:                                                                       */
/*      Total written chars (type size_t)                                                 */
/******************************************************************************************/
size_t ShowString(__in HANDLE hStdOut, __in __nullterminated __wchar_t* const lpwszString)
{
	DWORD dwWritten(0);
	if (hStdOut && lpwszString)
		::WriteConsoleW(hStdOut, lpwszString, StrLen(lpwszString), &dwWritten, nullptr);
	return dwWritten;
}

/******************************************************************************************/
/*   Function name: ShowStringEx                                                          */
/*   Description: Copy null-terminates string to console with specified console's         */ 
/*      attributes                                                                        */
/*   Parameters:                                                                          */
/*      [in] hStdOut (type HANDLE) - Console handle                                       */
/*      [in] lpwszString (type __wchar_t*) - Pointer to string buffer                     */
/*      [in] wForeAttr (type WORD) - Foreground color                                     */
/*      [in] wBackAttr (type WORD) - Background color                                     */
/*   Returen value:                                                                       */
/*      Total written chars (type size_t)                                                 */
/******************************************************************************************/
size_t ShowStringEx(__in HANDLE hStdOut, __in __nullterminated __wchar_t* const lpwszString, __in WORD wForeAttr, __in WORD wBackAttr)
{
	DWORD dwWritten(0);
	if (hStdOut && lpwszString)
	{
		CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
		if (::GetConsoleScreenBufferInfo(hStdOut, &csbi) && ::SetConsoleTextAttribute(hStdOut, wForeAttr | wBackAttr))
		{
			dwWritten = ShowString(hStdOut, lpwszString);
			::SetConsoleTextAttribute(hStdOut, csbi.wAttributes);
		}
	}
	return dwWritten;
}

/******************************************************************************************/
/*   Function name: ShowResourceString                                                    */
/*   Description: Locate string resource, copy it to console with specified console's     */ 
/*      attributes                                                                        */
/*   Parameters:                                                                          */
/*      [in] hStdOut (type HANDLE) - Console handle                                       */
/*      [in] dwStringID (type DWORD) - String resource ID                                 */
/*      [in] wLangID (type LANGID) - Resource language ID                                 */
/******************************************************************************************/
void ShowResourceString(__in HANDLE hStdOut, __in DWORD dwStringID, __in LANGID wLangID)
{
	HMODULE hModule(::GetModuleHandleW(nullptr));

	if (hStdOut && hModule)
	{
		__wchar_t* lpwszResString(LoadStringEx(hModule, dwStringID, wLangID));
		if (lpwszResString)
		{
			ShowString(hStdOut, lpwszResString);
			ReleaseLoadedString(lpwszResString);
		}
	}
}

/******************************************************************************************/
/*   Function name: ShowResourceString                                                    */
/*   Description: Locate string resource and use it as template to format string,         */
/*      copy it to console with specified console's attributes                            */ 
/*   Parameters:                                                                          */
/*      [in] hStdOut (type HANDLE) - Console handle                                       */
/*      [in] dwStringID (type DWORD) - String template resource ID                        */
/*      [in] wLangID (type LANGID) - Resource language ID                                 */
/*      [in] __VA_ARGS__ - passed variable arguments                                      */
/******************************************************************************************/
void ShowResourceStringArgs(__in HANDLE hStdOut, __in DWORD dwStringID, __in LANGID wLangID, ...)
{
	va_list argptr;
	va_start(argptr, wLangID);

	HMODULE hModule(::GetModuleHandleW(nullptr));

	if (hStdOut && hModule)
	{
		__wchar_t* lpwszResString(LoadStringEx(hModule, dwStringID, wLangID));
		if (lpwszResString)
		{
			__wchar_t szOutStr[2 * MAX_PATH] = { 0 };
			if (SUCCEEDED(::StringCchVPrintfW(szOutStr, 2 * MAX_PATH, lpwszResString, argptr)))
				ShowString(hStdOut, szOutStr);
			ReleaseLoadedString(lpwszResString);
		}
	}
	va_end(argptr);
}

void ShowUsage(__in HANDLE hStdOut)
{
	if (hStdOut)
	{
		__wchar_t* lpwszUsageStr(LoadStringEx(::GetModuleHandleW(nullptr), IDS_USAGE_STRING, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)));
		if (lpwszUsageStr)
		{
			CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
			BOOL fbRestoreConAttr(FALSE);
			fbRestoreConAttr = ::GetConsoleScreenBufferInfo(hStdOut, &csbi) && ::SetConsoleTextAttribute(hStdOut, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);

			ShowString(hStdOut, lpwszUsageStr);
			ReleaseLoadedString(lpwszUsageStr);

			if (fbRestoreConAttr)
				::SetConsoleTextAttribute(hStdOut, csbi.wAttributes);
		}
	}
}

/******************************************************************************************/
/*   Function name: IsUserAdmin                                                           */
/*   Description: Return true in case of process is being created under administator SID  */
/*   For use in verbose mode                                                              */
/******************************************************************************************/
bool IsUserAdmin(void)
{
	bool fbAdmin(false);
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup; 
	BOOL b(::AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)); 
	if(b) 
	{
		if (::CheckTokenMembership(nullptr, AdministratorsGroup, &b))
			fbAdmin = true;
		::FreeSid(AdministratorsGroup); 
	}
	return(fbAdmin);
}

/******************************************************************************************/
/*   Function name: GetElevationType                                                      */
/*   Description: Return process token's elevation type value                             */
/*   For use in verbose mode                                                              */
/******************************************************************************************/
TOKEN_ELEVATION_TYPE GetElevationType(void) 
{
    HANDLE hToken(nullptr); 
    TOKEN_ELEVATION_TYPE type((TOKEN_ELEVATION_TYPE) 0);
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
        TOKEN_ELEVATION_TYPE ElevationType;
        DWORD cbSize = sizeof(TOKEN_ELEVATION_TYPE);
        if (::GetTokenInformation(hToken, TokenElevationType, &ElevationType, sizeof(ElevationType), &cbSize))
			type = ElevationType;
    }

    if (hToken) 
		::CloseHandle(hToken);

    return type;
}

/******************************************************************************************/
/*   Function name: FileExists                                                            */
/*   Description: Check file existence                                                    */
/*   Parameters:                                                                          */
/*      [in] lpwszFileName (type __wchar_t* const) - File name buffer pointer             */
/******************************************************************************************/
bool FileExists(__in __nullterminated __wchar_t* const lpwszFileName)
{
	bool fbFileExists(false);
	HANDLE hFile(::CreateFileW(lpwszFileName, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
	if (INVALID_HANDLE_VALUE != hFile)
	{
		::CloseHandle(hFile);
		fbFileExists = true;
	}
	return (fbFileExists);
}

/******************************************************************************************/
/*   Function name: TryStrToByteW                                                         */
/*   Description: Attempts convert string to byte value                                   */
/*      Byte value description may be:                                                    */ 
/*         0x__(16), 0X__(16), __h(16), __H(16) - hexadecimal patterns                    */
/*         0___(8) - octal pattern                                                        */
/*          ___(10), ___d(10), ___D(10) - decimal patterns                                */
/*   Parameters:                                                                          */
/*      [in] wszString (type __wchar_t* const) - String to be analyzed                    */
/*      [out] byValue (type BYTE&) - Byte value                                           */
/*   Returns: true if succeeded.                                                          */
/*   Function does not throw exception in case of incorrect string passed.                */
/******************************************************************************************/
bool TryStrToByteW(__in __nullterminated __wchar_t* const wszString, __out_opt BYTE& byValue)
{
	bool fbCompleted(false);
	size_t nStrLen(0);
	if (wszString && 0 != (nStrLen = StrLen(wszString)))
	{
		E_NOTATION_BASE Base(nbDec);

		__wchar_t* wszStart(const_cast<__wchar_t*>(wszString));
		__wchar_t wszHexadecimal[] = L"0123456789ABCDEF";
		int iaHexadecimal[] = {	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15	};
		__wchar_t wszDecimal[] = L"0123456789";
		__wchar_t wszOctal[] = L"01234567";
		//	Filler patterns:
		//	0x__(16) | 0X__(16) | __h(16) | __H(16) | 0___(8) | ___(10) | ___d(10) | ___D(10)
		//	First char is '0', so it may be 0__, 0x___, 0X___
		if (1 < nStrLen)
		{
			if (wszString[0] == L'0')
			{
				wszStart++;
				nStrLen--;
				Base = nbOct;							
				//	Check for 0x | 0X
				if (L'X' == wszString[0] || L'x' == wszString[0])
				{
					wszStart++;
					nStrLen--;
					Base = nbHex;						
				}
			}
			//	Check last symbol
			if (nStrLen)
			{
				if (nbHex != Base)
				{
					switch(wszStart[nStrLen - 1])
					{
					case L'H':
					case L'h':
						//	Hexadecimal notation
						nStrLen--;
						Base = nbHex;						
						break;
					case L'D':
					case L'd':
						//	Decimal notation
						nStrLen--;
						Base = nbDec;						
						break;
					}
				}
				if (nStrLen)
				{
					//	Unwrap filler value
					unsigned int nValue(0);
					bool fbInvalidSymbol(false);
					__wchar_t* wszPos(nullptr);
					for (size_t nIndex(0); nIndex < nStrLen; ++nIndex)
					{
						switch(Base)
						{
						case nbDec:
							if (nullptr != (wszPos = ::StrChrW(&wszDecimal[0], wszStart[nIndex])))
								nValue = 10 * nValue + (wszPos[0] - L'0');
							else
								fbInvalidSymbol = true;
							break;
						case nbHex:
							if (nullptr != (wszPos = ::StrChrIW(&wszHexadecimal[0], wszStart[nIndex])))
								nValue = 16 * nValue + iaHexadecimal[wszPos - wszHexadecimal];
							else
								fbInvalidSymbol = true;
							break;
						case nbOct:
							if (nullptr != (wszPos = ::StrChrW(&wszOctal[0], wszStart[nIndex])))
								nValue = 8 * nValue + (wszPos[0] - L'0');
							else
								fbInvalidSymbol = true;
							break;
						}
						if (fbInvalidSymbol)
							break;
					}

					if (!fbInvalidSymbol && (nValue < 256))
					{
						byValue = LOBYTE(LOWORD(nValue));
						fbCompleted = true;
					}
				}
			}
		}
		else
		{
			//	nStrLen == 1
			__wchar_t* wszPos(nullptr);
			if (nullptr != (wszPos = ::StrChrW(&wszDecimal[0], wszString[0])))
			{
				byValue = static_cast<BYTE>(wszPos[0] - L'0');
				fbCompleted = true;
			}
		}
	}
	return (fbCompleted);
}

/******************************************************************************************/
/*   Function name: CheckOptArguments                                                     */
/*   Description: Checks command line arguments                                           */
/*   Parameters:                                                                          */
/*      [in] nArgsCount(type int) - Total arguments                                       */
/*      [in] argv (type __wchar_t** const) - Arguments vector                             */
/*      [out] nInvalidOptNo (type int&) - Invalid option number                           */
/*      [out] nInvalidCharIndex (type int&) - Invalid char index                          */
/*      [out] fbVerbose (type bool&) - Verbose mode flag is found                         */
/*      [out] fbClean (type bool&) - Clean mode flag is found                             */
/*      [out] byFiller (type BYTE&) - Filler value                                        */
/*      [out] fbChecksum (type BYTE&) - Checksum recalculate flag is found                */
/*   Returns: true if succeeded.                                                          */
/******************************************************************************************/
bool CheckOptArguments(__in int nArgsCount, __in __wchar_t** const argv, __out_opt int& nInvalidOptNo, __out_opt int& nInvalidCharIndex, __out_opt bool& fbVerbose, __out_opt bool& fbClean, __out_opt BYTE& byFiller, __out_opt bool& fbChecksum)
{
	bool fbStatus(true);

	bool fbPreSymbol(false);		//	Symbols: /\-
	bool fbVerboseMode(false);
	bool fbCleanMode(false);
	bool fbFillerPassed(false);
	BYTE byFillerCustomValue(0);
	bool fbCheckSumTest(false);

	int nInvOpt(-1);
	int nInvalidSymbol(-1);

	__wchar_t szCustomFiller[MAX_PATH] = { 0 };
	int nFillerIndex(0);

	for (int i(0); i < nArgsCount; ++i)
	{
		size_t nArgLineLen(StrLen(argv[i]));
		if (nArgLineLen)
			for (size_t nCharIndex(0); nCharIndex < nArgLineLen; ++nCharIndex)
			{
				if (argv[i][nCharIndex] != L' ')
				{
					switch(argv[i][nCharIndex])
					{
					case L'/':
					case L'\\':
					case L'-':
						fbPreSymbol = true;
						continue;
					}
					if (fbPreSymbol)
					{
						switch(argv[i][nCharIndex])
						{
						case L'V':
						case L'v':
							//	Verbose mode
							fbPreSymbol = false;
							if (!fbVerboseMode)
								fbVerboseMode = true;
							else		//	Duplicated option. Return error.
							{
								fbStatus = false;
								nInvOpt = i;
								nInvalidSymbol = static_cast<int>(nCharIndex);
							}
							break;
						case L'S':
						case L's':
							//	Calculate checksum
							fbPreSymbol = false;
							if (!fbCheckSumTest)
								fbCheckSumTest = true;
							else		//	Duplicated option. Return error.
							{
								fbStatus = false;
								nInvOpt = i;
								nInvalidSymbol = static_cast<int>(nCharIndex);
							}
							break;

						case L'c':
						case L'C':
							//	Clean mode
							fbPreSymbol = false;
							if (!fbCleanMode)
								fbCleanMode = true;
							else		//	Duplicated option. Return error.
							{
								fbStatus = false;
								nInvOpt = i;
								nInvalidSymbol = static_cast<int>(nCharIndex);
							}
							break;
						case L'f':
						case L'F':
							//	Filler value is passed
							fbPreSymbol = false;
							if (!fbFillerPassed)
							{
								fbFillerPassed = true;
								//	Keep going parsing for filler value ...
								bool fbFillerDelimiterSymbol(false);
								for (nCharIndex++; nCharIndex < nArgLineLen; ++nCharIndex)
									if ((L' ' == argv[i][nCharIndex]) || (L':' == argv[i][nCharIndex]))
									{
										if (L' ' == argv[i][nCharIndex])
											continue;
										else
										{
											if (!fbFillerDelimiterSymbol)
												fbFillerDelimiterSymbol = true;
											else	//	Dulicated delimiter
											{
												fbStatus = false;
												nInvOpt = i;
												nInvalidSymbol = static_cast<int>(nCharIndex);
												break;
											}
										}
									}
									else
										break;
								//	Filler may be:
								//	0xYZ(16) | 0XYZ(16) | XYh(16) | XYH(16) | 0ABC(8) | ABC(10) | ABCd(10) | ABCD(10)
								//	Just copy symbols to buffer
								bool fbFillerCopied(false);
								if (fbStatus)
								{
									for (; nCharIndex < nArgLineLen; ++nCharIndex)
										switch(argv[i][nCharIndex])
										{
										case L'/':
										case L'\\':
										case L'-':
										case L' ':
											//	Filler is in buffer
											fbFillerCopied = true;
											break;
										default:
											szCustomFiller[nFillerIndex++] = argv[i][nCharIndex];
											break;
										}
									if (TryStrToByteW(szCustomFiller, byFillerCustomValue))
										fbFillerPassed = true;
									else
									{
										fbStatus = false;
										nInvOpt = i;
										nInvalidSymbol = static_cast<int>(nCharIndex);
									}
								}
							}
							else		//	Duplicated option. Return error.
							{
								fbStatus = false;
								nInvOpt = i;
								nInvalidSymbol = static_cast<int>(nCharIndex);
							}
							break;
						default:
							fbStatus = false;
							nInvOpt = i;
							nInvalidSymbol = static_cast<int>(nCharIndex);
							break;
						}
					}
					else
					{
						fbStatus = false;
						nInvOpt = i;
						nInvalidSymbol = static_cast<int>(nCharIndex);
					}
				}
				if (!fbStatus)
					break;
			}
		if (!fbStatus)
			break;
	}

	if (fbStatus)
	{
		fbVerbose = fbVerboseMode;
		fbClean = fbCleanMode;
		if (fbFillerPassed)
			byFiller = byFillerCustomValue;
		fbChecksum = fbCheckSumTest;
	}
	else
	{
		nInvalidOptNo = nInvOpt;
		nInvalidCharIndex = nInvalidSymbol;
	}
	return (fbStatus);
}

/******************************************************************************************/
/*   Function name: GetCertificateDescription                                             */
/*   Description: Wrapper for CertGetNameStringW                                          */
/*   Parameters:                                                                          */
/*      [in] pCertCtx(type PCCERT_CONTEXT) - Pointer to certificate context               */
/*   Returns: Sertificate subject name as null-terminated string                          */
/******************************************************************************************/
__wchar_t* GetCertificateDescription(__in PCCERT_CONTEXT pCertCtx)
{
	DWORD dwStrType(CERT_X500_NAME_STR);
	__wchar_t* szSubjectRDN(nullptr);
	HANDLE hProcessHeap(::GetProcessHeap());
	if (hProcessHeap)
	{
		DWORD dwCount(::CertGetNameStringW(pCertCtx, CERT_NAME_RDN_TYPE, 0, &dwStrType, nullptr, 0));
		if (dwCount && AllocBufferEx(dwCount, sizeof(__wchar_t), reinterpret_cast<void**>(&szSubjectRDN)))
		{
			if (szSubjectRDN)
				::CertGetNameStringW(pCertCtx, CERT_NAME_RDN_TYPE, 0, &dwStrType, szSubjectRDN, dwCount);
		}
	}
   return szSubjectRDN;
}

/******************************************************************************************/
/*   Function name: GetFileSD                                                             */
/*   Description: Wrapper for GetSecurityInfo                                             */
/*   Parameters:                                                                          */
/*      [in] lpwszFileName(type __wchar_t* const) - File name                             */
/*      [out, opt] pFileSD(type PSECURITY_DESCRIPTOR*) - Pointer to security descriptor   */
/*      [out, opt] pACL(type PACL*) - Pointer to ACL                                      */
/*   Returns: TRUE if SD is obtained                                                      */
/******************************************************************************************/
BOOL GetFileSD(__in __nullterminated __wchar_t* const lpwszFileName, __out_opt PSECURITY_DESCRIPTOR *pFileSD, __out_opt PACL *pACL)
{
	BOOL	bRetVal(FALSE);
	SECURITY_INFORMATION secInfo(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION);

	if (lpwszFileName)
	{
		HANDLE hFile(::CreateFile(lpwszFileName, READ_CONTROL, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
		if (INVALID_HANDLE_VALUE != hFile)
		{
			bRetVal = (ERROR_SUCCESS == ::GetSecurityInfo(hFile, SE_FILE_OBJECT, secInfo, nullptr, nullptr, pACL, nullptr, pFileSD));
			::CloseHandle(hFile);
		}
	}
	return bRetVal;
}

/******************************************************************************************/
/*   Function name: CanAccessFile                                                         */
/*   Description: Wrapper for AccessCheck                                                 */
/*   Parameters:                                                                          */
/*      [in] lpwszFileName(type __wchar_t* const) - File name                             */
/*      [in] genericAccessRights(type DWORD) - generic access rights                      */
/*   Returns: TRUE if file is accessible                                                  */
/******************************************************************************************/
BOOL CanAccessFile(__in __nullterminated __wchar_t* const lpwszFileName, __in DWORD genericAccessRights)
{
	BOOL bRet(FALSE);

	if (lpwszFileName)
	{
		PACL pFileDACL(nullptr);
		PSECURITY_DESCRIPTOR pFileSD(nullptr);
		if (GetFileSD(lpwszFileName, &pFileSD, &pFileDACL))
		{
			if (!pFileDACL)
				bRet = TRUE;
			else
			{
				HANDLE hToken(nullptr);
				if (::OpenProcessToken( ::GetCurrentProcess(), TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | STANDARD_RIGHTS_READ, &hToken ))
				{
					HANDLE hImpersonatedToken(nullptr);
					if (::DuplicateToken( hToken, SecurityImpersonation, &hImpersonatedToken ))
					{
						GENERIC_MAPPING mapping = { 0xFFFFFFFF };
						PRIVILEGE_SET privileges = { 0 };
						DWORD grantedAccess = 0, privilegesLength = sizeof( privileges );

						mapping.GenericRead = FILE_GENERIC_READ;
						mapping.GenericWrite = FILE_GENERIC_WRITE;
						mapping.GenericExecute = FILE_GENERIC_EXECUTE;
						mapping.GenericAll = FILE_ALL_ACCESS;

						::MapGenericMask( const_cast<DWORD*>(&genericAccessRights), &mapping );

						if (!::AccessCheck( pFileSD, hImpersonatedToken, genericAccessRights, &mapping, &privileges, &privilegesLength, &grantedAccess, &bRet ))
							bRet = FALSE;

						::CloseHandle( hImpersonatedToken );
					}
					::CloseHandle( hToken );
				}
				if (pFileSD)
					::LocalFree(pFileSD);
			}
		}
	}
	return bRet;
}

void ShowDOSHeader(__in PIMAGE_DOS_HEADER lpImageDOSHeader, __in HANDLE hStdOut)
{
	ShowResourceString(hStdOut, IDS_MSG_DOS_HDR_CONTENT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	ShowResourceStringArgs(hStdOut, IDS_MSG_DOS_HDR_MAGIC, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImageDOSHeader ->e_magic);
	if (lpImageDOSHeader ->e_magic == IMAGE_DOS_SIGNATURE)
	{
		ShowResourceStringArgs(hStdOut, IDS_MSG_DOS_LAST_PAGE_SIZE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImageDOSHeader ->e_cblp);
		ShowResourceStringArgs(hStdOut, IDS_MSG_DOS_PAGES_TOTAL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImageDOSHeader ->e_cp);
		ShowResourceStringArgs(hStdOut, IDS_MSG_DOS_HEADER_PARA_TOTAL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImageDOSHeader ->e_cparhdr);
		ShowResourceStringArgs(hStdOut, IDS_MSG_DOS_HEADER_CHECKSUM, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImageDOSHeader ->e_csum);
		ShowResourceStringArgs(hStdOut, IDS_MSG_DOS_RELOC_TABLE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImageDOSHeader ->e_lfarlc);
		ShowResourceStringArgs(hStdOut, IDS_MSG_DOS_NEW_HDRS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImageDOSHeader ->e_lfanew);
	}
}

void ShowNTPEHeader(__in PIMAGE_NT_HEADERS lpImgNTHeader, __in HANDLE hStdOut)
{
	ShowResourceString(hStdOut, IDS_MSG_NT_PE_CONTENT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	ShowResourceStringArgs(hStdOut, IDS_MSG_NT_PE_SIG, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgNTHeader ->Signature);
}

void ShowImgFileHdr(__in PIMAGE_FILE_HEADER lpImgFileHeader, __in HANDLE hStdOut)
{
	ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CONTENT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_MACHINE_TYPE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

	switch(lpImgFileHeader ->Machine)
	{
	case IMAGE_FILE_MACHINE_I386:
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_MACHINE_TYPE_X86, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
		break;
	case IMAGE_FILE_MACHINE_IA64:
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_MACHINE_TYPE_IPF, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_MACHINE_TYPE_X64, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	default:
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_FILE_HDR_MACHINE_TYPE_UNK, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgFileHeader ->Machine);
		break;
	}

	ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_FILE_HDR_SECTIONS_TOTAL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgFileHeader ->NumberOfSections);
	if (lpImgFileHeader ->PointerToSymbolTable)
	{
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_FILE_HDR_COFF_TBL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgFileHeader ->PointerToSymbolTable);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_FILE_HDR_COFF_SYM_TOTAL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgFileHeader ->NumberOfSymbols);
	}
	else
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_NO_COFF, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

	ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_FILE_HDR_OPT_HDR_SIZE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgFileHeader ->SizeOfOptionalHeader);
	ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_FILE_HDR_CHARACTERISTICS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgFileHeader ->Characteristics);

	//	Show image characteristics

	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_NO_RELOC, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_EXEC, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_NO_COFF_LINE_NUMS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_NO_COFF_SYM_TBL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_AGGRESIVE_WS_TRIM, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_BYTES_REVERSED_LO)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_LO_BYTES_RESERVED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_32BIT_MACHINE)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_32BIT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_LARGE_ADDR_AWARE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_DEBUG_STRIPPED)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_NO_DEBUG_INFO, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_RMVBL_RUN_SWAP, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_NET_RUN_SWAP, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_SYSTEM)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_SYSTEM, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_DLL)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_DLL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_UNIPROC, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	if (lpImgFileHeader ->Characteristics & IMAGE_FILE_BYTES_REVERSED_HI)
		ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CHAR_HI_BYTES_RESERVED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
}

void ShowImgOptHdr(__in PIMAGE_OPTIONAL_HEADER lpImgOptHdr, __in HANDLE hStdOut)
{
	ShowResourceString(hStdOut, IDS_MSG_IMG_FILE_HDR_CONTENT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

	switch(lpImgOptHdr ->Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_EXE_32BIT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
		break;
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_EXE_64BIT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
		break;
	case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
		ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_EXE_ROM, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
		break;
	}

	if (IMAGE_NT_OPTIONAL_HDR64_MAGIC != lpImgOptHdr ->Magic)
	{
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_LINKER_VER, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->MajorLinkerVersion, lpImgOptHdr ->MinorLinkerVersion);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_CODE_SIZE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->SizeOfCode);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_INIT_DATA_SIZE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->SizeOfInitializedData);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_UNINIT_DATA_SIZE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->SizeOfUninitializedData);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_ENTRY_POINT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->AddressOfEntryPoint);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_CODE_BASE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->BaseOfCode);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_DATA_BASE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->BaseOfData);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_IMG_BASE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->ImageBase);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_RAM_ALIGN, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->SectionAlignment);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_FILE_ALIGN, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->FileAlignment);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_OS_REQUIRED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->MajorOperatingSystemVersion, lpImgOptHdr ->MinorOperatingSystemVersion);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_IMG_VER, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->MajorImageVersion, lpImgOptHdr ->MinorImageVersion);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_VER, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->MajorSubsystemVersion, lpImgOptHdr ->MinorSubsystemVersion);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_WIN32_VER_VALUE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->Win32VersionValue);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_ENTIRE_IMG_SIZE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->SizeOfImage);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_ALL_HDRS_SIZE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->SizeOfHeaders);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_CHECKSUM, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->CheckSum);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_REQUIRED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->Subsystem, lpImgOptHdr ->Subsystem);

		switch(lpImgOptHdr ->Subsystem)
		{
		case IMAGE_SUBSYSTEM_UNKNOWN:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_UNKNOWN, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		case IMAGE_SUBSYSTEM_NATIVE:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_NATIVE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		case IMAGE_SUBSYSTEM_WINDOWS_GUI:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_GUI, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		case IMAGE_SUBSYSTEM_WINDOWS_CUI:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_CUI, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		case IMAGE_SUBSYSTEM_OS2_CUI:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_OS2_CUI, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		case IMAGE_SUBSYSTEM_POSIX_CUI:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_POSIX_CUI, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_WIN_CE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		case IMAGE_SUBSYSTEM_EFI_APPLICATION:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_EFI, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_EFI_BOOT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_EFI_RT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		case IMAGE_SUBSYSTEM_EFI_ROM:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_EFI_ROM, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		case IMAGE_SUBSYSTEM_XBOX:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_XBOX, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_WIN_BOOT_APP, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		default:
			ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_SUBSYS_UNDEF, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			break;
		}

		if (lpImgOptHdr ->DllCharacteristics)
		{
			ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_DLL_CHARS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->DllCharacteristics);

			if (lpImgOptHdr ->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
				ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_DLL_CAN_RELOC, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			if (lpImgOptHdr ->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
				ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_DLL_FORCE_INEGRITY, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			if (lpImgOptHdr ->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
				ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_DLL_NX_COMPAT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			if (lpImgOptHdr ->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)
				ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_DLL_NO_ISOLATION, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			if (lpImgOptHdr ->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)
				ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_DLL_NO_SEH, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			if (lpImgOptHdr ->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND)
				ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_DLL_NO_BIND, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			if (lpImgOptHdr ->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
				ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_DLL_WDM, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			if (lpImgOptHdr ->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
				ShowResourceString(hStdOut, IDS_MSG_IMG_OPT_HDR_TERMSERV_AWARE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
		}
		else
			ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_DLL_NO_CHARS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->DllCharacteristics);

		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_STACK_RESERVE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->SizeOfStackReserve);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_STACK_COMMIT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->SizeOfStackCommit);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_HEAP_RESERVE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->SizeOfHeapReserve);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_HEAP_COMMIT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->SizeOfHeapCommit);
		ShowResourceStringArgs(hStdOut, IDS_MSG_IMG_OPT_HDR_DIR_ENTRIES_TOTAL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->NumberOfRvaAndSizes);
	}
}

void ShowDataDirContent(__in PIMAGE_DATA_DIRECTORY lpImgDataDir, __in DWORD dwNumberOfDataDirEntries, __in HANDLE hStdOut)
{
	CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
	BOOL fbRestoreAttr(::GetConsoleScreenBufferInfo(hStdOut, &csbi));

	if (dwNumberOfDataDirEntries)
	{
		ShowResourceString(hStdOut, IDS_MSG_DATADIR_CONTENT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
		for (DWORD ncIndex(0); ncIndex < dwNumberOfDataDirEntries; ++ncIndex)
		{
			if (fbRestoreAttr)
			{
				if (lpImgDataDir[ncIndex].VirtualAddress || lpImgDataDir[ncIndex].Size)
					::SetConsoleTextAttribute(hStdOut, csbi.wAttributes);
				else
					::SetConsoleTextAttribute(hStdOut, FOREGROUND_INTENSITY);
			}

			switch(ncIndex)
			{
			case IMAGE_DIRECTORY_ENTRY_EXPORT:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_EXPORTS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_IMPORT:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_IMPORTS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_RESOURCE:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_RESOURCES, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_EXCEPTIONS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_SECURITY:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_SECURITY, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_BASERELOC:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_RELOCATION_TABLE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_DEBUG:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_DEBUG, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_ARCHITECTURE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_GLOBAL_PTR, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_TLS:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_TLS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_LOAD_CFG, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_BOUND_IMPORT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_IAT:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_IAT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_DELAY_LOAD_IMPORT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_DOTNET, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			case 15:
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_RESERVED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				break;
			default:
				ShowResourceStringArgs(hStdOut, IDS_MSG_DATADIR_EXTRA, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), ncIndex);
				break;
			}

			if (lpImgDataDir[ncIndex].VirtualAddress || lpImgDataDir[ncIndex].Size)
				ShowResourceStringArgs(hStdOut, IDS_MSG_DATADIR_ENTRY_INFO, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgDataDir[ncIndex].Size, lpImgDataDir[ncIndex].VirtualAddress);
			else
				ShowResourceString(hStdOut, IDS_MSG_DATADIR_ENTRY_ABSENT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
		}
	}

	if (fbRestoreAttr)
		::SetConsoleTextAttribute(hStdOut, csbi.wAttributes);
}

void ShowNibble(__in HANDLE hStdOut, __in BYTE aByte)
{
	BYTE aNibble(aByte & 0xF);
	switch(aNibble)
	{
	case 0:
		ShowString(hStdOut, L"0");
		break;
	case 1:
		ShowString(hStdOut, L"1");
		break;
	case 2:
		ShowString(hStdOut, L"2");
		break;
	case 3:
		ShowString(hStdOut, L"3");
		break;
	case 4:
		ShowString(hStdOut, L"4");
		break;
	case 5:
		ShowString(hStdOut, L"5");
		break;
	case 6:
		ShowString(hStdOut, L"6");
		break;
	case 7:
		ShowString(hStdOut, L"7");
		break;
	case 8:
		ShowString(hStdOut, L"8");
		break;
	case 9:
		ShowString(hStdOut, L"9");
		break;
	case 0x0A:
		ShowString(hStdOut, L"A");
		break;
	case 0x0B:
		ShowString(hStdOut, L"B");
		break;
	case 0x0C:
		ShowString(hStdOut, L"C");
		break;
	case 0x0D:
		ShowString(hStdOut, L"D");
		break;
	case 0x0E:
		ShowString(hStdOut, L"E");
		break;
	case 0x0F:
		ShowString(hStdOut, L"F");
		break;
	}
}

void ShowByte(__in HANDLE hStdOut, __in BYTE aByte)
{
	ShowNibble(hStdOut, aByte >> 4);
	ShowNibble(hStdOut, aByte);
}

void ShowDWord(__in HANDLE hStdOut, __in DWORD dwValue)
{
	union
	{
		BYTE dwByte[4];
		DWORD dwVal;
	}
	DWord_Value;
	DWord_Value.dwVal = dwValue;

	for (int icnIndex(4); icnIndex > 0; icnIndex--)
		ShowByte(hStdOut, DWord_Value.dwByte[icnIndex - 1]);
}

__inline __wchar_t MapChar(__in char aChar)
{
	char aChars[2] = { aChar, 0 };
	__wchar_t wChars[2] = { 0 };
	if (0 == ::MultiByteToWideChar(1252, MB_PRECOMPOSED, aChars, -1, wChars, 2))
		wChars[0] = L'?';
	return (wChars[0]);
}

void WriteParagraph(__in HANDLE hStdOut, __in LPCVOID lpParagraph, __in LPVOID* lpNextParagraf)
{
	BYTE* lpPara(reinterpret_cast<BYTE*>(const_cast<LPVOID>(lpParagraph)));
	for (int icnIndex(0); icnIndex < MEM_PARAGRAPH_SIZE; icnIndex++)
	{
		ShowByte(hStdOut, lpPara[icnIndex]);
		ShowString(hStdOut, L" ");
	}
	ShowString(hStdOut, L"|");

	char* lpParaChar = reinterpret_cast<char*>(lpPara);
	__wchar_t wszSymbol[2] = { 0 };
	for (int icnIndex(0); icnIndex < MEM_PARAGRAPH_SIZE; icnIndex++)
	{
		if (lpParaChar[icnIndex] > 31)
		{
			wszSymbol[0] = MapChar(lpParaChar[icnIndex]);
			ShowString(hStdOut, &wszSymbol[0]);
		}
		else
			ShowString(hStdOut, L" ");
	}
	ShowString(hStdOut, L"|\r\n");
	if (lpNextParagraf != nullptr)
		*lpNextParagraf = reinterpret_cast<LPVOID>((UINT_PTR)(lpParagraph) + MEM_PARAGRAPH_SIZE);
}

void ShowMemory(__in HANDLE hStdOut, __in LPCVOID lpMemory, __in DWORD dwMemorySize)
{
	DWORD dwSize(dwMemorySize);
	
	LPVOID lpBase(const_cast<LPVOID>(lpMemory));
	LPVOID lpNext(nullptr);
	//DWORD dwBlockNo(0);

	DWORD dwFirstParaSize(MEM_PARAGRAPH_SIZE - ((DWORD)(lpBase) & 0x0000000FUL));	
	DWORD dwFirstParaGapSize((DWORD)(lpBase) & 0x0000000FUL);	

	if (dwFirstParaSize != 0)
	{
		DWORD dwFirstPara((DWORD)(lpBase) & 0xFFFFFFF0UL);
		ShowDWord(hStdOut, dwFirstPara);
		ShowString(hStdOut, L": ");

		UINT cnIndex(0);
		for (; cnIndex < dwFirstParaGapSize; cnIndex++)
				ShowString(hStdOut, L"   ");
		while (cnIndex < MEM_PARAGRAPH_SIZE)
		{
			ShowByte(hStdOut, ((BYTE*)(lpBase))[cnIndex]);
			ShowString(hStdOut, L" ");
			cnIndex++;
		}
		ShowString(hStdOut, L"|");

		cnIndex = 0;
		for (; cnIndex < dwFirstParaGapSize; cnIndex++)
				ShowString(hStdOut, L" ");
		__wchar_t wszSymbol[2] = { 0 };
		while (cnIndex < MEM_PARAGRAPH_SIZE)
		{
			if (((char*)(lpBase))[cnIndex] < 32)
				ShowString(hStdOut, L" ");
			else
			{
				wszSymbol[0] = MapChar(((char*)(lpBase))[cnIndex]);
				ShowString(hStdOut, &wszSymbol[0]);
			}
			cnIndex++;
		}
		ShowString(hStdOut, L"|\r\n");
		lpBase = (LPVOID)(dwFirstPara + MEM_PARAGRAPH_SIZE);
		dwSize -= dwFirstParaSize;
	}

	while (dwSize >= MEM_PARAGRAPH_SIZE)
	{
		ShowDWord(hStdOut, (DWORD)(lpBase));
		ShowString(hStdOut, L": ");
		WriteParagraph(hStdOut, lpBase, (LPVOID*)(&lpNext));
		lpBase = lpNext;
		lpNext = nullptr;
		dwSize -= MEM_PARAGRAPH_SIZE;
	}

	if (dwSize)
	{
		ShowDWord(hStdOut, (DWORD)(lpBase));
		ShowString(hStdOut, L": ");

		UINT cnIndex(0);
		for (; cnIndex < dwSize; cnIndex++)
		{
			ShowByte(hStdOut, ((BYTE*)(lpBase))[cnIndex]);
			ShowString(hStdOut, L" ");
		}
		while (cnIndex < MEM_PARAGRAPH_SIZE)
		{
			ShowString(hStdOut, L"   ");
			cnIndex++;
		}
		ShowString(hStdOut, L"|");

		cnIndex = 0;
		__wchar_t wszSymbol[2] = { 0 };
		for (; cnIndex < dwSize; cnIndex++)
		{
			if (((char*)(lpBase))[cnIndex] < 32)
				ShowString(hStdOut, L" ");
			else
			{
				wszSymbol[0] = MapChar(((char*)(lpBase))[cnIndex]);
				ShowString(hStdOut, &wszSymbol[0]);
			}
		}
		while (cnIndex < MEM_PARAGRAPH_SIZE)
		{
			ShowString(hStdOut, L" ");
			cnIndex++;
		}
		ShowString(hStdOut, L"|\r\n");
	}
}

void ShowSections(__in PIMAGE_SECTION_HEADER lpImgSectionHdr, __in PIMAGE_OPTIONAL_HEADER lpImgOptHdr, __in unsigned short cnwTotalSections, 
	__in LPVOID lpBase, __in HANDLE hStdOut, __in bool fbVerboseMode)
{
	CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
	BOOL fbRestoreAttr(::GetConsoleScreenBufferInfo(hStdOut, &csbi));
	DWORD dwGapsSizeTotal(0);

	if (cnwTotalSections)
	{
		ShowResourceString(hStdOut, IDS_MSG_SECTIONS_CONTENT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

		//DWORD dwSectionsVAFinish(0);
		DWORD dwSectionsStart(lpImgSectionHdr[0].PointerToRawData);
		DWORD dwSectionsFinish(dwSectionsStart);

		for (unsigned short cnwSectIndex(0); cnwSectIndex < cnwTotalSections; cnwSectIndex++)
		{
			if (dwSectionsStart > lpImgSectionHdr[cnwSectIndex].PointerToRawData)
				dwSectionsStart = lpImgSectionHdr[cnwSectIndex].PointerToRawData;

			if (dwSectionsFinish < (lpImgSectionHdr[cnwSectIndex].PointerToRawData + lpImgSectionHdr[cnwSectIndex].SizeOfRawData))
				dwSectionsFinish = lpImgSectionHdr[cnwSectIndex].PointerToRawData + lpImgSectionHdr[cnwSectIndex].SizeOfRawData;

			__wchar_t wszSectName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
			UINT dwcnSectionNameIndex(0);
			while ((lpImgSectionHdr[cnwSectIndex].Name[dwcnSectionNameIndex] != 0) && (dwcnSectionNameIndex < IMAGE_SIZEOF_SHORT_NAME))
			{
				wszSectName[dwcnSectionNameIndex] = MapChar(lpImgSectionHdr[cnwSectIndex].Name[dwcnSectionNameIndex]);
				++dwcnSectionNameIndex;
			}

			if (lpImgSectionHdr[cnwSectIndex].SizeOfRawData)
			{
				if (lpImgSectionHdr[cnwSectIndex].Misc.VirtualSize <= lpImgSectionHdr[cnwSectIndex].SizeOfRawData || lpImgSectionHdr[cnwSectIndex].SizeOfRawData % lpImgOptHdr ->FileAlignment)
					::SetConsoleTextAttribute(hStdOut, csbi.wAttributes);
				else
					::SetConsoleTextAttribute(hStdOut, FOREGROUND_INTENSITY);
			}
			else
				::SetConsoleTextAttribute(hStdOut, FOREGROUND_INTENSITY);


			ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_NUMBER_NAME, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), cnwSectIndex, &wszSectName[0]);
			if (fbVerboseMode)
			{
				ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_VIRTUAL_SIZE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgSectionHdr[cnwSectIndex].Misc.VirtualSize);
				ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_VIRTUAL_ADDRESS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgSectionHdr[cnwSectIndex].VirtualAddress);
				ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_RAW_SIZE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgSectionHdr[cnwSectIndex].SizeOfRawData);
				ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_RAW_DATA_PTR, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgSectionHdr[cnwSectIndex].PointerToRawData);
				ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_RAW_DATA_PTR_BEYOND, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgSectionHdr[cnwSectIndex].PointerToRawData  + lpImgSectionHdr[cnwSectIndex].SizeOfRawData);
				ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_RELOC_PTR, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgSectionHdr[cnwSectIndex].PointerToRelocations);
				ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_LINE_NUMS_PTR, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgSectionHdr[cnwSectIndex].PointerToLinenumbers);
				ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_RELOC_NUM, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgSectionHdr[cnwSectIndex].NumberOfRelocations);
				ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_LINENUMS_NUM, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgSectionHdr[cnwSectIndex].NumberOfLinenumbers);

				ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_CHARACTERISTICS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgSectionHdr[cnwSectIndex].Characteristics);

				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_TYPE_NO_PAD)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_NO_PAD, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_CNT_CODE)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_CODE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_INIT_DATA, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_UNINIT_DATA, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_LNK_INFO)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_LNKR_INFO, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_NO_DEFER_SPEC_EXC)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_NO_DEFER_SPEC_EXC, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_GPREL)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_GP_REL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_EXT_RELOC, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_MEM_DISCARDABLE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_NOT_CACHED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_MEM_NOT_PAGED)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_NOT_PAGED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_MEM_SHARED)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_MEM_SHARED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_MEM_EXECUTE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_MEM_READ)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_MEM_READ, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				if (lpImgSectionHdr[cnwSectIndex].Characteristics & IMAGE_SCN_MEM_WRITE)
					ShowResourceString(hStdOut, IDS_MSG_SECTION_CHARS_MEM_WRITE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			}
			
			if (lpImgSectionHdr[cnwSectIndex].SizeOfRawData && (lpImgSectionHdr[cnwSectIndex].Misc.VirtualSize <= lpImgSectionHdr[cnwSectIndex].SizeOfRawData))
			{
				LPVOID lpSectionGap(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(lpBase) + lpImgSectionHdr[cnwSectIndex].PointerToRawData + lpImgSectionHdr[cnwSectIndex].Misc.VirtualSize));
				DWORD dwSectionGapSize(max(lpImgSectionHdr[cnwSectIndex].SizeOfRawData, lpImgSectionHdr[cnwSectIndex].Misc.VirtualSize) - min(lpImgSectionHdr[cnwSectIndex].SizeOfRawData, lpImgSectionHdr[cnwSectIndex].Misc.VirtualSize));

				if (dwSectionGapSize)
				{
					dwGapsSizeTotal += dwSectionGapSize;
					ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_GAP_CONTENT_INFO, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), dwSectionGapSize);
					ShowMemory(hStdOut, lpSectionGap, dwSectionGapSize);
				}
				else
					ShowResourceString(hStdOut, IDS_MSG_SECTION_NO_GAP, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			}
			else
				if (lpImgSectionHdr[cnwSectIndex].SizeOfRawData)
				{
					DWORD dwRemainder(0);
					if (0 != (dwRemainder = lpImgSectionHdr[cnwSectIndex].SizeOfRawData % lpImgOptHdr ->FileAlignment))
					{
						dwGapsSizeTotal += lpImgOptHdr ->FileAlignment - dwRemainder;
						LPVOID lpSectionGap((LPVOID)((DWORD)(lpBase) + lpImgSectionHdr[cnwSectIndex].PointerToRawData + lpImgSectionHdr[cnwSectIndex].SizeOfRawData));
						ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_GAP_CONTENT_INFO, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpImgOptHdr ->FileAlignment - dwRemainder);
						ShowMemory(hStdOut, lpSectionGap, lpImgOptHdr ->FileAlignment - dwRemainder);
					}
					else
						ShowResourceString(hStdOut, IDS_MSG_SECTION_NO_GAP, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				}
				else
					ShowResourceString(hStdOut, IDS_MSG_SECTION_IS_VIRTUAL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
		}
	}
	if (fbRestoreAttr)
		::SetConsoleTextAttribute(hStdOut, csbi.wAttributes);
	if (dwGapsSizeTotal)
		ShowResourceStringArgs(hStdOut, IDS_MSG_SECTIONS_GAPS_TOTAL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), dwGapsSizeTotal);
}

void FillSectionsGap(__in PIMAGE_SECTION_HEADER lpImgSectionHdr, __in PIMAGE_OPTIONAL_HEADER lpImgOptHdr, __in unsigned short cnwTotalSections, 
	__in LPVOID lpBase, __in BYTE byFiller)
{
	if (cnwTotalSections)
		for (unsigned short cnwSectIndex(0); cnwSectIndex < cnwTotalSections; ++cnwSectIndex)
		{	
			if (lpImgSectionHdr[cnwSectIndex].SizeOfRawData && (lpImgSectionHdr[cnwSectIndex].Misc.VirtualSize <= lpImgSectionHdr[cnwSectIndex].SizeOfRawData))
			{
				LPBYTE lpbySectionGap((LPBYTE)((DWORD)(lpBase) + lpImgSectionHdr[cnwSectIndex].PointerToRawData + lpImgSectionHdr[cnwSectIndex].Misc.VirtualSize));
				DWORD dwSectionGapSize(max(lpImgSectionHdr[cnwSectIndex].SizeOfRawData, lpImgSectionHdr[cnwSectIndex].Misc.VirtualSize) - min(lpImgSectionHdr[cnwSectIndex].SizeOfRawData, lpImgSectionHdr[cnwSectIndex].Misc.VirtualSize));

				if (dwSectionGapSize)
					while (dwSectionGapSize--)
						*lpbySectionGap++ = byFiller;
			}
		}
	UNREFERENCED_PARAMETER(lpImgOptHdr);
}

/******************************************************************************************/
/*   Function name: ShowSysErrorMsg                                                       */
/*   Description: Show system error message for passed error code.                        */
/*   Parameters:                                                                          */
/*      [in] dwErrorCode(type DWORD) - Error code                                         */
/*      [in] hStdOut(type HANDLE) - Console handle                                        */
/******************************************************************************************/
void ShowSysErrorMsg(__in DWORD dwErrorCode, __in HANDLE hStdOut)
{
	if (hStdOut)
	{
		__wchar_t wszErrorMsgBuf[MAX_PATH] = { 0 };
		__wchar_t szNewLine[3] = { L'\r', L'\n', 0	};

		CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
		BOOL fbRestoreConAttr(FALSE);
		fbRestoreConAttr = ::GetConsoleScreenBufferInfo(hStdOut, &csbi) && ::SetConsoleTextAttribute(hStdOut, FOREGROUND_RED | FOREGROUND_INTENSITY);

		if (LoadErrorMessageW(MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), dwErrorCode, &wszErrorMsgBuf[0], MAX_PATH))
			ShowString(hStdOut, &wszErrorMsgBuf[0]);
		else
			ShowResourceStringArgs(hStdOut, IDS_ERROR_SYSTEM, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), dwErrorCode);
		ShowString(hStdOut, szNewLine);

		if (fbRestoreConAttr)
			::SetConsoleTextAttribute(hStdOut, csbi.wAttributes);
	}
}

/******************************************************************************************/
/*   Function name: StrSize                                                               */
/*   Description: Wrapper for StringCbLengthW.                                            */
/*   Parameters:                                                                          */
/*      [in] lpwszString(type __wchar_t* const) - Pointer to string buffer                */
/*   Return:                                                                              */
/*      Length of string in chars                                                         */
/******************************************************************************************/
size_t StrSize(__in  __nullterminated __wchar_t* const lpwszString)
{
	size_t cnSize(0);
	if (lpwszString)
		if FAILED(::StringCbLengthW(lpwszString, STRSAFE_MAX_CCH, &cnSize))
			cnSize = 0;
	return (cnSize);
}

bool CheckEventSrcRegistration(__in __wchar_t* const lpwszLogName, __in __wchar_t* const lpwszMsgTableFile)
{
	HKEY hKey(nullptr), hk(nullptr); 
	DWORD dwData(0), dwDisp(0), dwCategoryNum(1);
	bool fbChecked(false);

	if (ERROR_SUCCESS == ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, lpwszEventLoggerRootKey, 0, KEY_WRITE, &hKey)) 
	{
		//	Looking for <lpwszLogName> under hKey
		__wchar_t achKey[MAX_KEY_LENGTH] = { 0 };
		__wchar_t achValue[MAX_PATH] = { 0 };
		DWORD    cbName(0);
		DWORD    cnSubKeys(0);

		bool fbKeyExists(false);

		if (ERROR_SUCCESS == ::RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &cnSubKeys, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) && cnSubKeys)
		{
			for (DWORD i(0); i < cnSubKeys; ++i) 
			{ 
				cbName = MAX_KEY_LENGTH;
				if (ERROR_SUCCESS == ::RegEnumKeyExW(hKey, i, achKey, &cbName, nullptr, nullptr, nullptr, nullptr))
				{
					if (CSTR_EQUAL == ::CompareStringW(LOCALE_NEUTRAL, NORM_IGNORECASE, achKey, cbName, lpwszLogName, -1))
					{
						fbKeyExists = true;
						break;
					}
				}
			}
		}

		LSTATUS Status;
		if (fbKeyExists)
			Status = ::RegOpenKeyExW(hKey, lpwszLogName, 0, KEY_WRITE, &hk);
		else
			Status = ::RegCreateKeyExW(hKey, lpwszLogName, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hk, &dwDisp);

		if (ERROR_SUCCESS == Status) 
		{ 
			// Get/set the name of the message file.  
			bool bEventMsgFile(false);
			DWORD dwValueType(0);
			DWORD dwValueLen(MAX_PATH);

			if (ERROR_FILE_NOT_FOUND != (Status = ::RegQueryValueExW(hk, lpwszEventMessageFile, nullptr, &dwValueType, reinterpret_cast<LPBYTE>(achValue), &dwValueLen)) && ERROR_SUCCESS == Status)
				bEventMsgFile = (CSTR_EQUAL == ::CompareStringW(LOCALE_NEUTRAL, NORM_IGNORECASE, achValue, dwValueLen, lpwszLogName, -1));
			if (!bEventMsgFile)
				Status = ::RegSetValueExW(hk, lpwszEventMessageFile, 0, REG_EXPAND_SZ, reinterpret_cast<LPBYTE>(const_cast<__wchar_t*>(lpwszMsgTableFile)), static_cast<DWORD>(StrSize(lpwszMsgTableFile) + sizeof(__wchar_t)));
			if (ERROR_SUCCESS == Status)
			{ 
				// Get/set the supported event types.  
				dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE; 
				DWORD dwValue(0);
				dwValueLen = sizeof(DWORD);
				bool bTypesSupported(false);

				if (ERROR_FILE_NOT_FOUND != (Status = ::RegQueryValueExW(hk, lpwszTypesSupported, nullptr, &dwValueType, reinterpret_cast<LPBYTE>(dwValue), &dwValueLen)) && ERROR_SUCCESS == Status)
					bTypesSupported = (dwData == dwValue);
				if (!bTypesSupported)
					Status = ::RegSetValueExW(hk, lpwszTypesSupported, 0, REG_DWORD, (LPBYTE) &dwData, sizeof(DWORD));
				if (ERROR_SUCCESS == Status)
				{ 
					// Get/set the category message file and number of categories.
					dwValueLen = MAX_PATH;
					ZeroMemory(achValue, sizeof(__wchar_t) * MAX_PATH);
					bool bCategoryMessageFile(false);

					if (ERROR_FILE_NOT_FOUND != (Status = ::RegQueryValueExW(hk, lpwszCategoryMessageFile, nullptr, &dwValueType, reinterpret_cast<LPBYTE>(achValue), &dwValueLen)) && ERROR_SUCCESS == Status)
						bCategoryMessageFile = (CSTR_EQUAL == ::CompareStringW(LOCALE_NEUTRAL, NORM_IGNORECASE, achValue, dwValueLen, lpwszLogName, -1));
					if (!bCategoryMessageFile)
						Status = ::RegSetValueEx(hk, lpwszCategoryMessageFile, 0, REG_EXPAND_SZ, reinterpret_cast<LPBYTE>(const_cast<__wchar_t*>(lpwszMsgTableFile)), static_cast<DWORD>(StrSize(lpwszMsgTableFile) + sizeof(__wchar_t)));
					if (ERROR_SUCCESS == Status)
					{
						dwValueLen = sizeof(DWORD);
						bool bCategoryCount(false);

						if (ERROR_FILE_NOT_FOUND != (Status = ::RegQueryValueExW(hk, lpwszTypesSupported, nullptr, &dwValueType, reinterpret_cast<LPBYTE>(dwValue), &dwValueLen)) && ERROR_SUCCESS == Status)
							bCategoryCount = (dwCategoryNum == dwValue);
						if (!bCategoryCount)
							Status = ::RegSetValueExW(hk, lpwszCategoryCount, 0, REG_DWORD, reinterpret_cast<LPBYTE>(&dwCategoryNum), sizeof(DWORD));
						fbChecked = ERROR_SUCCESS == Status;
					}
				}
				if (hk)
					::RegCloseKey(hk);
			}
			if (hKey)
				::RegCloseKey(hKey);
		}
	}
	return fbChecked;
}

void UnregEventSrc(__in __wchar_t* const lpwszLogName)
{
	HKEY hKey(nullptr);
	if (ERROR_SUCCESS == ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, lpwszEventLoggerRootKey, 0, KEY_WRITE, &hKey)) 
	{
		::RegDeleteTreeW(hKey, lpwszLogName);
		if (hKey)
			::RegCloseKey(hKey);
	}
}

void MakeReportEventRecord(__in __wchar_t* const lpwszEventSrc, __in WORD wEventType, __in DWORD dwEventID, __in WORD cnInsertionsCount, __in __wchar_t** const lpwszStringsToInsert)
{
	if (lpwszEventSrc)
	{
		HANDLE hEventSrc(::RegisterEventSource(nullptr, lpwszEventSrc));
		if (hEventSrc) 
		{
			::ReportEventW(hEventSrc, wEventType, 0, dwEventID, nullptr, cnInsertionsCount, 0, (LPCWSTR*)(lpwszStringsToInsert), nullptr);
			::DeregisterEventSource(hEventSrc); 
		}
	}
}

LONG WINAPI gcfcUnhandledExceptionFilter(__in struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	__wchar_t wszIdent[MAX_PATH] = { 0 };
	__wchar_t* lpwszDescription(nullptr);
	__wchar_t lpwszEXEName[MAX_PATH] = { 0 };
	UINT cbLen(0);
	bool fbIdentOk(false);

	HRSRC hResource(::FindResourceW(nullptr, MAKEINTRESOURCEW(VS_VERSION_INFO), RT_VERSION));
	if (hResource)
	{
		HGLOBAL hGlobal(::LoadResource(nullptr, hResource));
		if (hGlobal)
		{
			LPVOID lpResource(::LockResource(hGlobal));
			if (lpResource)
			{
				if (::VerQueryValueW(lpResource, lpwszProductIdent, reinterpret_cast<LPVOID*>(&lpwszDescription), &cbLen))
				{								
					::StringCchCopyNW(wszIdent, MAX_PATH, lpwszDescription, cbLen);
					fbIdentOk = true;
				}
				UnlockResource(lpResource);
			}
			::FreeResource(hGlobal);
		}
	}

	if (0 != ::GetModuleFileNameW(nullptr, lpwszEXEName, MAX_PATH) && CheckEventSrcRegistration(wszIdent, lpwszEXEName))
	{
		//MakeReportEventRecord(wszIdent, STATUS_SEVERITY_ERROR, MSG_UNHANDLED_EXCEPTION, 1, reinterpret_cast<const __wchar_t**>(&lpwszEXEName));
		MakeReportEventRecord(wszIdent, STATUS_SEVERITY_ERROR, MSG_UNHANDLED_EXCEPTION, 1, (__wchar_t**)(&lpwszEXEName));
		UnregEventSrc(wszIdent);
	}

	return (EXCEPTION_EXECUTE_HANDLER);
	UNREFERENCED_PARAMETER(ExceptionInfo);
}

int __cdecl wmain(int argc, __wchar_t* argv[])
{
	LARGE_INTEGER liFileSize = { 0 };
	int nRetCode(0);
	//bool fbKeyIsPressed(false);

	::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
	LPTOP_LEVEL_EXCEPTION_FILTER lpEFOriginal(::SetUnhandledExceptionFilter(gcfcUnhandledExceptionFilter));

	HANDLE hOut(::GetStdHandle(STD_OUTPUT_HANDLE));

	__wchar_t szOutStrHeader[MAX_PATH] = { 0 };
	__wchar_t szOutStrVersion[MAX_PATH] = { 0 };
	__wchar_t szNewLine[3] = { L'\r', L'\n', 0	};
	__wchar_t szOldTitle[MAX_PATH] = { 0 };
	__wchar_t wszIdent[MAX_PATH] = { 0 };

	bool fbHeaderOk(false);
	bool fbVersionOk(false);
	bool fbIdentOk(false);
	bool fbReportEvent(false);

	if (hOut)
	{
		__wchar_t* lpwszDescription(nullptr);
		UINT cbLen(0);

		HRSRC hResource(::FindResourceW(nullptr, MAKEINTRESOURCEW(VS_VERSION_INFO), RT_VERSION));
		if (hResource)
		{
			HGLOBAL hGlobal(::LoadResource(nullptr, hResource));
			if (hGlobal)
			{
				LPVOID lpResource(::LockResource(hGlobal));
				if (lpResource)
				{
					if (::VerQueryValueW(lpResource, lpwszFileDescription, reinterpret_cast<LPVOID*>(&lpwszDescription), &cbLen))
						fbHeaderOk = SUCCEEDED(::StringCchCopyW(szOutStrHeader, MAX_PATH, lpwszDescription));

					__wchar_t* lpwszVersion(LoadStringEx(::GetModuleHandleW(nullptr), IDS_VERSION_STRING, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)));
					if (lpwszVersion)
					{
						if (SUCCEEDED(::StringCchCopyW(szOutStrVersion, MAX_PATH, lpwszVersion)))
						{	
							if (::VerQueryValueW(lpResource, lpwszFileVersion, reinterpret_cast<LPVOID*>(&lpwszDescription), &cbLen))
							{
								::StringCchCatW(szOutStrVersion, MAX_PATH, lpwszDescription);
								::StringCchCatW(szOutStrVersion, MAX_PATH, szNewLine);
							}
							if (::VerQueryValueW(lpResource, lpwszLegalCopyright, reinterpret_cast<LPVOID*>(&lpwszDescription), &cbLen))
							{
								::StringCchCatW(szOutStrVersion, MAX_PATH, lpwszDescription);
								::StringCchCatW(szOutStrVersion, MAX_PATH, szNewLine);
							}
							fbVersionOk = true;
							if (::VerQueryValueW(lpResource, lpwszProductIdent, reinterpret_cast<LPVOID*>(&lpwszDescription), &cbLen))
							{								
								::StringCchCopyNW(wszIdent, MAX_PATH, lpwszDescription, cbLen);
								fbIdentOk = true;
							}
						}
						ReleaseLoadedString(lpwszVersion);
					}
					UnlockResource(lpResource);
				}
				::FreeResource(hGlobal);
			}
		}

		fbReportEvent = fbIdentOk ? CheckEventSrcRegistration(wszIdent, argv[0]) : false;

		if (fbHeaderOk)
		{
			if (::GetConsoleTitleW(szOldTitle, ARRAYSIZE(szOldTitle)))
				::SetConsoleTitleW(szOutStrHeader);
			//DWORD dwWritten(0);

			ShowString(hOut, szOutStrHeader);
			ShowString(hOut, szNewLine);

			if (fbVersionOk)
			{
				ShowString(hOut, szOutStrVersion);
				ShowString(hOut, szNewLine);
			}

			if (argc < 2)
				ShowUsage(hOut);
			else
			{
				if (FileExists(argv[1]))
				{
					bool fbDigSig(false);
					bool fbDigSigIsValid(false);
					int nInvalidOptNo(-1);
					int nInvalidCharIndex(-1);
					bool fbVerbose(false);
					bool fbClean(false);
					bool fbChecksum(false);
					BYTE byFiller(0);
					bool fbOptionsAreCorrect(true);
					
					ShowResourceStringArgs(hOut, IDS_MSG_FILE_NAME, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), ::PathFindFileNameW(argv[1]));
					ShowString(hOut, szNewLine);

					if (argc > 2)
					{
						if (false == (fbOptionsAreCorrect = CheckOptArguments(argc - 2, /*const_cast<const __wchar_t**>*/(&argv[2]), nInvalidOptNo, nInvalidCharIndex, fbVerbose, fbClean, byFiller, fbChecksum)))
						{
							nInvalidOptNo += 2;
							ShowString(hOut, argv[nInvalidOptNo]);
							ShowString(hOut, szNewLine);
							for (int c(0); c < nInvalidCharIndex; ++c)
								ShowString(hOut, L" ");
							ShowResourceString(hOut, IDS_ERROR_INVALID_OPT_KEY, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
							ShowString(hOut, szNewLine);
							ShowUsage(hOut);
							nRetCode = -11;		//	Invalid option key
						}
					}

					if (!nRetCode)
					{
						if (fbVerbose)
						{
							ShowResourceString(hOut, IDS_MSG_VERBOSE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
							if (fbChecksum)
								ShowResourceString(hOut, IDS_MSG_CHECKSUM, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
							else
								ShowResourceString(hOut, IDS_MSG_NO_CHECKSUM, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

							if (fbClean)
							{
								ShowResourceString(hOut, IDS_MSG_CLEAN_ON, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
								ShowResourceStringArgs(hOut, IDS_MSG_FILLER, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), byFiller);
							}
							else
								ShowResourceString(hOut, IDS_MSG_CLEAN_OFF, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

							bool fbAdmin(false);
							if (true == (fbAdmin = IsUserAdmin()))
								ShowResourceString(hOut, IDS_UNDERADMIN_STRING, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

							TOKEN_ELEVATION_TYPE tet(static_cast<TOKEN_ELEVATION_TYPE>(0));
							if (TokenElevationTypeFull == (tet = GetElevationType()))
								ShowResourceString(hOut, IDS_ELEVATED_STRING, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
							if (fbAdmin || (TokenElevationTypeFull == tet))
								ShowString(hOut, szNewLine);
						}

						if (!CanAccessFile(argv[1], fbClean ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ))
						{
							ShowResourceString(hOut, IDS_MSG_FILE_ACCESS_DENIED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
							ShowString(hOut, szNewLine);
							nRetCode = -5;		//	Access denied.
						}
						else
						{
							if (true == (fbDigSig = IsFileDigitallySigned(argv[1], nullptr)))
							{
								ShowResourceString(hOut, IDS_MSG_FILE_SIGNED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
								if (fbDigSig && fbClean)
								{
									ShowResourceString(hOut, IDS_MSG_CLEAN_ON_SIGNED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
									fbClean = false;
								}
							}

							HANDLE hFile(::CreateFileW(argv[1], fbClean ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0));
							if (INVALID_HANDLE_VALUE == hFile || !::GetFileSizeEx(hFile, &liFileSize))
							{									
								ShowSysErrorMsg(::GetLastError(), hOut);
								if (INVALID_HANDLE_VALUE != hFile)
									::CloseHandle(hFile);
								nRetCode = -3;		//	Unable to open file or obtain file size 
							}
							else
							{
								if (fbDigSig)
								{
									GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
									WINTRUST_FILE_INFO sWintrustFileInfo = { 0 };
									WINTRUST_DATA sWintrustData = { 0 };

									sWintrustFileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
									sWintrustFileInfo.pcwszFilePath = argv[1];
									sWintrustFileInfo.hFile = hFile;

									sWintrustData.cbStruct = sizeof(WINTRUST_DATA);
									sWintrustData.dwUIChoice = WTD_UI_NONE;
									sWintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
									sWintrustData.dwUnionChoice = WTD_CHOICE_FILE;
									sWintrustData.pFile = &sWintrustFileInfo;
									sWintrustData.dwStateAction = WTD_STATEACTION_VERIFY;

									HRESULT hr(::WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guidAction, &sWintrustData));
									if (SUCCEEDED(hr))
									{
										// Retreive the signer certificate and display its information
										CRYPT_PROVIDER_DATA const *psProvData(nullptr);
										CRYPT_PROVIDER_SGNR       *psProvSigner(nullptr);
										CRYPT_PROVIDER_CERT       *psProvCert(nullptr);
										FILETIME                   localFt = { 0 };
										SYSTEMTIME                 sysTime = { 0 };

										psProvData = ::WTHelperProvDataFromStateData(sWintrustData.hWVTStateData);
										if (psProvData)
										{
											psProvSigner = WTHelperGetProvSignerFromChain(const_cast<PCRYPT_PROVIDER_DATA>(psProvData), 0 , FALSE, 0);
											if (psProvSigner && fbVerbose)
											{
												::FileTimeToLocalFileTime(&psProvSigner->sftVerifyAsOf, &localFt);
												::FileTimeToSystemTime(&localFt, &sysTime);

												if (fbVerbose)
													ShowResourceStringArgs(hOut, IDS_IMG_SIGNATURE_DATETIME, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), sysTime.wDay, sysTime.wMonth,sysTime.wYear, sysTime.wHour,sysTime.wMinute,sysTime.wSecond);

												if (psProvSigner ->csCertChain && fbVerbose)
												{
													if (1 == psProvSigner ->csCertChain)
														ShowResourceString(hOut, IDS_IMG_FILE_SIGNER, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
													else
														ShowResourceString(hOut, IDS_IMG_FILE_SIGNERS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

													for (DWORD dwCertIndex(0); dwCertIndex < psProvSigner ->csCertChain; ++dwCertIndex)
													{
														psProvCert = ::WTHelperGetProvCertFromChain(psProvSigner, dwCertIndex);
														if (psProvCert)
														{
															__wchar_t* szCertDesc(::GetCertificateDescription(psProvCert->pCert));
															if (szCertDesc)
															{
																ShowString(hOut, szCertDesc);
																ShowString(hOut, szNewLine);
																ReleaseLoadedString(szCertDesc);
															}
														}
													}
												}

												if (psProvSigner->csCounterSigners && fbVerbose)
												{
													// retreive timestamp information
													::FileTimeToLocalFileTime(&psProvSigner->pasCounterSigners[0].sftVerifyAsOf, &localFt);
													::FileTimeToSystemTime(&localFt, &sysTime);

													ShowResourceStringArgs(hOut, IDS_IMG_TIMESTAMP_DATETIME, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), sysTime.wDay, sysTime.wMonth,sysTime.wYear, sysTime.wHour,sysTime.wMinute,sysTime.wSecond);

													if (psProvSigner->csCounterSigners)
													{
														if (1 == psProvSigner->csCounterSigners)
															ShowResourceString(hOut, IDS_IMG_TIMESTAMP_SIGNER, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
														else
															ShowResourceString(hOut, IDS_IMG_TIMESTAMP_SIGNERS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

														for (DWORD idxCert(0); idxCert < psProvSigner->csCounterSigners; ++idxCert)
														{
															psProvCert = ::WTHelperGetProvCertFromChain(&psProvSigner->pasCounterSigners[idxCert], idxCert);
															if (psProvCert)
															{
																__wchar_t* szCertDesc = ::GetCertificateDescription(psProvCert->pCert);
																if (szCertDesc)
																{
																	ShowString(hOut, szCertDesc);
																	ShowString(hOut, szNewLine);
																	ReleaseLoadedString(szCertDesc);
																}
															}
														}
													}
												}
											}
										}
										fbDigSigIsValid = true;
									}
									else
									{
										switch(hr)
										{
										case TRUST_E_BAD_DIGEST:
											ShowResourceString(hOut, IDS_MSG_FILE_BAD_SIG, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
											break;
										case TRUST_E_PROVIDER_UNKNOWN:
											ShowResourceString(hOut, IDS_MSG_FILE_SIG_PROV_UNK, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
											break;
										case TRUST_E_SUBJECT_NOT_TRUSTED:
											ShowResourceString(hOut, IDS_MSG_FILE_SIG_NOT_TRUSTED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
											break;
										default:
											ShowResourceStringArgs(hOut, IDS_MSG_FILE_SIG_ERROR, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), hr);
											break;
										}
										ShowString(hOut, szNewLine);
									}
								}

								if (fbDigSig && fbDigSigIsValid)
								{
									ShowResourceString(hOut, IDS_MSG_FILE_SIG_OK, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
									ShowString(hOut, szNewLine);
								}

								HANDLE hFileMap(::CreateFileMappingW(hFile, nullptr, fbClean ? PAGE_READWRITE : PAGE_READONLY, 0, 0, nullptr));
								if (!hFileMap)
								{
									ShowSysErrorMsg(::GetLastError(), hOut);
									::CloseHandle(hFile);
									nRetCode = -4;		//	Unable to map file
								}
								else
								{
									LPVOID lpFileBase(::MapViewOfFile(hFileMap, fbClean ? FILE_MAP_READ | FILE_MAP_WRITE : FILE_MAP_READ , 0, 0, 0));
									if (!lpFileBase)
									{
										ShowSysErrorMsg(::GetLastError(), hOut);
										::CloseHandle(hFileMap);
										::CloseHandle(hFile);
										nRetCode = -5;		//	Unable to create view of map file
									}
									else
									{
										//HMODULE hModule(reinterpret_cast<HMODULE>(lpFileBase));
										PIMAGE_DOS_HEADER lpImgDOSHdr(reinterpret_cast<PIMAGE_DOS_HEADER>(lpFileBase));
										if (fbVerbose)
										{
											ShowDOSHeader(lpImgDOSHdr, hOut);
											ShowString(hOut, szNewLine);
										}
										if ((lpImgDOSHdr ->e_magic != IMAGE_DOS_SIGNATURE) || (lpImgDOSHdr ->e_lfarlc != 0x40))
										{
											nRetCode = -9;		//	DOS stub is damaged
											ShowResourceString(hOut, IDS_MSG_DOS_HDR_INVALID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
										}
										else
										{
											PIMAGE_NT_HEADERS lpImgNTHdrs(reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<UINT_PTR>(lpImgDOSHdr) + lpImgDOSHdr ->e_lfanew));
											if (fbVerbose)
											{
												ShowNTPEHeader(lpImgNTHdrs, hOut);
												ShowString(hOut, szNewLine);
											}
											if (lpImgNTHdrs ->Signature != IMAGE_NT_SIGNATURE)
											{
												nRetCode = -8;		//	PE headers are damaged
												ShowResourceString(hOut, IDS_MSG_NT_PE_INVALID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
											}
											else
											{
												PIMAGE_FILE_HEADER lpImgFileHdr(&lpImgNTHdrs ->FileHeader);
												if (fbVerbose)
												{
													ShowImgFileHdr(lpImgFileHdr, hOut);
													ShowString(hOut, szNewLine);
												}

												PIMAGE_OPTIONAL_HEADER lpImgOptHdr(&lpImgNTHdrs ->OptionalHeader);
												if (fbVerbose)
												{
													ShowImgOptHdr(lpImgOptHdr, hOut);
													ShowString(hOut, szNewLine);
												}

												if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == lpImgOptHdr ->Magic)
												{
													PIMAGE_DATA_DIRECTORY lpImgDataDir(&lpImgOptHdr ->DataDirectory[0]);
													if (fbVerbose)
													{
														ShowDataDirContent(lpImgDataDir, lpImgOptHdr ->NumberOfRvaAndSizes, hOut);
														ShowString(hOut, szNewLine);
													}

													PIMAGE_SECTION_HEADER lpImgSectionHdr(IMAGE_FIRST_SECTION(lpImgNTHdrs));
													ShowSections(lpImgSectionHdr, lpImgOptHdr, lpImgFileHdr ->NumberOfSections, lpFileBase, hOut, fbVerbose);
													ShowString(hOut, szNewLine);

													//	Calculate checksum ...
													DWORD dwHeaderSum(0), dwCheckSum(0);
													if (fbChecksum)
													{
														if (::CheckSumMappedFile(lpFileBase, liFileSize.LowPart, &dwHeaderSum, &dwCheckSum))
														{
															ShowResourceStringArgs(hOut, IDS_MSG_CHECKSUM_ORIGINAL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), dwHeaderSum);
															ShowResourceStringArgs(hOut, IDS_MSG_CHECKSUM_CALCD, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), dwCheckSum);

															CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
															BOOL fbRestoreAttr(::GetConsoleScreenBufferInfo(hOut, &csbi));
															if (dwCheckSum == dwHeaderSum)
															{																
																ShowResourceString(hOut, IDS_MSG_CHECKSUM_CORRECT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
																fbRestoreAttr = FALSE;
															}
															else
															{
																::SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_INTENSITY | COMMON_LVB_UNDERSCORE);
																ShowResourceString(hOut, IDS_MSG_CHECKSUM_INCORRECT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
															}
															if (fbRestoreAttr)
																::SetConsoleTextAttribute(hOut, csbi.wAttributes);
														}
														else
														{
															DWORD dwErrCode(::GetLastError());
															ShowResourceString(hOut, IDS_MSG_CHECKSUM_FAIL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
															ShowSysErrorMsg(dwErrCode, hOut);
															nRetCode = -7;		//	System error
														}
													}

													if (fbClean)
													{
														FillSectionsGap(lpImgSectionHdr, lpImgOptHdr, lpImgFileHdr ->NumberOfSections, lpFileBase, byFiller);
														if (fbVerbose)
															ShowResourceString(hOut, IDS_MSG_GAPS_FILLED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
															
														if (::CheckSumMappedFile(lpFileBase, liFileSize.LowPart, &dwHeaderSum, &dwCheckSum))
														{
															if (dwHeaderSum != dwCheckSum)
															{
																lpImgOptHdr ->CheckSum = dwCheckSum;
																ShowResourceString(hOut, IDS_MSG_CHECKSUM_ADJUSTED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
															}

															if (!::FlushViewOfFile(lpFileBase, 0))
															{
																nRetCode = -7;		//	System error
																ShowSysErrorMsg(::GetLastError(), hOut);
															}
															else
															{
																ShowResourceString(hOut, IDS_MSG_COMPLETED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));																
																if (fbReportEvent)
																	MakeReportEventRecord(wszIdent, STATUS_SEVERITY_SUCCESS, MSG_PROCESSING_SUCCESS, 1, /*const_cast<const __wchar_t**>*/(&argv[1]));
															}
														}
														else
														{
															nRetCode = -7;		//	System error
															ShowSysErrorMsg(::GetLastError(), hOut);
														}
													}
												}
												else
												{
													ShowResourceString(hOut, IDS_IMG_NOT_32BIT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
													nRetCode = -6;		//	Not 32-bit PE image
												}

												//__L_Cleanup:
												::UnmapViewOfFile(lpFileBase);
												::CloseHandle(hFileMap);
												::CloseHandle(hFile);												
											}
										}
									}
								}
							}
						}
					}
				}
				else
				{
					ShowResourceStringArgs(hOut, IDS_ERROR_FILE_ISNT_FOUND, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), argv[1]);
					ShowUsage(hOut);
					nRetCode = -2;				//	File is not exists
				}
			}

			::SetConsoleTitleW(szOldTitle);
		}
	}
	else
		nRetCode = -1;

	if (nRetCode < 0 && fbReportEvent)
		MakeReportEventRecord(wszIdent, STATUS_SEVERITY_ERROR, MSG_PROCESSING_FAILED, 1, /*const_cast<const __wchar_t**>*/(&argv[1]));

	if (fbReportEvent)
		UnregEventSrc(wszIdent);

	//	Try to obtain console's processes list
	DWORD dwProcessListLen(CONSOLE_PROCESS_LIST_LAMBDA);
	LPDWORD lpdwList(nullptr);
	DWORD dwConAppTotal(0);
	if (AllocBuffer(dwProcessListLen, &lpdwList))
	{
		DWORD dwReturnValue(dwConAppTotal = ::GetConsoleProcessList(lpdwList, dwProcessListLen));
		if (dwReturnValue > dwProcessListLen)
		{
			//	Realloc buffer
			dwProcessListLen = ((dwReturnValue + (CONSOLE_PROCESS_LIST_LAMBDA - 1)) & ~(CONSOLE_PROCESS_LIST_LAMBDA - 1));
			if (AllocBuffer(dwProcessListLen, &lpdwList))
				dwConAppTotal = dwReturnValue = ::GetConsoleProcessList(lpdwList, dwProcessListLen);
		}

		DISPOSE_BUF(&lpdwList);
	}

	//	If console is attached to 2 or more processes - current process is running from cmd.exe/ps.exe etc.
	//	Else wait for user action - key press ...
	if (dwConAppTotal < 2)
	{
		ShowResourceString(hOut, IDS_EXIT_MESSAGE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
		HANDLE hStdInput(::GetStdHandle(STD_INPUT_HANDLE));
		if (hStdInput)
		{
			::FlushConsoleInputBuffer(hStdInput);
			INPUT_RECORD ir = { 0 };
			do
			{
				DWORD dwEventsRead(0);
				if (!::ReadConsoleInputW(hStdInput, &ir, 1, &dwEventsRead))
					break;
			}
			while (ir.EventType != KEY_EVENT);
			::FlushConsoleInputBuffer(hStdInput);
		}
	}

	::SetUnhandledExceptionFilter(lpEFOriginal);
	return nRetCode;
}