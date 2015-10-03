/*************************************************************
 *  Registry Redirector
 *
 *  (C)oded by leecher@dose.0wnz.at, 2010
 *
 * This application redirects registry calls to Registry dump
 * files, so that you can "shim" your application to a foreign
 * registry.
 *
 * This may become handy if you want to check the registry
 * of another machine with various checking tools that are
 * designed for the checking of a live System.
 * Note that the application must use the normal WIN32 API
 * for registry Access. If the app is checking via Native API,
 * this won't work.
 *
 * Be aware that reads AND WRITES are redirected, so only
 * use this tool on copies of your original Registry files.
 * It may be a good idea to use this tool in a PE environment.
 *
 *************************************************************
 * Module:   injector.c
 * Descr.:   Creates a remote thread in the target process that
 *           handles the redirection of the registry
 * License:  GPL 3
 * Date  :   12.02.2010
 * Changelog:
 *************************************************************/

// ------------------------- INCLUDES -------------------------

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "injector.h"

// ------------------------- DEFINES --------------------------

typedef FARPROC (WINAPI *RegOver)(HKEY, HKEY);
typedef FARPROC (WINAPI *RegCreate)(HKEY, LPCTSTR, DWORD, LPTSTR, DWORD, 
									REGSAM, LPSECURITY_ATTRIBUTES, PHKEY,
									LPDWORD);

#define REG_CLASSES_SPECIAL_TAG 2
#define TagSpecialClassesHandle( Handle )                                       \
 ( *Handle = (( HKEY )((( ULONG_PTR )( *Handle )) | REG_CLASSES_SPECIAL_TAG )))


// ------------------------ VARIABLES -------------------------

static DWORD m_dwLastError = ERROR_SUCCESS;
static char m_szLastErr[256] = {0};

// ------------------------ PROTOTYPES ------------------------

static void Inj_Error (char *pszFormat, ...) ;

//-----------------------------------------------------------------
// Remote code
//-----------------------------------------------------------------

#pragma check_stack (off)
DWORD WINAPI ThreadProc (LPVOID lpParameter)
{
	HKEY hKey = 0;
	DWORD dwr=0, dwWait=INFINITE;

	HYPINJECT* pp = (HYPINJECT*)lpParameter;
	int i;
	HKEY hkeyTab[sizeof(pp->aRedirKeys)/sizeof(pp->aRedirKeys[0])]={0};

	// load advapi32.dll 
	HMODULE hadv = pp->fnLoad (pp->szADVAPI);

	ProcGetProcAddress GetProc = (ProcGetProcAddress)(pp->fnGetProc);
	RegOver RegOverride = (RegOver)GetProc(hadv,pp->szRegOverridePredefKey) ;
	RegCreate RegCreateK = (RegCreate)GetProc(hadv, pp->szRegCreateKeyEx ) ;

	// Create our substitute keys 
	for (i=0; i<sizeof(pp->aRedirKeys)/sizeof(pp->aRedirKeys[0]); i++)
	{
		if (pp->aRedirKeys[i].hKey)
		{
			if (RegCreateK (pp->aRedirKeys[i].hKey, pp->aRedirKeys[i].szPath, 0, NULL, 0, 
					KEY_ALL_ACCESS, NULL, &hKey, &dwr) == ERROR_SUCCESS)
			{
				hkeyTab[i] = hKey;
				// if (i == 0) TagSpecialClassesHandle(hKey);
				RegOverride ((HKEY)(i | 0x80000000), hKey);
			}
		}
	}

	// Resume process
	if (pp->hThread)
	{
		if (pp->fnResumeThread(pp->hThread) != 0xFFFFFFFF && pp->bWaitForMainThread)
		// Some libs may f*ck up because of DLL_THREAD_ATTACH/DETACH calls issued during init
		// So we may block until main thread terminates to not confuse these DLLs
		if (pp->dwResetStartTimeout) dwWait = pp->dwResetStartTimeout;
			if (pp->fnWaitForSingleObject (pp->hThread, dwWait) == WAIT_TIMEOUT)
			{
				// Re-override associations after a given time to be sure that
				// it hasn't been reset by the app
				for (i=0; i<sizeof(pp->aRedirKeys)/sizeof(pp->aRedirKeys[0]); i++)
				{
					if (hkeyTab[i]) RegOverride ((HKEY)(i | 0x80000000), hkeyTab[i]);
				}
				pp->fnWaitForSingleObject (pp->hThread, INFINITE);
			}
			
	}
	return 0;
}
static void AfterThreadProc (void) { }
#pragma check_stack

//-----------------------------------------------------------------
// Public
//-----------------------------------------------------------------

/* Injector_Init
 *
 * Description: Sets up Injector structure with default values
 * Parameters : pp		-	Structure to initialize
 */
void Injector_Init (HYPINJECT *pp)
{
	HYPINJECT hypInject = {0};
	HMODULE hk = GetModuleHandle ("kernel32.dll");

	memset (pp, 0, sizeof(HYPINJECT));
	pp->fnLoad = (ProcLoadLibrary)GetProcAddress (hk, "LoadLibraryA");
	pp->fnGetProc = (ProcGetProcAddress)GetProcAddress (hk, "GetProcAddress");
	pp->fnResumeThread = (ProcResumeThread)GetProcAddress (hk, "ResumeThread");
	pp->fnWaitForSingleObject = (ProcWaitForSingleObject)GetProcAddress (hk, "WaitForSingleObject");
	lstrcpy (pp->szADVAPI, "advapi32.dll");
	lstrcpy (pp->szRegOverridePredefKey, "RegOverridePredefKey");
	lstrcpy (pp->szRegCreateKeyEx, "RegCreateKeyExA");
	pp->dwResetStartTimeout = 5000;
	return;
}

//-----------------------------------------------------------------

/* Injector_GetLastError
 *
 * Description: Get last error that occured in this module
 * Parameters : pdwLastErr	-	Optional pointer to a variable that receives error code
 * Returns    : Error message
 */
char *Injector_GetLastError(DWORD *pdwLastErr)
{
	if (pdwLastErr) *pdwLastErr = m_dwLastError;
	return m_szLastErr;
}

//-----------------------------------------------------------------

/* Injector_Override
 *
 * Description: Set base Keys you want to override
 * Parameters : pp			-	Injector instance structure
 *				hKey		-	Root key which you want to override (HKLM/HKCU/HKCR,...)
 *				hRoot		-	Root Key of registry key where hKey will be redirected to
 *				pszSubKey	-	Subkey of hRoot where hKey will be redirected to
 */
void Injector_Override (HYPINJECT *pp, HKEY hKey, HKEY hRoot, char *pszSubKey)
{
	REDIRINFO *pInfo;

	pInfo = &pp->aRedirKeys[(DWORD)hKey^0x80000000];
	pInfo->hKey = hRoot;
	lstrcpyn (pInfo->szPath, pszSubKey, sizeof(pInfo->szPath));
}

//-----------------------------------------------------------------

/* Injector_OpenProcess
 *
 * Description : Inject into running process
 * Parameters  : pp			-	Injector instance structure
 *				 PID		-	Process ID of target process
 * Returns     : TRUE on success, FALSE on failure
 */
BOOL Injector_OpenProcess (HYPINJECT *pp, DWORD PID)
{
	BOOL bRet = FALSE;
	HANDLE hProc = OpenProcess(
		PROCESS_QUERY_INFORMATION |  
		PROCESS_CREATE_THREAD     |
		PROCESS_VM_OPERATION      |
		PROCESS_VM_WRITE,           
		FALSE, PID);

	if (!hProc)
	{
		Inj_Error ("OpenProcess for PID %d failed: ", PID);
		return FALSE;
	}
	bRet = Injector_InjectFunc (pp, hProc);
	CloseHandle (hProc);
	return bRet;
}

//-----------------------------------------------------------------

/* Injector_CreateProcess
 *
 * Description : Start Application and inject into it
 * Parameters  : pp			-	Injector instance structure
 *				 dwDelay	-	Delay to wait for after startup before injecting. Should be 0 normally.
 *				 lpApplicationName - Path and filename of application to start
 *				 lpCommandLine     - Commandline args like with CreateProcess, can be NULL
 *				 ppi		-	[OUT] PROCESS_INFORMATION from CreateProcess
 * Returns     : TRUE on success, FALSE on failure
 */
BOOL Injector_CreateProcess (HYPINJECT *pp, DWORD dwDelay, LPCTSTR lpApplicationName, LPTSTR lpCommandLine, PROCESS_INFORMATION *ppi)
{
	BOOL bRet = FALSE;
	STARTUPINFO sui={0};

	if (!CreateProcess (lpApplicationName, lpCommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL,
		NULL, &sui,ppi))
	{
		Inj_Error ("CreateProcess for %s failed: ", lpApplicationName);
		return FALSE;
	}

	if (dwDelay || !DuplicateHandle (GetCurrentProcess(), ppi->hThread, ppi->hProcess, &pp->hThread, PROCESS_ALL_ACCESS, FALSE, 0))
		pp->hThread = NULL;

	if (!pp->hThread)
	{
		ResumeThread (ppi->hThread);
		WaitForInputIdle(ppi->hProcess, dwDelay);
		SuspendThread (ppi->hThread);
	}
	else pp->bWaitForMainThread = TRUE;

	bRet = Injector_InjectFunc (pp, ppi->hProcess);
	if (!pp->hThread) ResumeThread (ppi->hThread);
	return bRet;
}

//-----------------------------------------------------------------

/* Injector_InjectFunc
 *
 * Description : Inject our redirection code to the process
 * Parameters  : pp			-	Injector instance structure
 *				 hProc		-	Handle to the process where wo should inject to
 * Returns     : TRUE on success, FALSE on failure
 */
BOOL Injector_InjectFunc(HYPINJECT *pp, HANDLE hProc)
{
	PVOID pCode, pData;
	HANDLE hThread;
	DWORD cbCodeSize = (BYTE*)AfterThreadProc - (BYTE*)ThreadProc;
      
	if (pCode = VirtualAllocEx (hProc,NULL,cbCodeSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE))
	{
		if (WriteProcessMemory(hProc,pCode,(LPVOID)(DWORD)&ThreadProc,cbCodeSize,NULL))
		{
			if (pData = VirtualAllocEx (hProc,NULL, sizeof (HYPINJECT), MEM_COMMIT, PAGE_EXECUTE_READWRITE))
			{
				if (WriteProcessMemory (hProc, pData, pp, sizeof (HYPINJECT), NULL))
				{
					if (hThread = CreateRemoteThread(hProc,NULL,0,(LPTHREAD_START_ROUTINE)pCode,pData,0,NULL))
					{
						if (!(pp->bWaitForMainThread && pp->hThread))
						{
							WaitForSingleObject (hThread, INFINITE);
							CloseHandle(hThread);
						}
						return TRUE;
					}
					else
					{
						Inj_Error ("CreateRemoteThread failed: ");
					}
				}
				else
				{
					Inj_Error ("Error writing Session data (%d bytes) to target process", sizeof (HYPINJECT));
				}
				VirtualFreeEx (hProc, pData, 0, MEM_RELEASE);
			}
			else
			{
				Inj_Error ("Error allocating Session data (%d bytes) in target process", sizeof (HYPINJECT));
			}

		}
		else
		{			
			Inj_Error ("Error writing Thread routine (%d bytes) to target process", cbCodeSize);
		}
		VirtualFreeEx (hProc, pCode, 0, MEM_RELEASE);
	}
	else
	{
		Inj_Error ("Error allocating memory for Thread routine (%d bytes) in target process", cbCodeSize);
		
	}
	return FALSE;
}

//-----------------------------------------------------------------
//-----------------------------------------------------------------

// Set last error message
static void Inj_Error (char *pszFormat, ...) 
{
	char *p;
	va_list ap;

	m_dwLastError = GetLastError();
	va_start(ap, pszFormat);
	_vsnprintf(m_szLastErr, sizeof(m_szLastErr), pszFormat, ap); 
	va_end(ap);
	p = m_szLastErr + FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, NULL, m_dwLastError,
		MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT), m_szLastErr, 0, NULL);
	wsprintf (p, " (%08X)", m_dwLastError);
}
