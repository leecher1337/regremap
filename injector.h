#ifndef __INJECTOR_H__
#define __INJECTOR_H__

typedef HINSTANCE (WINAPI *ProcLoadLibrary)(char*);
typedef FARPROC (WINAPI *ProcGetProcAddress)(HMODULE, LPCSTR);
typedef DWORD (WINAPI *ProcResumeThread)(HANDLE);
typedef DWORD (WINAPI *ProcWaitForSingleObject)(HANDLE, DWORD);

typedef struct tagREDIRINFO {
	HKEY	hKey;
	char	szPath[MAX_PATH];
} REDIRINFO;

typedef struct tagHYPINJECT {
       ProcLoadLibrary    fnLoad;
       ProcGetProcAddress fnGetProc;
	   ProcResumeThread	  fnResumeThread;
	   ProcWaitForSingleObject fnWaitForSingleObject;
	   HANDLE hThread;
       char szADVAPI[sizeof("advapi32.dll")];
	   char szRegOverridePredefKey[sizeof("RegOverridePredefKey")];
	   char szRegCreateKeyEx[sizeof("RegCreateKeyEx")];
	   REDIRINFO aRedirKeys[6];
	   BOOL bWaitForMainThread;
	   DWORD dwResetStartTimeout;
} HYPINJECT;


void Injector_Init (HYPINJECT *pp);
char *Injector_GetLastError(DWORD *pdwLastErr);
void Injector_Override (HYPINJECT *pp, HKEY hKey, HKEY hRoot, char *pszSubKey);
BOOL Injector_OpenProcess (HYPINJECT *pp, DWORD PID);
BOOL Injector_CreateProcess (HYPINJECT *pp, DWORD dwDelay, LPCTSTR lpApplicationName, LPTSTR lpCommandLine, PROCESS_INFORMATION *ppi);
BOOL Injector_InjectFunc(HYPINJECT *pp, HANDLE hProc);

#endif
