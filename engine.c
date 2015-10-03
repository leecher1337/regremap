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
 * Module:   engine.c
 * Descr.:   Simple routines for Registry remapping of all keys
 * License:  GPL 3
 * Date  :   12.02.2010
 * Changelog:
 *************************************************************/

// ------------------------- INCLUDES -------------------------

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "engine.h"
#include "symlink.h"

// ------------------------- DEFINES --------------------------

#define MY_REGKEY "Software\\RegRemap"

// ------------------------ VARIABLES -------------------------

static DWORD m_dwLastError = ERROR_SUCCESS;
static char m_szLastErr[256] = {0};

// ------------------------ PROTOTYPES ------------------------

static void Eng_Error (DWORD dwErr, char *pszFormat, ...) ;
static BOOL MapHKLMKey (char *pszUID, HKEY hKey, char *pszName, char *pszFile);

//-----------------------------------------------------------------
// Public
//-----------------------------------------------------------------

/* Eng_EnablePrivilege
 *
 * Description : Assigns the given process the needed privilege
 * Parameters  : hProcess			-	Process to assign Privilege to
 *				 lpPrivilegeName	-	Name of Privilege token to assign
 * Returns     : TRUE on success, FALSE on failure
 */
BOOL Eng_EnablePrivilege (HANDLE hProcess, LPCTSTR lpPrivilegeName)
{
	HANDLE hTok;
	TOKEN_PRIVILEGES tp;
	BOOL bRet = FALSE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (OpenProcessToken (hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
	{
		LookupPrivilegeValue (NULL, lpPrivilegeName, &tp.Privileges[0].Luid);
		if (!(bRet = AdjustTokenPrivileges (hTok, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0)))
		{
			Eng_Error (GetLastError(), "Cannot adjust privilege %s: ", lpPrivilegeName);
		}
		CloseHandle (hTok);
	}
	else
	{
		Eng_Error (GetLastError(), "Cannot open Process token: ");
	}
		
	return bRet;
}

//-----------------------------------------------------------------

/* Eng_MapHKCU
 *
 * Description : Remaps HKEY_CURRENT_USER to given Registry file
 * Parameters  : pszUID		-	UID for our virtual remap-Key (can be anything)
 *				 phInject	-	Injector instance handle to add remapping to
 *				 pszFile	-	Registry file to load
 * Returns     : TRUE on success, FALSE on failure
 */
BOOL Eng_MapHKCU (char *pszUID, HYPINJECT *phInject, char *pszFile)
{
	DWORD dwErr;
	char szKey[MAX_PATH];

	if (!pszUID) return TRUE;

	wsprintf (szKey, "EXT_%s_USER001", pszUID);
	if ((dwErr = RegLoadKey (HKEY_USERS, szKey, pszFile)) == ERROR_SUCCESS)
	{
		char szKeyCLS[MAX_PATH];

		// Link current user to the first user loaded
		Injector_Override (phInject, HKEY_CURRENT_USER, HKEY_USERS, szKey);
		wsprintf (szKeyCLS, "%s\\Software\\Classes", szKey);
		Injector_Override (phInject, HKEY_CLASSES_ROOT, HKEY_USERS, szKeyCLS);
		return TRUE;
	}
	else
	{
		Eng_Error (dwErr, "Cannot load user hive %s from %s: ", szKey, pszFile);
		return FALSE;
	}

	return FALSE;
}

//-----------------------------------------------------------------

/* Eng_UnmapHKCU
 *
 * Description : Unmaps assigned Keys previously loaded with Eng_MapHKCU
 * Parameters  : pszUID		-	UID for our virtual remap-Key used in Eng_MapHKCU
 */
void Eng_UnmapHKCU(char *pszUID)
{
	char szKey[MAX_PATH];

	wsprintf (szKey, "EXT_%s_USER001", pszUID);
	RegUnLoadKey (HKEY_USERS, szKey);
}

//-----------------------------------------------------------------

/* Eng_MapHKLM
 *
 * Description : Maps 3 Files as HKEY_LOCAL_MACHINE for pszUID to our virtual registry
 *				 Don't forget to unmap to delete the leftovers in the registry to avoid corruption!
 *				 You can set pszUID i.e. to the PID of the app you wanna hook
 * Parameters  : pszUID		-	UID for our virtual remap-Key used in Eng_MapHKCU
 *				 phInject	-	Injector instance handle to add remapping to
 *				 pszSYSTEM	-	File for SYSTEM hive to attach, can be NULL
 *				 pszSOFTWARE-	File for SOFTWARE hive to attach, can be NULL
 *				 pszSAM		-	File for SAM hive to attach, can be NULL
 * Returns     : TRUE on success, FALSE on failure
 */
BOOL Eng_MapHKLM (char *pszUID, HYPINJECT *phInject, char *pszSYSTEM, char *pszSOFTWARE, char *pszSAM)
{
	char szKey[MAX_PATH];
	HKEY hKey, hSubKey;
	DWORD dwErr;

	/* If we have nothing to do, succeed anyway */
	if (!pszSYSTEM && !pszSOFTWARE && !pszSAM)
		return TRUE;

	/* Create fake registry root */
	wsprintf (szKey, MY_REGKEY"\\%s\\HKEY_LOCAL_MACHINE", pszUID);
	if ((dwErr = RegCreateKeyEx(HKEY_LOCAL_MACHINE, szKey, 0, NULL,
                       REG_OPTION_VOLATILE, KEY_ALL_ACCESS, 
					   NULL, &hKey, NULL))  != ERROR_SUCCESS)
	{
		Eng_Error (dwErr, "Cannot create fake registry root in %s: ", MY_REGKEY"\\%s\\HKEY_LOCAL_MACHINE");
		return FALSE;
	}

	/* Map base keys */
	if (!MapHKLMKey (pszUID, hKey, "SYSTEM", pszSYSTEM) ||
		!MapHKLMKey (pszUID, hKey, "SOFTWARE", pszSOFTWARE) ||
		!MapHKLMKey (pszUID, hKey, "SAM", pszSAM))
	{
		Eng_UnmapHKLM(pszUID);
		RegCloseKey(hKey);
		return FALSE;
	}

	/* Create additional volatile symlinks */
	if (pszSYSTEM)
	{
		if (CreateSymLinkKey (hKey, "SYSTEM", "CurrentControlSet", &hSubKey) == ERROR_SUCCESS)
		{
			char szLinkTarget[MAX_PATH];

			wsprintf (szLinkTarget, "%s\\SYSTEM\\ControlSet001", szKey);
			SetSymLink (hSubKey, HKEY_LOCAL_MACHINE, szLinkTarget);
			RegCloseKey (hSubKey);
		}
	}

	RegCloseKey(hKey);
	Injector_Override (phInject, HKEY_LOCAL_MACHINE, HKEY_LOCAL_MACHINE, szKey);
	return TRUE;
}

//-----------------------------------------------------------------
/* Eng_UnmapHKLM
 *
 * Description : Unmaps assigned Keys previously loaded with Eng_MapHKLM
 * Parameters  : pszUID		-	UID for our virtual remap-Key used in Eng_MapHKLM
 */
void Eng_UnmapHKLM(char *pszUID)
{
	char szKey[MAX_PATH], szLink[MAX_PATH], *p;
	char *aszKeys[]={"SYSTEM", "SOFTWARE", "SAM"};
	int i;

	// First remove the symlinks
	p = szLink + wsprintf (szLink, MY_REGKEY"\\%s\\HKEY_LOCAL_MACHINE\\", pszUID);
	lstrcat (szLink, "SYSTEM\\CurrentControlSet");
	DeleteSymLink (HKEY_LOCAL_MACHINE, szLink);
	*p = 0;

	for (i=0; i<sizeof(aszKeys)/sizeof(aszKeys[0]); i++)
	{
		lstrcat (szLink, aszKeys[i]);
		DeleteSymLink (HKEY_LOCAL_MACHINE, szLink);
		*p = 0;
	}

	// Delete our mapping key
	*(p-1)=0;
	RegDeleteKey (HKEY_LOCAL_MACHINE, szLink);
	wsprintf (szLink, MY_REGKEY"\\%s", pszUID);
	RegDeleteKey (HKEY_LOCAL_MACHINE, szLink);

	// Unload external hives
	for (i=0; i<sizeof(aszKeys)/sizeof(aszKeys[0]); i++)
	{
		wsprintf (szKey, "EXT_%s_HKLM_%s", pszUID, aszKeys[i]);
		RegUnLoadKey (HKEY_LOCAL_MACHINE, szKey);
	}
}

//-----------------------------------------------------------------
/* Eng_GetLastError
 *
 * Description: Get last error that occured in this module
 * Parameters : pdwLastErr	-	Optional pointer to a variable that receives error code
 * Returns    : Error message
 */
char *Eng_GetLastError(DWORD *pdwLastErr)
{
	if (pdwLastErr) *pdwLastErr = m_dwLastError;
	return m_szLastErr;
}

//-----------------------------------------------------------------
// Static
//-----------------------------------------------------------------

static void Eng_Error (DWORD dwErr, char *pszFormat, ...) 
{
	char *p;
	va_list ap;

	m_dwLastError = dwErr;
	va_start(ap, pszFormat);
	_vsnprintf(m_szLastErr, sizeof(m_szLastErr), pszFormat, ap); 
	va_end(ap);
	p = m_szLastErr + FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, NULL, m_dwLastError,
		MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT), m_szLastErr, 0, NULL);
	wsprintf (p, " (%08X)", m_dwLastError);
}

//-----------------------------------------------------------------

static BOOL MapHKLMKey (char *pszUID, HKEY hKey, char *pszName, char *pszFile)
{
	char szKey[MAX_PATH];
	HKEY hSubKey;
	DWORD dwErr;
	BOOL bRet = TRUE;

	if (pszFile)
	{
		wsprintf (szKey, "EXT_%s_HKLM_%s", pszUID, pszName);
		if ((dwErr = RegLoadKey (HKEY_LOCAL_MACHINE, szKey, pszFile)) != ERROR_SUCCESS)
		{
			Eng_Error (dwErr, "Cannot load key %s from file %s: ", pszName, pszFile);
			return FALSE;
		}

		if ((dwErr = RegCreateKeyEx(hKey, pszName, 0, NULL,
                            REG_OPTION_VOLATILE |
                            REG_OPTION_CREATE_LINK,
                            KEY_ALL_ACCESS | KEY_CREATE_LINK,
                            NULL, &hSubKey, NULL)) != ERROR_SUCCESS)

		{
			Eng_Error (dwErr, "Cannot create link %s: ", pszName);
			return FALSE;
		}

		if ((dwErr = SetSymLink (hSubKey, HKEY_LOCAL_MACHINE, szKey)) != ERROR_SUCCESS)
		{
			Eng_Error (dwErr, "Cannot setup symlink %s in %s: ", szKey, pszName);
			bRet = FALSE;
		}

		RegCloseKey (hSubKey);
	}

	return bRet;
}
