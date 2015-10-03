// symlink.c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "symlink.h"

//-----------------------------------------------------------------
DWORD CreateSymLinkKey(HKEY   hLinkRootKey,
                       LPTSTR pszLinkSubKey,
                       LPTSTR pszLinkKey,
                       PHKEY  phLinkKey)
{
    DWORD status = 0, t = 0, size = 0;
    HKEY hKey = NULL, hTempKey = NULL;

    // Create (or open if already existing) the base symbolic
    // link key.

    status = RegCreateKeyEx(hLinkRootKey, pszLinkSubKey, 0, NULL,
                            REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS, NULL, &hKey, NULL);
    if (status != ERROR_SUCCESS) {
        return status;
    }

    // Create a volatile "link" key under base subkey opened above

    status = RegCreateKeyEx(hKey, pszLinkKey, 0, NULL,
                            REG_OPTION_VOLATILE |
                            REG_OPTION_CREATE_LINK,
                            KEY_ALL_ACCESS | KEY_CREATE_LINK,
                            NULL, phLinkKey, NULL);

    // the symbolic link key has been created but it doesn't link
    // to anything to yet

    RegCloseKey(hKey);
    return status;

} // CreateSymLinkKey

//-----------------------------------------------------------------
DWORD SetSymLink(HKEY   hLinkKey,
                 HKEY   hBaseRootKey,
                 LPTSTR pszBaseKey)
{
    DWORD status = 0;
    HKEY hKey = NULL;
    char sz[MAX_PATH];
	WCHAR szw[MAX_PATH];

    // Form the path to link to using kernel mode registry syntax

	if (hBaseRootKey == HKEY_LOCAL_MACHINE)
		wsprintf(sz, TEXT("\\Registry\\MACHINE\\%s"), pszBaseKey);
	else if (hBaseRootKey == HKEY_USERS)
		wsprintf(sz, TEXT("\\Registry\\USER\\%s"), pszBaseKey);
	else
		return ERROR_INVALID_PARAMETER;

	if (!MultiByteToWideChar(GetACP(), 0L, sz, -1, szw, sizeof(szw)/sizeof(WCHAR)))
		return GetLastError();

    // Store the link target in the special "SymbolicLinkValue"
    // REG_LINK value in the special link key to form the link.

    status = RegSetValueExW(hLinkKey, L"SymbolicLinkValue", 0,
                           REG_LINK, (LPBYTE)szw, 
                           lstrlen(sz) * sizeof(WCHAR));

    return status;

} // SetSymLink

//-----------------------------------------------------------------
DWORD OpenSymLink(HKEY   hRootKey,
                  LPTSTR pszKey,
                  PHKEY  phLinkKey)
{
    DWORD status = ERROR_SUCCESS;

    status = RegOpenKeyEx(hRootKey, pszKey, REG_OPTION_OPEN_LINK, 
                          KEY_ALL_ACCESS, phLinkKey);
    return status;

} // OpenSymLink

//-----------------------------------------------------------------
DWORD ClearSymLink(HKEY hLinkKey)
{
    DWORD status = 0;

    // Clear the link target from the special "SymbolicLinkValue"
    // REG_LINK value.

    status = RegDeleteValueW(hLinkKey, L"SymbolicLinkValue");
    return status;

} // ClearSymLink

//-----------------------------------------------------------------
DWORD DeleteSymLink(HKEY hRootKey, LPTSTR pszKey)
{
    DWORD status = ERROR_SUCCESS;
    HKEY hKey = NULL;

    // Open the symbolic link, clear the SymbolicLinkValue,
    // and delete the symbolic link key. We can't use the
    // normal user-mode RegDeleteKey routine because we have
    // to open the key a special way and the RegDeleteKey
    // performs the open internally. Use the ZwDeleteKey
    // routine instead.

    status = OpenSymLink(hRootKey, pszKey, &hKey);
    if (status == ERROR_SUCCESS) {

        status = ClearSymLink(hKey);
        _ZwDeleteKey(hKey);
		RegCloseKey(hKey);
    }

    return status;

} // DeleteSymLink
//End of File

