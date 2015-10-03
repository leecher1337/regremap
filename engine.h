#include "injector.h"

BOOL Eng_EnablePrivilege (HANDLE hProcess, LPCTSTR lpPrivilegeName);
BOOL Eng_MapHKLM (char *pszUID, HYPINJECT *phInject, char *pszSYSTEM, char *pszSOFTWARE, char *pszSAM);
void Eng_UnmapHKLM(char *pszUID);
BOOL Eng_MapHKCU (char *pszUID, HYPINJECT *phInject, char *pszFile);
void Eng_UnmapHKCU(char *pszUID);
char *Eng_GetLastError(DWORD *pdwLastErr);
