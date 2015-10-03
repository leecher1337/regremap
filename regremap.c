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
 * Module:   regremap.c
 * Descr.:   Main application Commandline version
 * License:  GPL 3
 * Date  :   12.02.2010
 * Changelog:
 *************************************************************/

// ------------------------- INCLUDES -------------------------

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "engine.h"
#include "symlink.h"

//-----------------------------------------------------------------
// EIP
//-----------------------------------------------------------------

int main (int argc, char **argv)
{
	HYPINJECT hInject;
	PROCESS_INFORMATION pi={0};
	int iKeys=0, i, j, dwDelay = 0;
	char *pszApp = NULL, *pszArgs = NULL, *pszSYSTEM = NULL, *pszSOFTWARE = NULL, *pszSAM = NULL, *pszNTUSER = NULL;
	char szID[16];

	typedef struct
	{
		char *pszArg;
		char cTyp;
		void *pVal;
	} TYP_ARGTBL;
	TYP_ARGTBL aArgs[] = {
		{"x",	's', &pszApp},
		{"p",	's', &pszArgs},
		{"sys",	's', &pszSYSTEM},
		{"sw",	's', &pszSOFTWARE},
		{"sam",	's', &pszSAM},
		{"usr",	's', &pszNTUSER},
		{"dly",	'd', &dwDelay},
		{"rst",	'd', &hInject.dwResetStartTimeout}
	};

	Injector_Init(&hInject);
	printf ("Registry Remapper, (C) by leecher@dose.0wnz.at\n\n");

	/* Parse commandline */
	if (argc<2)
	{
		fprintf (stderr, "Usage:\n"
			"%s\t<-x Application> [-p Arguments] [-sys SYSTEM-Hive] [-sw SOFTWARE-Hive] [-sam SAM-Hive] \n"
			"\t\t[-usr NTUSER-Hive] [-dly Injection-Delay] [-rst ResetHive-Timeout] [-c ID]\n\n"
			"\t-dly nnn [%04d]\tOnly use this if you are experiencing problems. Delays injection by nnn ms\n"
			"\t-rst nnn [%04d]\tSome apps may need a refresh of our Remappings after startup. This shouldn't\n"
			"\t             \tharm and may be a good idea. Timeout is in ms.\n"
			"\t-c ID\tIf this app crashes unexpectedly, cleanup Registry leftovers with this function\n\n",
			argv[0], dwDelay, hInject.dwResetStartTimeout);
		return EXIT_FAILURE;
	}

	for (i=1; i<argc; i++)
	{
		if (argv[i][0]=='-')
		{
			if (argc <= i-1)
			{
				fprintf (stderr, "Option %s: Argument missing\n", argv[i]);
				return EXIT_FAILURE;
			}

			if (lstrcmp(argv[i], "-c") == 0)
			{
				Eng_UnmapHKLM (argv[i]);
				Eng_UnmapHKCU (argv[i]);
				return EXIT_SUCCESS;
			}

			for (j=0; j<sizeof(aArgs)/sizeof(aArgs[0]); j++)
			{
				if (lstrcmp (&argv[i][1], aArgs[j].pszArg) == 0)
				{
					switch (aArgs[j].cTyp)
					{
					case 's': *((char**)aArgs[j].pVal) = argv[++i]; break;
					case 'd': *((DWORD*)aArgs[j].pVal) = atol(argv[++i]); break;
					}
					break;
				}
			}

			if (j==sizeof(aArgs)/sizeof(aArgs[0]))
			{
				fprintf (stderr, "Unknown argument: %s\n", argv[i]);
				return EXIT_FAILURE;
			}
		}
		else
		{
			fprintf (stderr, "Unexpected parameter: %s\n", argv[i]);
			return EXIT_FAILURE;
		}
	}

	/* Initialize */
	if (!Eng_EnablePrivilege (GetCurrentProcess(), SE_RESTORE_NAME))
	{
		fprintf (stderr, "%s\n", Eng_GetLastError(NULL));
		return EXIT_FAILURE;
	}

	if (!(*(FARPROC *)&_ZwDeleteKey = GetProcAddress (GetModuleHandle ("ntdll.dll"), "NtDeleteKey")))
	{
		fprintf (stderr, "Cannot find ZwDeleteKey in ntdll.dll\n");
		return EXIT_FAILURE;
	}

	wsprintf (szID, "%d", GetCurrentProcessId());
	printf ("Using ID %s\n", szID);

	/* Do the real work */
	printf ("Mapping registry entries...");
	if (Eng_MapHKLM (szID, &hInject, pszSYSTEM, pszSOFTWARE, pszSAM))
	{
		// Now map the fuckin' users
		if (!Eng_MapHKCU (szID, &hInject, pszNTUSER))
		{
			fprintf (stderr, "%s\n", Eng_GetLastError(NULL));
		}

		// Now start the process and inject the overrides
		printf ("OK\nStarting target process...\n");
		if (Injector_CreateProcess (&hInject, dwDelay, pszApp, pszArgs, &pi))
		{
			WaitForSingleObject (pi.hProcess, INFINITE);
		}
		else
		{
			fprintf (stderr, "%s\n", Injector_GetLastError(NULL));
		}

		// Finally clean up the mess
		printf ("Cleaning up...");
		Eng_UnmapHKLM (szID);
		Eng_UnmapHKCU (szID);
		printf ("OK\n");
	}
	else
	{
		fprintf (stderr, "%s\n", Eng_GetLastError(NULL));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
