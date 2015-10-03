// symlink.h

DWORD CreateSymLinkKey(HKEY, LPTSTR, LPTSTR, PHKEY);
DWORD SetSymLink(HKEY, HKEY, LPTSTR);
DWORD OpenSymLink(HKEY, LPTSTR, PHKEY);
DWORD ClearSymLink(HKEY);
DWORD DeleteSymLink(HKEY, LPTSTR);

//---------------------------------------------------------
// Excerpts from wdm.h or ntddk.h
//---------------------------------------------------------

typedef LONG NTSTATUS;

NTSTATUS (WINAPI *_ZwDeleteKey)(
    IN HANDLE KeyHandle
    );
