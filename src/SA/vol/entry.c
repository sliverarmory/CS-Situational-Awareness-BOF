#include <windows.h>
#include "bofdefs.h"
#include "base.c"

#ifdef BOF
void vol(PCHAR args, ULONG length)
{
    datap   parser;
    char   *argDrive      = NULL;
    char    driveLetter   = '\0';
    wchar_t drivePath[8]  = {0};
    wchar_t volumeName[MAX_PATH] = {0};
    DWORD   serialNumber  = 0;


    BeaconDataParse(&parser, args, length);
    argDrive = BeaconDataExtract(&parser, NULL);

    if (argDrive && argDrive[0] != '\0')
    {
        driveLetter = (char)(argDrive[0] & ~0x20); /* force to upper      */
    }
    else
    {
        wchar_t curDir[MAX_PATH] = {0};
        if (KERNEL32$GetCurrentDirectoryW(MAX_PATH, curDir) && curDir[0])
        {
            driveLetter = (char)(curDir[0] & ~0x20);
        }
        else
        {
            driveLetter = 'C';
        }
    }


    drivePath[0] = (wchar_t)driveLetter;
    drivePath[1] = L':';
    drivePath[2] = L'\\';
    drivePath[3] = L'\0';

    if (!KERNEL32$GetVolumeInformationW(
            drivePath,
            volumeName,
            MAX_PATH,
            &serialNumber,
            NULL,
            NULL,
            NULL,
            0))
    {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] GetVolumeInformationW failed for drive %c:\\ (error %lu)\n",
            driveLetter,
            (unsigned long)KERNEL32$GetLastError());
        return;
    }

    if (volumeName[0] != L'\0')
    {
        internal_printf(" Volume in drive %c is %ls\n",
            driveLetter, volumeName);
    }
    else
    {
        internal_printf(" Volume in drive %c has no label.\n", driveLetter);
    }

    // Serial number is displayed as XXXX-XXXX
    internal_printf(" Volume Serial Number is %04X-%04X\n",
        (serialNumber >> 16) & 0xFFFF,
        serialNumber         & 0xFFFF);
}

VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    if (!bofstart())
    {
        return;
    }

    vol(Buffer, Length);

    printoutput(TRUE);
}

#else

int main()
{
    /* Stub for standalone build (scanbuild / leak checks) */
    return 0;
}

#endif