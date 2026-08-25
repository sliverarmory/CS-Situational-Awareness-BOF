#include <windows.h>
#include "bofdefs.h"
#include "base.c"

#ifdef BOF

VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    datap   parser;
    char*   filename    = NULL;
    HANDLE  hFile       = INVALID_HANDLE_VALUE;
    DWORD   fileSize    = 0;
    DWORD   bytesRead   = 0;
    char*   fileContent = NULL;

    if (!bofstart())
    {
        return;
    }

    BeaconDataParse(&parser, Buffer, Length);
    filename = BeaconDataExtract(&parser, NULL);

    if (!filename || filename[0] == '\0')
    {
        internal_printf("[!] Usage: cat <filepath>\n");
        goto cleanup;
    }

    // Open the target file
    hFile = KERNEL32$CreateFileA(
        filename,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        internal_printf("[!] Failed to open '%s' (GetLastError: %lu)\n",
            filename, KERNEL32$GetLastError());
        goto cleanup;
    }

    // Get the file size
    fileSize = KERNEL32$GetFileSize(hFile, NULL);

    if (fileSize == INVALID_FILE_SIZE)
    {
        internal_printf("[!] GetFileSize failed (GetLastError: %lu)\n",
            KERNEL32$GetLastError());
        goto cleanup;
    }

    if (fileSize == 0)
    {
        internal_printf("[*] '%s' is empty.\n", filename);
        goto cleanup;
    }

    // Allocate read buffer
    fileContent = (char*)MSVCRT$calloc(fileSize + 1, 1);
    if (!fileContent)
    {
        internal_printf("[!] Memory allocation failed.\n");
        goto cleanup;
    }

    // Read file contents
    if (!KERNEL32$ReadFile(hFile, fileContent, fileSize, &bytesRead, NULL))
    {
        internal_printf("[!] ReadFile failed (GetLastError: %lu)\n",
            KERNEL32$GetLastError());
        goto cleanup;
    }

    fileContent[bytesRead] = '\0';

    internal_printf("%s", fileContent);
    internal_printf("\n");

cleanup:
    if (fileContent)
    {
        MSVCRT$free(fileContent);
        fileContent = NULL;
    }
    if (hFile != INVALID_HANDLE_VALUE)
    {
        KERNEL32$CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }

    printoutput(TRUE);
}

#else

int main()
{
    // Stub for scanbuild / static analysis / leak checks
    return 0;
}

#endif
