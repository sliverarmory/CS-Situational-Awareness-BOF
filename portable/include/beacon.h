#ifndef PORTABLE_BOF_BEACON_H
#define PORTABLE_BOF_BEACON_H

/* Minimal, SDK-independent Beacon ABI used by the portable BOFs. */

typedef __INT32_TYPE__ bof_i32;
typedef __UINT8_TYPE__ bof_u8;
typedef __UINT16_TYPE__ bof_u16;
typedef __UINT32_TYPE__ bof_u32;
typedef __UINT64_TYPE__ bof_u64;
typedef __UINTPTR_TYPE__ bof_uptr;
typedef __INTPTR_TYPE__ bof_sptr;

typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} datap;

#if defined(_WIN32)
#define BOF_IMPORT __declspec(dllimport)
#else
#define BOF_IMPORT extern
#endif

BOF_IMPORT void BeaconDataParse(datap *parser, char *buffer, int size);
BOF_IMPORT int BeaconDataInt(datap *parser);
BOF_IMPORT short BeaconDataShort(datap *parser);
BOF_IMPORT int BeaconDataLength(datap *parser);
BOF_IMPORT char *BeaconDataExtract(datap *parser, int *size);
BOF_IMPORT void BeaconOutput(int type, char *data, int len);

#define CALLBACK_OUTPUT 0
#define CALLBACK_ERROR 13

#endif
