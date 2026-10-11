/* Invoke the unmodified Sliver Armory COFFLoader DLL like Sliver's extension. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (__cdecl *output_callback)(char *, int);
typedef int (__cdecl *load_and_run)(char *, uint32_t, output_callback);

static int saw_callback;
static int saw_user_name;
static int saw_sid;

static int contains(const char *haystack, size_t length, const char *needle)
{
    size_t needle_length = strlen(needle);
    if (needle_length > length) {
        return 0;
    }
    for (size_t i = 0; i <= length - needle_length; ++i) {
        if (memcmp(haystack + i, needle, needle_length) == 0) {
            return 1;
        }
    }
    return 0;
}

static int __cdecl receive_output(char *output, int length)
{
    if (output == NULL || length <= 0) {
        return 0;
    }
    saw_callback = 1;
    saw_user_name |= contains(output, (size_t)length, "UserName");
    saw_sid |= contains(output, (size_t)length, "S-1-");
    fwrite(output, 1, (size_t)length, stdout);
    return 0;
}

static unsigned char *read_object(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
        if (file != NULL) fclose(file);
        return NULL;
    }
    long size = ftell(file);
    if (size <= 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    unsigned char *object = malloc((size_t)size);
    if (object == NULL || fread(object, 1, (size_t)size, file) != (size_t)size) {
        free(object);
        fclose(file);
        return NULL;
    }
    fclose(file);
    *length = (size_t)size;
    return object;
}

static void write_u32(unsigned char **cursor, uint32_t value)
{
    memcpy(*cursor, &value, sizeof(value));
    *cursor += sizeof(value);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: coffloader-smoke.exe <COFFLoader.dll> <whoami.o>\n");
        return 2;
    }

    size_t object_length = 0;
    unsigned char *object = read_object(argv[2], &object_length);
    if (object == NULL || object_length > UINT32_MAX - 20) {
        fprintf(stderr, "cannot read BOF object: %s\n", argv[2]);
        free(object);
        return 1;
    }

    /* Beacon's argument parser expects an outer size followed by three
       length-prefixed fields: entrypoint, object bytes, and BOF arguments. */
    uint32_t input_length = (uint32_t)object_length + 19;
    unsigned char *input = calloc((size_t)input_length + 1, 1);
    if (input == NULL) {
        free(object);
        return 1;
    }
    unsigned char *cursor = input;
    write_u32(&cursor, input_length - 4);
    write_u32(&cursor, 3);
    memcpy(cursor, "go", 3);
    cursor += 3;
    write_u32(&cursor, (uint32_t)object_length);
    memcpy(cursor, object, object_length);
    cursor += object_length;
    write_u32(&cursor, 0);
    free(object);

    HMODULE loader = LoadLibraryA(argv[1]);
    if (loader == NULL) {
        fprintf(stderr, "cannot load COFFLoader DLL: %s (error %lu)\n", argv[1], GetLastError());
        free(input);
        return 1;
    }
    load_and_run run = (load_and_run)GetProcAddress(loader, "LoadAndRun");
    if (run == NULL) {
        fprintf(stderr, "COFFLoader DLL does not export LoadAndRun\n");
        FreeLibrary(loader);
        free(input);
        return 1;
    }

    int result = run((char *)input, input_length, receive_output);
    FreeLibrary(loader);
    free(input);
    if (result != 0 || !saw_callback || !saw_user_name || !saw_sid) {
        fprintf(stderr, "COFFLoader failed: result=%d callback=%d UserName=%d SID value=%d\n",
                result, saw_callback, saw_user_name, saw_sid);
        return 1;
    }
    puts("COFFLoader executed packaged whoami BOF successfully");
    return 0;
}
