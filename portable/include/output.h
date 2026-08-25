#ifndef PORTABLE_BOF_OUTPUT_H
#define PORTABLE_BOF_OUTPUT_H

#include "beacon.h"

#define BOF_OUTPUT_CAPACITY 4096U

typedef struct {
    char data[BOF_OUTPUT_CAPACITY];
    bof_u32 length;
    int type;
} bof_writer;

static void bof_flush(bof_writer *writer) {
    if (writer->length != 0U) {
        BeaconOutput(writer->type, writer->data, (int)writer->length);
        writer->length = 0U;
    }
}

static void bof_writer_init(bof_writer *writer, int type) {
    writer->length = 0U;
    writer->type = type;
}

static void bof_putc(bof_writer *writer, char value) {
    if (writer->length == BOF_OUTPUT_CAPACITY) {
        bof_flush(writer);
    }
    writer->data[writer->length++] = value;
}

static void bof_write(bof_writer *writer, const char *value, bof_uptr length) {
    bof_uptr index;
    for (index = 0U; index < length; index++) {
        bof_putc(writer, value[index]);
    }
}

static void bof_puts(bof_writer *writer, const char *value) {
    while (*value != '\0') {
        bof_putc(writer, *value++);
    }
}

static int bof_streq(const char *left, const char *right) {
    while (*left != '\0' && *right != '\0') {
        if (*left++ != *right++) {
            return 0;
        }
    }
    return *left == *right;
}

static void bof_put_uint(bof_writer *writer, unsigned long value) {
    char digits[3U * sizeof(unsigned long)];
    bof_u32 count = 0U;
    do {
        digits[count++] = (char)('0' + (value % 10UL));
        value /= 10UL;
    } while (value != 0UL);
    while (count != 0U) {
        bof_putc(writer, digits[--count]);
    }
}

static void bof_put_hex(bof_writer *writer, const bof_u8 *value, bof_uptr length) {
    static const char alphabet[] = "0123456789abcdef";
    bof_uptr index;
    for (index = 0U; index < length; index++) {
        bof_putc(writer, alphabet[value[index] >> 4U]);
        bof_putc(writer, alphabet[value[index] & 15U]);
    }
}

static void bof_error(const char *message) {
    bof_writer writer;
    bof_writer_init(&writer, CALLBACK_ERROR);
    bof_puts(&writer, message);
    bof_putc(&writer, '\n');
    bof_flush(&writer);
}

#endif
