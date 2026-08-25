#include "beacon.h"
#include "output.h"

#if defined(_WIN32)
#error "posix.c implements only Linux and Darwin BOFs"
#endif

#if (defined(BOF_COMMAND_CACLS) + defined(BOF_COMMAND_ENUM_LOCAL_SESSIONS) + \
     defined(BOF_COMMAND_FIND_LOADED_MODULE) + defined(BOF_COMMAND_LISTMODS) + \
     defined(BOF_COMMAND_NETLOCALGROUP) + defined(BOF_COMMAND_NETLOGGEDON) + \
     defined(BOF_COMMAND_NETLOGGEDON2) + defined(BOF_COMMAND_NETUSER) + \
     defined(BOF_COMMAND_NETUSERENUM)) != 1
#error "define exactly one BOF_COMMAND_* macro"
#endif

#define POSIX_F_OK 0
#define POSIX_X_OK 1
#define POSIX_W_OK 2
#define POSIX_R_OK 4
#define POSIX_O_RDONLY 0
#define POSIX_TEXT_CAPACITY 4096U

typedef void posix_file;
typedef unsigned int posix_uid;
typedef unsigned int posix_gid;

extern int access(const char *path, int mode);
extern int getpid(void);
extern posix_uid geteuid(void);
extern int open(const char *path, int flags, ...);
extern bof_sptr read(int descriptor, void *buffer, bof_uptr length);
extern int close(int descriptor);
extern posix_file *popen(const char *command, const char *mode);
extern bof_uptr fread(void *buffer, bof_uptr size, bof_uptr count, posix_file *stream);
extern int pclose(posix_file *stream);

typedef struct posix_group {
    char *name;
    char *password;
    posix_gid gid;
    char **members;
} posix_group;

#if defined(BOF_DARWIN)
typedef struct posix_passwd {
    char *name;
    char *password;
    posix_uid uid;
    posix_gid gid;
    long change;
    char *class_name;
    char *gecos;
    char *directory;
    char *shell;
    long expire;
    int fields;
} posix_passwd;
#else
typedef struct posix_passwd {
    char *name;
    char *password;
    posix_uid uid;
    posix_gid gid;
    char *gecos;
    char *directory;
    char *shell;
} posix_passwd;
#endif

extern void setpwent(void);
extern posix_passwd *getpwent(void);
extern void endpwent(void);
extern posix_passwd *getpwnam(const char *name);
extern posix_passwd *getpwuid(posix_uid uid);
extern void setgrent(void);
extern posix_group *getgrent(void);
extern void endgrent(void);
extern posix_group *getgrnam(const char *name);
extern posix_group *getgrgid(posix_gid gid);

#if defined(BOF_DARWIN)
extern unsigned int _dyld_image_count(void);
extern const char *_dyld_get_image_name(unsigned int index);
extern const char *getprogname(void);
#endif

static int posix_ascii_lower(int value) {
    if (value >= 'A' && value <= 'Z') {
        return value + ('a' - 'A');
    }
    return value;
}

static int posix_contains_casefold(const char *value, const char *needle) {
    bof_uptr value_index;
    bof_uptr needle_index;
    if (needle == (const char *)0 || *needle == '\0') {
        return 1;
    }
    if (value == (const char *)0) {
        return 0;
    }
    for (value_index = 0U; value[value_index] != '\0'; value_index++) {
        for (needle_index = 0U; needle[needle_index] != '\0'; needle_index++) {
            if (value[value_index + needle_index] == '\0' ||
                posix_ascii_lower((unsigned char)value[value_index + needle_index]) !=
                    posix_ascii_lower((unsigned char)needle[needle_index])) {
                break;
            }
        }
        if (needle[needle_index] == '\0') {
            return 1;
        }
    }
    return 0;
}

static int posix_copy_string(char *destination, bof_uptr capacity, const char *source) {
    bof_uptr index = 0U;
    if (capacity == 0U) {
        return 0;
    }
    if (source != (const char *)0) {
        while (source[index] != '\0' && index + 1U < capacity) {
            destination[index] = source[index];
            index++;
        }
        if (source[index] != '\0') {
            destination[0] = '\0';
            return 0;
        }
    }
    destination[index] = '\0';
    return 1;
}

static int posix_extract_string(datap *parser, const char **value) {
    int length = 0;
    char *raw = BeaconDataExtract(parser, &length);
    int index;
    *value = "";
    if (raw == (char *)0 || length <= 0) {
        return 0;
    }
    for (index = 0; index < length; index++) {
        if (raw[index] == '\0') {
            *value = raw;
            return 1;
        }
    }
    return 0;
}

static int posix_extract_utf16(datap *parser, char *output, bof_uptr capacity) {
    int byte_length = 0;
    const bof_u8 *raw = (const bof_u8 *)BeaconDataExtract(parser, &byte_length);
    bof_uptr input_index = 0U;
    bof_uptr output_index = 0U;
    if (capacity == 0U) {
        return 0;
    }
    output[0] = '\0';
    if (raw == (const bof_u8 *)0 || byte_length < 2 || (byte_length & 1) != 0) {
        return 0;
    }
    while (input_index + 1U < (bof_uptr)byte_length) {
        bof_u32 codepoint = (bof_u32)raw[input_index] | ((bof_u32)raw[input_index + 1U] << 8U);
        input_index += 2U;
        if (codepoint == 0U) {
            output[output_index] = '\0';
            return 1;
        }
        if (codepoint >= 0xd800U && codepoint <= 0xdbffU) {
            bof_u32 low;
            if (input_index + 1U >= (bof_uptr)byte_length) {
                return 0;
            }
            low = (bof_u32)raw[input_index] | ((bof_u32)raw[input_index + 1U] << 8U);
            if (low < 0xdc00U || low > 0xdfffU) {
                return 0;
            }
            input_index += 2U;
            codepoint = 0x10000U + ((codepoint - 0xd800U) << 10U) + (low - 0xdc00U);
        } else if (codepoint >= 0xdc00U && codepoint <= 0xdfffU) {
            return 0;
        }
        if (codepoint < 0x80U) {
            if (output_index + 1U >= capacity) return 0;
            output[output_index++] = (char)codepoint;
        } else if (codepoint < 0x800U) {
            if (output_index + 2U >= capacity) return 0;
            output[output_index++] = (char)(0xc0U | (codepoint >> 6U));
            output[output_index++] = (char)(0x80U | (codepoint & 0x3fU));
        } else if (codepoint < 0x10000U) {
            if (output_index + 3U >= capacity) return 0;
            output[output_index++] = (char)(0xe0U | (codepoint >> 12U));
            output[output_index++] = (char)(0x80U | ((codepoint >> 6U) & 0x3fU));
            output[output_index++] = (char)(0x80U | (codepoint & 0x3fU));
        } else {
            if (output_index + 4U >= capacity) return 0;
            output[output_index++] = (char)(0xf0U | (codepoint >> 18U));
            output[output_index++] = (char)(0x80U | ((codepoint >> 12U) & 0x3fU));
            output[output_index++] = (char)(0x80U | ((codepoint >> 6U) & 0x3fU));
            output[output_index++] = (char)(0x80U | (codepoint & 0x3fU));
        }
    }
    return 0;
}

static void posix_put_yes_no(bof_writer *writer, int value) {
    bof_puts(writer, value ? "yes" : "no");
    bof_putc(writer, '\n');
}

static void posix_put_summary(bof_writer *writer, const char *label, unsigned long count) {
    bof_puts(writer, label);
    bof_put_uint(writer, count);
    bof_putc(writer, '\n');
}

static int posix_has_wildcard(const char *path) {
    while (*path != '\0') {
        if (*path == '*' || *path == '?' || *path == '[') {
            return 1;
        }
        path++;
    }
    return 0;
}

#if defined(BOF_COMMAND_CACLS)

static void posix_cacls(datap *parser) {
    char path[POSIX_TEXT_CAPACITY];
    bof_writer writer;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "POSIX current-process file access:\n");
    if (!posix_extract_utf16(parser, path, sizeof(path)) || path[0] == '\0') {
        bof_error("a UTF-16 file path is required");
        posix_put_summary(&writer, "Total entries: ", 0UL);
        bof_flush(&writer);
        return;
    }
    bof_puts(&writer, "Path: "); bof_puts(&writer, path); bof_putc(&writer, '\n');
    if (posix_has_wildcard(path)) {
        bof_error("unsupported: wildcard ACL queries are not available on POSIX");
        bof_puts(&writer, "Exists: not checked\n");
        posix_put_summary(&writer, "Total entries: ", 0UL);
        bof_flush(&writer);
        return;
    }
    if (access(path, POSIX_F_OK) != 0) {
        bof_error("file or directory does not exist, or cannot be inspected");
        bof_puts(&writer, "Exists: no\n");
        posix_put_summary(&writer, "Total entries: ", 0UL);
        bof_flush(&writer);
        return;
    }
    bof_puts(&writer, "Exists: yes\n");
    bof_puts(&writer, "Readable: "); posix_put_yes_no(&writer, access(path, POSIX_R_OK) == 0);
    bof_puts(&writer, "Writable: "); posix_put_yes_no(&writer, access(path, POSIX_W_OK) == 0);
    bof_puts(&writer, "Executable/searchable: "); posix_put_yes_no(&writer, access(path, POSIX_X_OK) == 0);
    posix_put_summary(&writer, "Total entries: ", 1UL);
    bof_flush(&writer);
}

#endif

#if defined(BOF_COMMAND_ENUM_LOCAL_SESSIONS) || defined(BOF_COMMAND_NETLOGGEDON) || defined(BOF_COMMAND_NETLOGGEDON2)

static void posix_emit_session_line(bof_writer *writer, const char *line, bof_uptr length, int structured) {
    if (structured) {
        bof_puts(writer, "-----------Logged on User-----------\nSession: ");
        bof_write(writer, line, length);
        bof_puts(writer, "\n---------End Logged on User---------\n");
    } else {
        bof_write(writer, line, length);
        bof_putc(writer, '\n');
    }
}

static void posix_list_sessions(const char *heading, int structured) {
    char input[1024];
    char line[POSIX_TEXT_CAPACITY];
    bof_uptr line_length = 0U;
    bof_uptr amount;
    unsigned long count = 0UL;
    posix_file *stream;
    bof_writer writer;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, heading);
    bof_putc(&writer, '\n');
    stream = popen("/usr/bin/who", "r");
    if (stream == (posix_file *)0) {
        bof_error("unable to execute /usr/bin/who");
        posix_put_summary(&writer, "Total sessions: ", 0UL);
        bof_flush(&writer);
        return;
    }
    while ((amount = fread(input, 1U, sizeof(input), stream)) != 0U) {
        bof_uptr index;
        for (index = 0U; index < amount; index++) {
            if (input[index] == '\n') {
                if (line_length != 0U) {
                    posix_emit_session_line(&writer, line, line_length, structured);
                    count++;
                    line_length = 0U;
                }
            } else if (line_length + 1U < sizeof(line)) {
                line[line_length++] = input[index];
            }
        }
    }
    if (line_length != 0U) {
        posix_emit_session_line(&writer, line, line_length, structured);
        count++;
    }
    if (pclose(stream) != 0) {
        bof_error("/usr/bin/who returned an error");
    }
    posix_put_summary(&writer, "Total sessions: ", count);
    bof_flush(&writer);
}

static int posix_require_local_server(datap *parser) {
    char server[POSIX_TEXT_CAPACITY];
    if (!posix_extract_utf16(parser, server, sizeof(server))) {
        bof_error("a UTF-16 server argument is required (empty selects the local host)");
        return 0;
    }
    if (server[0] != '\0') {
        bof_error("unsupported: remote computer queries are not available on POSIX");
        return 0;
    }
    return 1;
}

static void posix_empty_sessions(const char *heading) {
    bof_writer writer;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, heading);
    bof_putc(&writer, '\n');
    posix_put_summary(&writer, "Total sessions: ", 0UL);
    bof_flush(&writer);
}

#endif

#if defined(BOF_COMMAND_FIND_LOADED_MODULE) || defined(BOF_COMMAND_LISTMODS)

static int posix_same_string(const char *left, const char *right) {
    if (left == (const char *)0 || right == (const char *)0) return 0;
    while (*left != '\0' && *right != '\0' && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

#if !defined(BOF_DARWIN)
static int posix_current_process_name(char *output, bof_uptr capacity) {
    int descriptor;
    bof_sptr amount;
    if (capacity < 2U) return 0;
    descriptor = open("/proc/self/comm", POSIX_O_RDONLY);
    if (descriptor < 0) return 0;
    amount = read(descriptor, output, capacity - 1U);
    (void)close(descriptor);
    if (amount <= 0) return 0;
    output[(bof_uptr)amount] = '\0';
    while (amount > 0 && (output[amount - 1] == '\n' || output[amount - 1] == '\r')) {
        output[--amount] = '\0';
    }
    return amount > 0;
}
#endif

static const char *posix_process_name(char *storage, bof_uptr capacity) {
#if defined(BOF_DARWIN)
    const char *name = getprogname();
    (void)storage;
    (void)capacity;
    return name == (const char *)0 ? "unknown" : name;
#else
    if (!posix_current_process_name(storage, capacity)) {
        return "unknown";
    }
    return storage;
#endif
}

#if !defined(BOF_DARWIN)
static void posix_process_maps_line(bof_writer *writer, const char *line, bof_uptr length,
                                    const char *filter, char *last_path,
                                    bof_uptr last_capacity, unsigned long *count) {
    bof_uptr index;
    const char *path = (const char *)0;
    char current[POSIX_TEXT_CAPACITY];
    bof_uptr path_length;
    for (index = 0U; index < length; index++) {
        if (line[index] == '/') {
            path = line + index;
            break;
        }
    }
    if (path == (const char *)0) return;
    path_length = length - (bof_uptr)(path - line);
    if (path_length + 1U > sizeof(current)) return;
    for (index = 0U; index < path_length; index++) current[index] = path[index];
    current[path_length] = '\0';
    if (posix_same_string(current, last_path) || !posix_contains_casefold(current, filter)) return;
    if (!posix_copy_string(last_path, last_capacity, current)) last_path[0] = '\0';
    bof_puts(writer, "- "); bof_puts(writer, current); bof_putc(writer, '\n');
    (*count)++;
}
#endif

static unsigned long posix_list_current_modules(bof_writer *writer, const char *filter) {
    unsigned long count = 0UL;
#if defined(BOF_DARWIN)
    unsigned int image_count = _dyld_image_count();
    unsigned int index;
    for (index = 0U; index < image_count; index++) {
        const char *path = _dyld_get_image_name(index);
        if (path != (const char *)0 && posix_contains_casefold(path, filter)) {
            bof_puts(writer, "- "); bof_puts(writer, path); bof_putc(writer, '\n');
            count++;
        }
    }
#else
    int descriptor = open("/proc/self/maps", POSIX_O_RDONLY);
    char input[2048];
    char line[POSIX_TEXT_CAPACITY];
    char last_path[POSIX_TEXT_CAPACITY];
    bof_uptr line_length = 0U;
    bof_sptr amount;
    last_path[0] = '\0';
    if (descriptor < 0) {
        bof_error("unable to open /proc/self/maps");
        return 0UL;
    }
    while ((amount = read(descriptor, input, sizeof(input))) > 0) {
        bof_uptr index;
        for (index = 0U; index < (bof_uptr)amount; index++) {
            if (input[index] == '\n') {
                posix_process_maps_line(writer, line, line_length, filter, last_path, sizeof(last_path), &count);
                line_length = 0U;
            } else if (line_length + 1U < sizeof(line)) {
                line[line_length++] = input[index];
            }
        }
    }
    if (line_length != 0U) {
        posix_process_maps_line(writer, line, line_length, filter, last_path, sizeof(last_path), &count);
    }
    (void)close(descriptor);
    if (amount < 0) bof_error("unable to read /proc/self/maps");
#endif
    return count;
}

static void posix_find_loaded_module(datap *parser) {
    const char *module_filter;
    const char *process_filter;
    char process_storage[256];
    const char *process_name;
    unsigned long count = 0UL;
    bof_writer writer;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "Current-process loaded module matches:\n");
    if (!posix_extract_string(parser, &module_filter) || module_filter[0] == '\0' ||
        !posix_extract_string(parser, &process_filter)) {
        bof_error("module and process-filter string arguments are required");
        posix_put_summary(&writer, "Total matches: ", 0UL);
        bof_flush(&writer);
        return;
    }
    process_name = posix_process_name(process_storage, sizeof(process_storage));
    bof_puts(&writer, "Process: "); bof_puts(&writer, process_name); bof_puts(&writer, " (PID ");
    bof_put_uint(&writer, (unsigned long)getpid()); bof_puts(&writer, ")\n");
    if (process_filter[0] == '\0' || posix_contains_casefold(process_name, process_filter)) {
        count = posix_list_current_modules(&writer, module_filter);
    }
    posix_put_summary(&writer, "Total matches: ", count);
    bof_flush(&writer);
}

static void posix_listmods(datap *parser) {
    int requested_pid = BeaconDataInt(parser);
    int current_pid = getpid();
    unsigned long count = 0UL;
    bof_writer writer;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "Loaded modules:\nProcess ID: ");
    bof_put_uint(&writer, (unsigned long)(requested_pid == 0 ? current_pid : requested_pid));
    bof_putc(&writer, '\n');
    if (requested_pid != 0 && requested_pid != current_pid) {
        bof_error("unsupported: inspecting modules in another POSIX process is not available");
    } else {
        count = posix_list_current_modules(&writer, "");
    }
    posix_put_summary(&writer, "Total modules: ", count);
    bof_flush(&writer);
}

#endif

#if defined(BOF_COMMAND_NETLOCALGROUP) || defined(BOF_COMMAND_NETUSER) || defined(BOF_COMMAND_NETUSERENUM)

static int posix_group_has_member(const posix_group *group, const char *name) {
    char **member;
    if (group == (const posix_group *)0 || group->members == (char **)0) return 0;
    for (member = group->members; *member != (char *)0; member++) {
        if (bof_streq(*member, name)) return 1;
    }
    return 0;
}

static void posix_list_groups(bof_writer *writer) {
    posix_group *group;
    unsigned long count = 0UL;
    bof_puts(writer, "Local groups:\n");
    setgrent();
    while ((group = getgrent()) != (posix_group *)0) {
        bof_puts(writer, "- "); bof_puts(writer, group->name == (char *)0 ? "" : group->name);
        bof_puts(writer, " (gid="); bof_put_uint(writer, (unsigned long)group->gid); bof_puts(writer, ")\n");
        count++;
    }
    endgrent();
    posix_put_summary(writer, "Total groups: ", count);
}

static void posix_list_group_members(bof_writer *writer, const char *group_name) {
    posix_group *group = getgrnam(group_name);
    unsigned long count = 0UL;
    char **member;
    posix_gid gid;
    bof_puts(writer, "Members of local group "); bof_puts(writer, group_name); bof_puts(writer, ":\n");
    if (group == (posix_group *)0) {
        bof_error("local group was not found");
        posix_put_summary(writer, "Total members: ", 0UL);
        return;
    }
    gid = group->gid;
    if (group->members != (char **)0) {
        for (member = group->members; *member != (char *)0; member++) {
            bof_puts(writer, "- "); bof_puts(writer, *member); bof_putc(writer, '\n');
            count++;
        }
    }
    setpwent();
    for (;;) {
        posix_passwd *account = getpwent();
        if (account == (posix_passwd *)0) break;
        if (account->gid == gid && !posix_group_has_member(group, account->name)) {
            bof_puts(writer, "- "); bof_puts(writer, account->name); bof_putc(writer, '\n');
            count++;
        }
    }
    endpwent();
    posix_put_summary(writer, "Total members: ", count);
}

#endif

#if defined(BOF_COMMAND_NETLOCALGROUP)

static void posix_netlocalgroup(datap *parser) {
    int operation = (int)(short)BeaconDataShort(parser);
    char server[POSIX_TEXT_CAPACITY];
    char group[POSIX_TEXT_CAPACITY];
    bof_writer writer;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    if (!posix_extract_utf16(parser, server, sizeof(server)) ||
        !posix_extract_utf16(parser, group, sizeof(group))) {
        bof_error("type, UTF-16 server, and UTF-16 group arguments are required");
        bof_puts(&writer, operation == 0 ? "Local groups:\n" : "Local group members:\n");
        posix_put_summary(&writer, operation == 0 ? "Total groups: " : "Total members: ", 0UL);
        bof_flush(&writer);
        return;
    }
    if (server[0] != '\0') {
        bof_error("unsupported: remote/domain group queries are not available on POSIX");
        bof_puts(&writer, operation == 0 ? "Local groups:\n" : "Local group members:\n");
        posix_put_summary(&writer, operation == 0 ? "Total groups: " : "Total members: ", 0UL);
    } else if (operation == 0) {
        posix_list_groups(&writer);
    } else if (operation == 1 && group[0] != '\0') {
        posix_list_group_members(&writer, group);
    } else if (operation == 1) {
        bof_error("a local group name is required for member enumeration");
        bof_puts(&writer, "Local group members:\n");
        posix_put_summary(&writer, "Total members: ", 0UL);
    } else {
        bof_error("unsupported local-group operation (use 0=list or 1=members)");
        bof_puts(&writer, "Local group members:\n");
        posix_put_summary(&writer, "Total members: ", 0UL);
    }
    bof_flush(&writer);
}

#endif

#if defined(BOF_COMMAND_NETUSER)

static void posix_netuser(datap *parser) {
    char username[POSIX_TEXT_CAPACITY];
    char domain[POSIX_TEXT_CAPACITY];
    posix_passwd *account;
    posix_group *group;
    unsigned long group_count = 0UL;
    bof_writer writer;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "Local POSIX user information:\n");
    if (!posix_extract_utf16(parser, username, sizeof(username)) ||
        !posix_extract_utf16(parser, domain, sizeof(domain))) {
        bof_error("a UTF-16 username and UTF-16 domain argument are required");
        posix_put_summary(&writer, "Total users: ", 0UL);
        bof_flush(&writer);
        return;
    }
    if (domain[0] != '\0') {
        bof_error("unsupported: remote/domain user queries are not available on POSIX");
        posix_put_summary(&writer, "Total users: ", 0UL);
        bof_flush(&writer);
        return;
    }
    account = username[0] == '\0' ? getpwuid(geteuid()) : getpwnam(username);
    if (account == (posix_passwd *)0) {
        bof_error("local user was not found");
        posix_put_summary(&writer, "Total users: ", 0UL);
        bof_flush(&writer);
        return;
    }
    bof_puts(&writer, "User name: "); bof_puts(&writer, account->name); bof_putc(&writer, '\n');
    bof_puts(&writer, "UID: "); bof_put_uint(&writer, (unsigned long)account->uid); bof_putc(&writer, '\n');
    bof_puts(&writer, "Primary GID: "); bof_put_uint(&writer, (unsigned long)account->gid); bof_putc(&writer, '\n');
    bof_puts(&writer, "Full name/comment: "); bof_puts(&writer, account->gecos == (char *)0 ? "" : account->gecos); bof_putc(&writer, '\n');
    bof_puts(&writer, "Home: "); bof_puts(&writer, account->directory == (char *)0 ? "" : account->directory); bof_putc(&writer, '\n');
    bof_puts(&writer, "Shell: "); bof_puts(&writer, account->shell == (char *)0 ? "" : account->shell); bof_putc(&writer, '\n');
    bof_puts(&writer, "Groups:\n");
    group = getgrgid(account->gid);
    if (group != (posix_group *)0) {
        bof_puts(&writer, "- "); bof_puts(&writer, group->name); bof_puts(&writer, " (primary)\n");
        group_count++;
    }
    setgrent();
    while ((group = getgrent()) != (posix_group *)0) {
        if (group->gid != account->gid && posix_group_has_member(group, account->name)) {
            bof_puts(&writer, "- "); bof_puts(&writer, group->name); bof_putc(&writer, '\n');
            group_count++;
        }
    }
    endgrent();
    posix_put_summary(&writer, "Total groups: ", group_count);
    posix_put_summary(&writer, "Total users: ", 1UL);
    bof_flush(&writer);
}

#endif

#if defined(BOF_COMMAND_NETUSERENUM)

static void posix_netuserenum(datap *parser) {
    int use_domain = BeaconDataInt(parser);
    int filter = BeaconDataInt(parser);
    unsigned long count = 0UL;
    posix_passwd *account;
    bof_writer writer;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "Local POSIX users:\n");
    if (use_domain != 0) {
        bof_error("unsupported: domain user enumeration is not available on POSIX");
    } else if (filter != 1) {
        bof_error("unsupported: POSIX does not expose Windows locked/disabled account filters (use filter 1)");
    } else {
        setpwent();
        while ((account = getpwent()) != (posix_passwd *)0) {
            bof_puts(&writer, "- "); bof_puts(&writer, account->name == (char *)0 ? "" : account->name);
            bof_puts(&writer, " (uid="); bof_put_uint(&writer, (unsigned long)account->uid); bof_puts(&writer, ")\n");
            count++;
        }
        endpwent();
    }
    posix_put_summary(&writer, "Total users: ", count);
    bof_flush(&writer);
}

#endif

void go(char *buffer, int length) {
    datap parser;
    BeaconDataParse(&parser, buffer, length);
#if defined(BOF_COMMAND_CACLS)
    posix_cacls(&parser);
#elif defined(BOF_COMMAND_ENUM_LOCAL_SESSIONS)
    posix_list_sessions("Local sessions:", 0);
#elif defined(BOF_COMMAND_FIND_LOADED_MODULE)
    posix_find_loaded_module(&parser);
#elif defined(BOF_COMMAND_LISTMODS)
    posix_listmods(&parser);
#elif defined(BOF_COMMAND_NETLOCALGROUP)
    posix_netlocalgroup(&parser);
#elif defined(BOF_COMMAND_NETLOGGEDON)
    if (posix_require_local_server(&parser)) posix_list_sessions("Users logged on (local POSIX host):", 0);
    else posix_empty_sessions("Users logged on (local POSIX host):");
#elif defined(BOF_COMMAND_NETLOGGEDON2)
    if (posix_require_local_server(&parser)) posix_list_sessions("Structured local POSIX sessions:", 1);
    else posix_empty_sessions("Structured local POSIX sessions:");
#elif defined(BOF_COMMAND_NETUSER)
    posix_netuser(&parser);
#elif defined(BOF_COMMAND_NETUSERENUM)
    posix_netuserenum(&parser);
#endif
}
