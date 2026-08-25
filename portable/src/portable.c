#include "beacon.h"
#include "output.h"

#if defined(_WIN32)
#error "portable.c is the Unix implementation; Windows uses the preserved upstream BOFs"
#endif

#define BOF_O_RDONLY 0

typedef void bof_dir;
typedef void bof_file;

typedef struct bof_addrinfo bof_addrinfo;
struct bof_addrinfo {
    int flags;
    int family;
    int socket_type;
    int protocol;
    bof_u32 address_length;
#if defined(BOF_DARWIN)
    char *canonical_name;
    void *address;
#else
    void *address;
    char *canonical_name;
#endif
    bof_addrinfo *next;
};

typedef struct bof_ifaddrs bof_ifaddrs;
struct bof_ifaddrs {
    bof_ifaddrs *next;
    char *name;
    unsigned int flags;
    void *address;
    void *netmask;
    void *destination;
    void *data;
};

typedef struct {
    long seconds;
    long nanoseconds;
} bof_timespec;

typedef struct {
    int descriptor;
    short events;
    short returned_events;
} bof_pollfd;

extern int open(const char *path, int flags, ...);
extern bof_sptr read(int descriptor, void *buffer, bof_uptr length);
extern int close(int descriptor);
extern bof_dir *opendir(const char *path);
extern void *readdir(bof_dir *directory);
extern int closedir(bof_dir *directory);
extern unsigned int getuid(void);
extern unsigned int geteuid(void);
extern unsigned int getgid(void);
extern unsigned int getegid(void);
extern int getlogin_r(char *name, bof_uptr length);
extern char *getenv(const char *name);
extern int gethostname(char *name, bof_uptr length);
extern int getifaddrs(bof_ifaddrs **addresses);
extern void freeifaddrs(bof_ifaddrs *addresses);
extern int getaddrinfo(const char *name, const char *service, const bof_addrinfo *hints, bof_addrinfo **result);
extern void freeaddrinfo(bof_addrinfo *result);
extern const char *gai_strerror(int error);
extern int getnameinfo(const void *address, bof_u32 address_length, char *host, bof_u32 host_length,
                       char *service, bof_u32 service_length, int flags);
extern int socket(int domain, int type, int protocol);
extern int connect(int descriptor, const void *address, bof_u32 address_length);
#if defined(BOF_DARWIN)
extern int setsockopt(int descriptor, int level, int option, const void *value, bof_u32 length);
#else
extern int getsockopt(int descriptor, int level, int option, void *value, bof_u32 *length);
extern int fcntl(int descriptor, int command, ...);
extern int poll(bof_pollfd *descriptors, bof_uptr count, int timeout);
#endif
extern bof_file *popen(const char *command, const char *mode);
extern bof_uptr fread(void *buffer, bof_uptr size, bof_uptr count, bof_file *stream);
extern int pclose(bof_file *stream);

#if defined(BOF_DARWIN)
extern char ***_NSGetEnviron(void);
#endif
extern int clock_gettime(int clock_id, void *time_value);

#define BOF_AF_INET 2
#if defined(BOF_DARWIN)
#define BOF_AF_INET6 30
#define BOF_SOL_SOCKET 0xffff
#define BOF_SO_ERROR 0x1007
#define BOF_NI_NUMERICHOST 2
#define BOF_O_NONBLOCK 0x0004
#define BOF_TCP_CONNECTIONTIMEOUT 0x20
#else
#define BOF_AF_INET6 10
#define BOF_SOL_SOCKET 1
#define BOF_SO_ERROR 4
#define BOF_NI_NUMERICHOST 1
#define BOF_O_NONBLOCK 04000
#endif
#define BOF_AF_UNSPEC 0
#define BOF_SOCK_STREAM 1
#define BOF_IPPROTO_TCP 6
#define BOF_AI_CANONNAME 2
#define BOF_F_GETFL 3
#define BOF_F_SETFL 4
#define BOF_POLLOUT 0x0004

static void bof_zero(void *value, bof_uptr length) {
    bof_u8 *bytes = (bof_u8 *)value;
    while (length-- != 0U) {
        *bytes++ = 0U;
    }
}

static bof_uptr bof_strlen(const char *value) {
    bof_uptr length = 0U;
    while (value[length] != '\0') {
        length++;
    }
    return length;
}

static int bof_starts_with(const char *value, const char *prefix) {
    while (*prefix != '\0') {
        if (*value++ != *prefix++) {
            return 0;
        }
    }
    return 1;
}

static int bof_is_decimal(const char *value) {
    if (*value == '\0') {
        return 0;
    }
    while (*value != '\0') {
        if (*value < '0' || *value > '9') {
            return 0;
        }
        value++;
    }
    return 1;
}

static int bof_join_path(char *destination, bof_uptr capacity, const char *left,
                         const char *middle, const char *right) {
    const char *parts[3];
    bof_uptr part;
    bof_uptr used = 0U;
    parts[0] = left;
    parts[1] = middle;
    parts[2] = right;
    for (part = 0U; part < 3U; part++) {
        const char *cursor = parts[part];
        while (*cursor != '\0') {
            if (used + 1U >= capacity) {
                return 0;
            }
            destination[used++] = *cursor++;
        }
    }
    destination[used] = '\0';
    return 1;
}

static void bof_uint_string(char *destination, bof_uptr capacity, unsigned long value) {
    char reverse[3U * sizeof(unsigned long)];
    bof_uptr count = 0U;
    bof_uptr index;
    do {
        reverse[count++] = (char)('0' + (value % 10UL));
        value /= 10UL;
    } while (value != 0UL && count < sizeof(reverse));
    if (count + 1U > capacity) {
        destination[0] = '\0';
        return;
    }
    for (index = 0U; index < count; index++) {
        destination[index] = reverse[count - index - 1U];
    }
    destination[count] = '\0';
}

static int bof_emit_file(bof_writer *writer, const char *path) {
    bof_u8 chunk[2048];
    bof_sptr amount;
    int descriptor = open(path, BOF_O_RDONLY);
    if (descriptor < 0) {
        return 0;
    }
    while ((amount = read(descriptor, chunk, sizeof(chunk))) > 0) {
        bof_write(writer, (const char *)chunk, (bof_uptr)amount);
    }
    (void)close(descriptor);
    return amount >= 0;
}

static int bof_emit_command(bof_writer *writer, const char *command) {
    bof_u8 chunk[2048];
    bof_uptr amount;
    bof_file *stream = popen(command, "r");
    if (stream == (bof_file *)0) {
        return 0;
    }
    while ((amount = fread(chunk, 1U, sizeof(chunk), stream)) != 0U) {
        bof_write(writer, (const char *)chunk, amount);
    }
    return pclose(stream) == 0;
}

static const char *bof_dirent_name(void *entry) {
    bof_u8 *raw = (bof_u8 *)entry;
#if defined(BOF_DARWIN)
    return (const char *)(raw + 21U);
#elif defined(__i386__) || defined(__arm__)
    return (const char *)(raw + 11U);
#else
    return (const char *)(raw + 19U);
#endif
}

static void bof_addrinfo_init(bof_addrinfo *hints, int family, int socket_type, int protocol) {
    bof_zero(hints, sizeof(*hints));
    hints->family = family;
    hints->socket_type = socket_type;
    hints->protocol = protocol;
}

static int bof_monotonic_milliseconds(bof_u64 *milliseconds) {
    bof_timespec value;
#if defined(BOF_DARWIN)
    const int clock_id = 6; /* CLOCK_MONOTONIC */
#else
    const int clock_id = 1; /* CLOCK_MONOTONIC */
#endif
    if (clock_gettime(clock_id, &value) != 0 || value.seconds < 0 || value.nanoseconds < 0) {
        return 0;
    }
    *milliseconds = (bof_u64)(unsigned long)value.seconds * 1000U +
                    (bof_u64)(unsigned long)value.nanoseconds / 1000000U;
    return 1;
}

static char *bof_argument(char *buffer, int length, int *argument_length) {
    datap parser;
    int extracted_length = 0;
    char *argument;
    if (buffer == (char *)0 || length <= 0) {
        if (argument_length != (int *)0) {
            *argument_length = 0;
        }
        return (char *)0;
    }
    BeaconDataParse(&parser, buffer, length);
    argument = BeaconDataExtract(&parser, &extracted_length);
    if (argument == (char *)0 || extracted_length <= 0 || argument[extracted_length - 1] != '\0') {
        if (argument_length != (int *)0) {
            *argument_length = 0;
        }
        return (char *)0;
    }
    if (argument_length != (int *)0) {
        *argument_length = extracted_length;
    }
    return argument;
}

static int bof_extract_empty_utf16(datap *parser, int *empty) {
    const bof_u8 *raw;
    int byte_length = 0;
    int index;
    *empty = 0;
    raw = (const bof_u8 *)BeaconDataExtract(parser, &byte_length);
    if (raw == (const bof_u8 *)0 || byte_length < 2 || (byte_length & 1) != 0 ||
        raw[byte_length - 2] != 0U || raw[byte_length - 1] != 0U) {
        return 0;
    }
    *empty = 1;
    for (index = 0; index + 1 < byte_length - 2; index += 2) {
        if (raw[index] != 0U || raw[index + 1] != 0U) {
            *empty = 0;
            break;
        }
    }
    return 1;
}

#if defined(BOF_COMMAND_ARP)

static void run_command(char *buffer, int length) {
    bof_u8 chunk[2048];
    bof_writer writer;
    (void)buffer;
    (void)length;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "ARP table:\n");
#if defined(BOF_DARWIN)
    bof_file *stream = popen("/usr/sbin/arp -an", "r");
    bof_uptr amount;
    if (stream == (bof_file *)0) {
        bof_error("unable to query ARP table");
        return;
    }
    while ((amount = fread(chunk, 1U, sizeof(chunk), stream)) != 0U) {
        bof_write(&writer, (const char *)chunk, amount);
    }
    (void)pclose(stream);
#else
    int descriptor = open("/proc/net/arp", BOF_O_RDONLY);
    bof_sptr amount;
    if (descriptor < 0) {
        bof_error("unable to open /proc/net/arp");
        return;
    }
    while ((amount = read(descriptor, chunk, sizeof(chunk))) > 0) {
        bof_write(&writer, (const char *)chunk, (bof_uptr)amount);
    }
    (void)close(descriptor);
    if (amount < 0) {
        bof_error("unable to read /proc/net/arp");
        return;
    }
#endif
    bof_flush(&writer);
}

#elif defined(BOF_COMMAND_ENV)

static void run_command(char *buffer, int length) {
    bof_writer writer;
    (void)buffer;
    (void)length;
#if defined(BOF_DARWIN)
    char **environment;
    bof_u32 count = 0U;
    char ***environment_pointer = _NSGetEnviron();
    environment = environment_pointer == (char ***)0 ? (char **)0 : *environment_pointer;
    if (environment == (char **)0) {
        bof_error("environment is unavailable");
        return;
    }
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    while (*environment != (char *)0 && count++ < 65536U) {
        bof_puts(&writer, *environment++);
        bof_putc(&writer, '\n');
    }
#else
    int descriptor = open("/proc/self/environ", BOF_O_RDONLY);
    bof_u8 chunk[2048];
    bof_sptr amount;
    bof_uptr index;
    if (descriptor < 0) {
        bof_error("unable to open /proc/self/environ");
        return;
    }
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    while ((amount = read(descriptor, chunk, sizeof(chunk))) > 0) {
        for (index = 0U; index < (bof_uptr)amount; index++) {
            bof_putc(&writer, chunk[index] == 0U ? '\n' : (char)chunk[index]);
        }
    }
    (void)close(descriptor);
    if (amount < 0) {
        bof_error("unable to read /proc/self/environ");
        return;
    }
#endif
    bof_flush(&writer);
}

#elif defined(BOF_COMMAND_DIR)

static void run_command(char *buffer, int length) {
    datap parser;
    int argument_length = 0;
    int recurse = 0;
    char *path = ".";
    bof_dir *directory;
    void *entry;
    bof_writer writer;
    if (buffer != (char *)0 && length > 0) {
        BeaconDataParse(&parser, buffer, length);
        if (BeaconDataLength(&parser) != 0) {
            char *argument = BeaconDataExtract(&parser, &argument_length);
            if (argument == (char *)0 || argument_length <= 0 ||
                argument[argument_length - 1] != '\0') {
                bof_error("directory path argument is not NUL-terminated");
                return;
            }
            if (*argument != '\0') {
                path = argument;
                /* Retain compatibility with the legacy Windows-only manifest default. */
                if (bof_streq(path, ".\\")) {
                    path = ".";
                }
            }
            if (BeaconDataLength(&parser) != 0) {
                if (BeaconDataLength(&parser) < 2) {
                    bof_error("directory recursion argument is malformed");
                    return;
                }
                recurse = (int)(unsigned short)BeaconDataShort(&parser);
            }
            if (BeaconDataLength(&parser) != 0) {
                bof_error("unexpected trailing directory arguments");
                return;
            }
        }
    }
    if (recurse != 0) {
        bof_error("recursive directory listing is not supported on Unix");
        return;
    }
    directory = opendir(path);
    if (directory == (bof_dir *)0) {
        bof_error("unable to open directory");
        return;
    }
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "Contents of ");
    bof_puts(&writer, path);
    bof_puts(&writer, ":\n");
    while ((entry = readdir(directory)) != (void *)0) {
        const char *name = bof_dirent_name(entry);
        if (!bof_streq(name, ".") && !bof_streq(name, "..")) {
            bof_puts(&writer, name);
            bof_putc(&writer, '\n');
        }
    }
    bof_flush(&writer);
    (void)closedir(directory);
}

#elif defined(BOF_COMMAND_WHOAMI)

static void run_command(char *buffer, int length) {
    char login[256];
    bof_writer writer;
    (void)buffer;
    (void)length;
    login[0] = '\0';
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    if (getlogin_r(login, sizeof(login)) == 0 && login[0] != '\0') {
        bof_puts(&writer, "login=");
        bof_puts(&writer, login);
        bof_putc(&writer, '\n');
    }
    bof_puts(&writer, "uid=");
    bof_put_uint(&writer, (unsigned long)getuid());
    bof_puts(&writer, " euid=");
    bof_put_uint(&writer, (unsigned long)geteuid());
    bof_puts(&writer, " gid=");
    bof_put_uint(&writer, (unsigned long)getgid());
    bof_puts(&writer, " egid=");
    bof_put_uint(&writer, (unsigned long)getegid());
    bof_putc(&writer, '\n');
    bof_flush(&writer);
}

#elif defined(BOF_COMMAND_UPTIME)

static void run_command(char *buffer, int length) {
    unsigned long seconds;
    bof_writer writer;
    (void)buffer;
    (void)length;
    bof_timespec uptime;
#if defined(BOF_DARWIN)
    const int clock_id = 6; /* CLOCK_MONOTONIC */
#else
    const int clock_id = 7; /* CLOCK_BOOTTIME */
#endif
    if (clock_gettime(clock_id, &uptime) != 0 || uptime.seconds < 0) {
        bof_error("unable to query system uptime");
        return;
    }
    seconds = (unsigned long)uptime.seconds;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "uptime_seconds=");
    bof_put_uint(&writer, seconds);
    bof_puts(&writer, " uptime_days=");
    bof_put_uint(&writer, seconds / 86400UL);
    bof_putc(&writer, '\n');
    bof_flush(&writer);
}

#elif defined(BOF_COMMAND_IPCONFIG)

static int bof_sockaddr_family(const void *address) {
    const bof_u8 *raw = (const bof_u8 *)address;
#if defined(BOF_DARWIN)
    return (int)raw[1];
#else
    return (int)((bof_u16)raw[0] | ((bof_u16)raw[1] << 8U));
#endif
}

static bof_u32 bof_sockaddr_length(const void *address, int family) {
#if defined(BOF_DARWIN)
    const bof_u8 *raw = (const bof_u8 *)address;
    if (raw[0] != 0U) {
        return (bof_u32)raw[0];
    }
#else
    (void)address;
#endif
    return family == BOF_AF_INET ? 16U : 28U;
}

static void run_command(char *buffer, int length) {
    char hostname[256];
    char numeric_host[128];
    bof_ifaddrs *addresses = (bof_ifaddrs *)0;
    bof_ifaddrs *current;
    bof_writer writer;
    (void)buffer;
    (void)length;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "Network interfaces:\n");
    hostname[0] = '\0';
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        hostname[sizeof(hostname) - 1U] = '\0';
        bof_puts(&writer, "hostname: ");
        bof_puts(&writer, hostname);
        bof_putc(&writer, '\n');
    }
    if (getifaddrs(&addresses) == 0) {
        for (current = addresses; current != (bof_ifaddrs *)0; current = current->next) {
            int family;
            if (current->name == (char *)0 || current->address == (void *)0) {
                continue;
            }
            family = bof_sockaddr_family(current->address);
            if (family != BOF_AF_INET && family != BOF_AF_INET6) {
                continue;
            }
            if (getnameinfo(current->address, bof_sockaddr_length(current->address, family),
                            numeric_host, sizeof(numeric_host), (char *)0, 0U,
                            BOF_NI_NUMERICHOST) != 0) {
                continue;
            }
            bof_puts(&writer, current->name);
            bof_puts(&writer, family == BOF_AF_INET ? " IPv4 " : " IPv6 ");
            bof_puts(&writer, numeric_host);
            bof_putc(&writer, '\n');
        }
        freeifaddrs(addresses);
    } else {
        bof_puts(&writer, "interface enumeration unavailable\n");
    }
    bof_puts(&writer, "Resolver configuration:\n");
#if defined(BOF_DARWIN)
    if (!bof_emit_command(&writer, "/usr/sbin/scutil --dns")) {
        bof_puts(&writer, "unavailable\n");
    }
#else
    if (!bof_emit_file(&writer, "/etc/resolv.conf")) {
        bof_puts(&writer, "unavailable\n");
    }
#endif
    bof_flush(&writer);
}

#elif defined(BOF_COMMAND_LOCALE)

static void bof_put_environment_value(bof_writer *writer, const char *name) {
    char *value = getenv(name);
    bof_puts(writer, name);
    bof_putc(writer, '=');
    bof_puts(writer, value == (char *)0 ? "<unset>" : value);
    bof_putc(writer, '\n');
}

static void run_command(char *buffer, int length) {
    bof_writer writer;
    (void)buffer;
    (void)length;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "Locale:\n");
    bof_put_environment_value(&writer, "LANG");
    bof_put_environment_value(&writer, "LC_ALL");
    bof_put_environment_value(&writer, "LC_CTYPE");
    bof_put_environment_value(&writer, "TZ");
    bof_flush(&writer);
}

#elif defined(BOF_COMMAND_NETSTAT)

static void bof_netstat_file(bof_writer *writer, const char *label, const char *path) {
    bof_puts(writer, label);
    bof_putc(writer, '\n');
    if (!bof_emit_file(writer, path)) {
        bof_puts(writer, "unavailable\n");
    }
}

static void run_command(char *buffer, int length) {
    int filter = 0x1111;
    bof_writer writer;
    if (buffer != (char *)0 && length > 0) {
        datap parser;
        BeaconDataParse(&parser, buffer, length);
        if (BeaconDataLength(&parser) >= 4) {
            filter = BeaconDataInt(&parser);
        }
    }
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "Network connections:\n");
#if defined(BOF_DARWIN)
    bof_puts(&writer, "requested_filter=");
    bof_put_uint(&writer, (unsigned long)(unsigned int)filter);
    bof_putc(&writer, '\n');
    if (!bof_emit_command(&writer, "/usr/sbin/netstat -an")) {
        bof_puts(&writer, "netstat unavailable\n");
    }
#else
    if ((filter & 0x0001) != 0) bof_netstat_file(&writer, "TCP IPv4:", "/proc/net/tcp");
    if ((filter & 0x0010) != 0) bof_netstat_file(&writer, "TCP IPv6:", "/proc/net/tcp6");
    if ((filter & 0x0100) != 0) bof_netstat_file(&writer, "UDP IPv4:", "/proc/net/udp");
    if ((filter & 0x1000) != 0) bof_netstat_file(&writer, "UDP IPv6:", "/proc/net/udp6");
#endif
    bof_flush(&writer);
}

#elif defined(BOF_COMMAND_NSLOOKUP)

static void run_command(char *buffer, int length) {
    datap parser;
    int hostname_length = 0;
    int server_length = 0;
    int record_type = 1;
    int family;
    int status;
    int found = 0;
    char *hostname;
    char *server = (char *)0;
    char numeric_host[128];
    bof_addrinfo hints;
    bof_addrinfo *addresses = (bof_addrinfo *)0;
    bof_addrinfo *current;
    bof_writer writer;
    if (buffer == (char *)0 || length <= 0) {
        bof_error("a hostname is required");
        return;
    }
    BeaconDataParse(&parser, buffer, length);
    hostname = BeaconDataExtract(&parser, &hostname_length);
    if (BeaconDataLength(&parser) > 0) {
        server = BeaconDataExtract(&parser, &server_length);
    }
    if (BeaconDataLength(&parser) >= 2) {
        record_type = (int)(unsigned short)BeaconDataShort(&parser);
    }
    if (hostname == (char *)0 || hostname_length <= 0 ||
        hostname[hostname_length - 1] != '\0' || *hostname == '\0') {
        bof_error("a hostname is required");
        return;
    }
    if (server != (char *)0 && server_length > 0 && server[server_length - 1] != '\0') {
        bof_error("DNS server argument is not NUL-terminated");
        return;
    }
    if (server != (char *)0 && server_length > 0 && *server != '\0') {
        bof_error("custom DNS servers are not supported on Unix");
        return;
    }
    if (record_type == 1) {
        family = BOF_AF_INET;
    } else if (record_type == 28) {
        family = BOF_AF_INET6;
    } else if (record_type == 255) {
        family = BOF_AF_UNSPEC;
    } else {
        bof_error("Unix nslookup supports A, AAAA, and ANY records");
        return;
    }
    bof_addrinfo_init(&hints, family, BOF_SOCK_STREAM, 0);
    hints.flags = BOF_AI_CANONNAME;
    status = getaddrinfo(hostname, (const char *)0, &hints, &addresses);
    if (status != 0 || addresses == (bof_addrinfo *)0) {
        (void)gai_strerror(status);
        bof_error("DNS lookup failed");
        return;
    }
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "DNS results for ");
    bof_puts(&writer, hostname);
    bof_puts(&writer, ":\n");
    if (addresses->canonical_name != (char *)0) {
        bof_puts(&writer, "canonical_name: ");
        bof_puts(&writer, addresses->canonical_name);
        bof_putc(&writer, '\n');
    }
    for (current = addresses; current != (bof_addrinfo *)0; current = current->next) {
        if (current->address == (void *)0 || current->address_length == 0U) {
            continue;
        }
        if (getnameinfo(current->address, current->address_length, numeric_host,
                        sizeof(numeric_host), (char *)0, 0U,
                        BOF_NI_NUMERICHOST) == 0) {
            bof_puts(&writer, numeric_host);
            bof_putc(&writer, '\n');
            found = 1;
        }
    }
    freeaddrinfo(addresses);
    if (!found) {
        bof_puts(&writer, "no address records\n");
    }
    bof_flush(&writer);
}

#elif defined(BOF_COMMAND_PROBE)

static void run_command(char *buffer, int length) {
    datap parser;
    int host_length = 0;
    char *host;
    int port;
    int timeout = 5;
    int status;
    int connected = 0;
    char service[24];
    bof_addrinfo hints;
    bof_addrinfo *addresses = (bof_addrinfo *)0;
    bof_addrinfo *current;
    bof_u64 now;
    bof_u64 deadline;
    bof_writer writer;
    if (buffer == (char *)0 || length <= 0) {
        bof_error("host and port are required");
        return;
    }
    BeaconDataParse(&parser, buffer, length);
    host = BeaconDataExtract(&parser, &host_length);
    if (host == (char *)0 || host_length <= 0 || host[host_length - 1] != '\0' ||
        BeaconDataLength(&parser) < 4) {
        bof_error("host and port are required");
        return;
    }
    port = BeaconDataInt(&parser);
    if (BeaconDataLength(&parser) >= 4) {
        timeout = BeaconDataInt(&parser);
    }
    if (port < 1 || port > 65535) {
        bof_error("port must be between 1 and 65535");
        return;
    }
    if (timeout <= 0) timeout = 5;
    if (timeout > 300) timeout = 300;
    bof_uint_string(service, sizeof(service), (unsigned long)(unsigned int)port);
    bof_addrinfo_init(&hints, BOF_AF_UNSPEC, BOF_SOCK_STREAM, BOF_IPPROTO_TCP);
    status = getaddrinfo(host, service, &hints, &addresses);
    if (status != 0 || addresses == (bof_addrinfo *)0) {
        bof_error("unable to resolve probe host");
        return;
    }
    if (!bof_monotonic_milliseconds(&now)) {
        freeaddrinfo(addresses);
        bof_error("unable to start probe timeout");
        return;
    }
    deadline = now + (bof_u64)(unsigned int)timeout * 1000U;
    for (current = addresses; current != (bof_addrinfo *)0; current = current->next) {
        int descriptor;
#if defined(BOF_DARWIN)
        int connection_timeout;
#else
        int flags;
        int connection_error = 0;
        bof_u32 connection_error_length = sizeof(connection_error);
        bof_pollfd poll_descriptor;
#endif
        bof_u64 remaining;
        if (current->address == (void *)0 || current->address_length == 0U) continue;
        if (!bof_monotonic_milliseconds(&now) || now >= deadline) break;
        remaining = deadline - now;
        descriptor = socket(current->family, current->socket_type, current->protocol);
        if (descriptor < 0) continue;
#if defined(BOF_DARWIN)
        connection_timeout = (int)((remaining + 999U) / 1000U);
        if (setsockopt(descriptor, BOF_IPPROTO_TCP, BOF_TCP_CONNECTIONTIMEOUT,
                       &connection_timeout, sizeof(connection_timeout)) != 0) {
            (void)close(descriptor);
            continue;
        }
        if (connect(descriptor, current->address, current->address_length) == 0) {
            connected = 1;
        }
        (void)close(descriptor);
        if (connected) break;
#else
        flags = fcntl(descriptor, BOF_F_GETFL, 0);
        if (flags < 0 || fcntl(descriptor, BOF_F_SETFL, flags | BOF_O_NONBLOCK) != 0) {
            (void)close(descriptor);
            continue;
        }
        if (connect(descriptor, current->address, current->address_length) == 0) {
            connected = 1;
            (void)fcntl(descriptor, BOF_F_SETFL, flags);
            (void)close(descriptor);
            break;
        }
        if (!bof_monotonic_milliseconds(&now) || now >= deadline) {
            (void)close(descriptor);
            break;
        }
        remaining = deadline - now;
        poll_descriptor.descriptor = descriptor;
        poll_descriptor.events = BOF_POLLOUT;
        poll_descriptor.returned_events = 0;
        if (poll(&poll_descriptor, 1U, (int)remaining) > 0 &&
            getsockopt(descriptor, BOF_SOL_SOCKET, BOF_SO_ERROR, &connection_error,
                       &connection_error_length) == 0 && connection_error == 0) {
            connected = 1;
        }
        (void)fcntl(descriptor, BOF_F_SETFL, flags);
        (void)close(descriptor);
        if (connected) break;
#endif
    }
    freeaddrinfo(addresses);
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "Probe ");
    bof_puts(&writer, host);
    bof_putc(&writer, ':');
    bof_put_uint(&writer, (unsigned long)(unsigned int)port);
    bof_puts(&writer, connected ? " OPEN\n" : " FAILED\n");
    bof_flush(&writer);
}

#elif defined(BOF_COMMAND_RESOURCES)

static void run_command(char *buffer, int length) {
    bof_writer writer;
    (void)buffer;
    (void)length;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "System resources:\n");
#if defined(BOF_DARWIN)
    bof_puts(&writer, "Memory:\n");
    if (!bof_emit_command(&writer, "/usr/bin/vm_stat")) bof_puts(&writer, "unavailable\n");
#else
    bof_puts(&writer, "Memory:\n");
    if (!bof_emit_file(&writer, "/proc/meminfo")) bof_puts(&writer, "unavailable\n");
    bof_puts(&writer, "Load:\n");
    if (!bof_emit_file(&writer, "/proc/loadavg")) bof_puts(&writer, "unavailable\n");
#endif
    bof_puts(&writer, "Disk:\n");
    if (!bof_emit_command(&writer, "/bin/df -k /")) bof_puts(&writer, "unavailable\n");
    bof_flush(&writer);
}

#elif defined(BOF_COMMAND_ROUTEPRINT)

static void run_command(char *buffer, int length) {
    bof_writer writer;
    (void)buffer;
    (void)length;
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "Routing table:\n");
#if defined(BOF_DARWIN)
    if (!bof_emit_command(&writer, "/usr/sbin/netstat -rn")) {
        bof_puts(&writer, "routing information unavailable\n");
    }
#else
    bof_puts(&writer, "IPv4:\n");
    if (!bof_emit_file(&writer, "/proc/net/route")) bof_puts(&writer, "unavailable\n");
    bof_puts(&writer, "IPv6:\n");
    if (!bof_emit_file(&writer, "/proc/net/ipv6_route")) bof_puts(&writer, "unavailable\n");
#endif
    bof_flush(&writer);
}

#elif defined(BOF_COMMAND_TASKLIST)

static void bof_emit_process_status(bof_writer *writer, const char *process_id) {
    char path[96];
    char status[2048];
    bof_sptr amount;
    int descriptor;
    char *cursor;
    if (!bof_join_path(path, sizeof(path), "/proc/", process_id, "/status")) {
        return;
    }
    descriptor = open(path, BOF_O_RDONLY);
    if (descriptor < 0) return;
    amount = read(descriptor, status, sizeof(status) - 1U);
    (void)close(descriptor);
    if (amount <= 0) return;
    status[(bof_uptr)amount] = '\0';
    cursor = status;
    while (*cursor != '\0') {
        char *line = cursor;
        bof_uptr line_length;
        while (*cursor != '\0' && *cursor != '\n') cursor++;
        line_length = (bof_uptr)(cursor - line);
        if (bof_starts_with(line, "Name:\t") || bof_starts_with(line, "Pid:\t") ||
            bof_starts_with(line, "PPid:\t")) {
            bof_write(writer, line, line_length);
            bof_putc(writer, '\n');
        }
        if (*cursor == '\n') cursor++;
    }
    bof_putc(writer, '\n');
}

static void run_command(char *buffer, int length) {
    bof_writer writer;
    if (buffer != (char *)0 && length > 0) {
        datap parser;
        int resource_is_empty = 0;
        BeaconDataParse(&parser, buffer, length);
        if (BeaconDataLength(&parser) != 0) {
            if (!bof_extract_empty_utf16(&parser, &resource_is_empty) ||
                BeaconDataLength(&parser) != 0) {
                bof_error("tasklist resource argument must be a NUL-terminated UTF-16 string");
                return;
            }
            if (!resource_is_empty) {
                bof_error("remote process enumeration is not supported on Unix");
                return;
            }
        }
    }
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_puts(&writer, "Processes:\n");
#if defined(BOF_DARWIN)
    if (!bof_emit_command(&writer, "/bin/ps -axo pid=,ppid=,comm=")) {
        bof_puts(&writer, "process enumeration unavailable\n");
    }
#else
    {
        bof_dir *directory = opendir("/proc");
        void *entry;
        if (directory == (bof_dir *)0) {
            bof_puts(&writer, "process enumeration unavailable\n");
        } else {
            while ((entry = readdir(directory)) != (void *)0) {
                const char *name = bof_dirent_name(entry);
                if (bof_is_decimal(name)) {
                    bof_emit_process_status(&writer, name);
                }
            }
            (void)closedir(directory);
        }
    }
#endif
    bof_flush(&writer);
}

#elif defined(BOF_COMMAND_MD5) || defined(BOF_COMMAND_SHA1) || defined(BOF_COMMAND_SHA256)

static bof_u32 bof_rotl32(bof_u32 value, bof_u32 count) {
    return (value << count) | (value >> (32U - count));
}

static bof_u32 bof_rotr32(bof_u32 value, bof_u32 count) {
    return (value >> count) | (value << (32U - count));
}

static bof_u32 bof_load_le32(const bof_u8 *value) {
    return ((bof_u32)value[0]) | ((bof_u32)value[1] << 8U) |
           ((bof_u32)value[2] << 16U) | ((bof_u32)value[3] << 24U);
}

static bof_u32 bof_load_be32(const bof_u8 *value) {
    return ((bof_u32)value[0] << 24U) | ((bof_u32)value[1] << 16U) |
           ((bof_u32)value[2] << 8U) | ((bof_u32)value[3]);
}

static void bof_store_le32(bof_u8 *value, bof_u32 word) {
    value[0] = (bof_u8)word;
    value[1] = (bof_u8)(word >> 8U);
    value[2] = (bof_u8)(word >> 16U);
    value[3] = (bof_u8)(word >> 24U);
}

static void bof_store_be32(bof_u8 *value, bof_u32 word) {
    value[0] = (bof_u8)(word >> 24U);
    value[1] = (bof_u8)(word >> 16U);
    value[2] = (bof_u8)(word >> 8U);
    value[3] = (bof_u8)word;
}

typedef struct {
    bof_u32 state[8];
    bof_u64 byte_count;
    bof_u32 used;
    bof_u8 block[64];
} bof_hash;

#if defined(BOF_COMMAND_MD5)

static const bof_u32 md5_k[64] = {
    0xd76aa478U,0xe8c7b756U,0x242070dbU,0xc1bdceeeU,0xf57c0fafU,0x4787c62aU,0xa8304613U,0xfd469501U,
    0x698098d8U,0x8b44f7afU,0xffff5bb1U,0x895cd7beU,0x6b901122U,0xfd987193U,0xa679438eU,0x49b40821U,
    0xf61e2562U,0xc040b340U,0x265e5a51U,0xe9b6c7aaU,0xd62f105dU,0x02441453U,0xd8a1e681U,0xe7d3fbc8U,
    0x21e1cde6U,0xc33707d6U,0xf4d50d87U,0x455a14edU,0xa9e3e905U,0xfcefa3f8U,0x676f02d9U,0x8d2a4c8aU,
    0xfffa3942U,0x8771f681U,0x6d9d6122U,0xfde5380cU,0xa4beea44U,0x4bdecfa9U,0xf6bb4b60U,0xbebfbc70U,
    0x289b7ec6U,0xeaa127faU,0xd4ef3085U,0x04881d05U,0xd9d4d039U,0xe6db99e5U,0x1fa27cf8U,0xc4ac5665U,
    0xf4292244U,0x432aff97U,0xab9423a7U,0xfc93a039U,0x655b59c3U,0x8f0ccc92U,0xffeff47dU,0x85845dd1U,
    0x6fa87e4fU,0xfe2ce6e0U,0xa3014314U,0x4e0811a1U,0xf7537e82U,0xbd3af235U,0x2ad7d2bbU,0xeb86d391U
};
static const bof_u8 md5_s[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static void hash_init(bof_hash *hash) {
    hash->state[0] = 0x67452301U; hash->state[1] = 0xefcdab89U;
    hash->state[2] = 0x98badcfeU; hash->state[3] = 0x10325476U;
    hash->byte_count = 0U; hash->used = 0U;
}

static void hash_block(bof_hash *hash, const bof_u8 *block) {
    bof_u32 words[16], a = hash->state[0], b = hash->state[1];
    bof_u32 c = hash->state[2], d = hash->state[3], f, g, temp, index;
    for (index = 0U; index < 16U; index++) words[index] = bof_load_le32(block + index * 4U);
    for (index = 0U; index < 64U; index++) {
        if (index < 16U) { f = (b & c) | ((~b) & d); g = index; }
        else if (index < 32U) { f = (d & b) | ((~d) & c); g = (5U * index + 1U) & 15U; }
        else if (index < 48U) { f = b ^ c ^ d; g = (3U * index + 5U) & 15U; }
        else { f = c ^ (b | (~d)); g = (7U * index) & 15U; }
        temp = d; d = c; c = b;
        b = b + bof_rotl32(a + f + md5_k[index] + words[g], md5_s[index]);
        a = temp;
    }
    hash->state[0] += a; hash->state[1] += b;
    hash->state[2] += c; hash->state[3] += d;
}

#elif defined(BOF_COMMAND_SHA1)

static void hash_init(bof_hash *hash) {
    hash->state[0] = 0x67452301U; hash->state[1] = 0xefcdab89U;
    hash->state[2] = 0x98badcfeU; hash->state[3] = 0x10325476U;
    hash->state[4] = 0xc3d2e1f0U; hash->byte_count = 0U; hash->used = 0U;
}

static void hash_block(bof_hash *hash, const bof_u8 *block) {
    bof_u32 words[80], a = hash->state[0], b = hash->state[1];
    bof_u32 c = hash->state[2], d = hash->state[3], e = hash->state[4];
    bof_u32 f, k, temp, index;
    for (index = 0U; index < 16U; index++) words[index] = bof_load_be32(block + index * 4U);
    for (index = 16U; index < 80U; index++) words[index] = bof_rotl32(words[index-3U]^words[index-8U]^words[index-14U]^words[index-16U], 1U);
    for (index = 0U; index < 80U; index++) {
        if (index < 20U) { f = (b & c) | ((~b) & d); k = 0x5a827999U; }
        else if (index < 40U) { f = b ^ c ^ d; k = 0x6ed9eba1U; }
        else if (index < 60U) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcU; }
        else { f = b ^ c ^ d; k = 0xca62c1d6U; }
        temp = bof_rotl32(a, 5U) + f + e + k + words[index];
        e = d; d = c; c = bof_rotl32(b, 30U); b = a; a = temp;
    }
    hash->state[0] += a; hash->state[1] += b; hash->state[2] += c;
    hash->state[3] += d; hash->state[4] += e;
}

#else

static const bof_u32 sha256_k[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

static void hash_init(bof_hash *hash) {
    hash->state[0]=0x6a09e667U; hash->state[1]=0xbb67ae85U; hash->state[2]=0x3c6ef372U; hash->state[3]=0xa54ff53aU;
    hash->state[4]=0x510e527fU; hash->state[5]=0x9b05688cU; hash->state[6]=0x1f83d9abU; hash->state[7]=0x5be0cd19U;
    hash->byte_count=0U; hash->used=0U;
}

static void hash_block(bof_hash *hash, const bof_u8 *block) {
    bof_u32 words[64], a=hash->state[0], b=hash->state[1], c=hash->state[2], d=hash->state[3];
    bof_u32 e=hash->state[4], f=hash->state[5], g=hash->state[6], h=hash->state[7];
    bof_u32 s0,s1,ch,maj,t1,t2,index;
    for(index=0U;index<16U;index++) words[index]=bof_load_be32(block+index*4U);
    for(index=16U;index<64U;index++) {
        s0=bof_rotr32(words[index-15U],7U)^bof_rotr32(words[index-15U],18U)^(words[index-15U]>>3U);
        s1=bof_rotr32(words[index-2U],17U)^bof_rotr32(words[index-2U],19U)^(words[index-2U]>>10U);
        words[index]=words[index-16U]+s0+words[index-7U]+s1;
    }
    for(index=0U;index<64U;index++) {
        s1=bof_rotr32(e,6U)^bof_rotr32(e,11U)^bof_rotr32(e,25U); ch=(e&f)^((~e)&g);
        t1=h+s1+ch+sha256_k[index]+words[index];
        s0=bof_rotr32(a,2U)^bof_rotr32(a,13U)^bof_rotr32(a,22U); maj=(a&b)^(a&c)^(b&c); t2=s0+maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    hash->state[0]+=a; hash->state[1]+=b; hash->state[2]+=c; hash->state[3]+=d;
    hash->state[4]+=e; hash->state[5]+=f; hash->state[6]+=g; hash->state[7]+=h;
}

#endif

static void hash_update(bof_hash *hash, const bof_u8 *data, bof_uptr length) {
    bof_uptr amount, index = 0U, copy;
    hash->byte_count += (bof_u64)length;
    while (index < length) {
        amount = 64U - hash->used;
        if (amount > length - index) amount = length - index;
        for (copy = 0U; copy < amount; copy++) hash->block[hash->used + copy] = data[index + copy];
        hash->used += (bof_u32)amount; index += amount;
        if (hash->used == 64U) { hash_block(hash, hash->block); hash->used = 0U; }
    }
}

static void hash_final(bof_hash *hash, bof_u8 *digest) {
    bof_u64 bits = hash->byte_count << 3U;
    bof_u32 digest_words, index;
    hash->block[hash->used++] = 0x80U;
    if (hash->used > 56U) {
        while (hash->used < 64U) hash->block[hash->used++] = 0U;
        hash_block(hash, hash->block); hash->used = 0U;
    }
    while (hash->used < 56U) hash->block[hash->used++] = 0U;
#if defined(BOF_COMMAND_MD5)
    for (index=0U;index<8U;index++) hash->block[56U+index]=(bof_u8)(bits>>(index*8U));
    digest_words=4U;
#else
    for (index=0U;index<8U;index++) hash->block[63U-index]=(bof_u8)(bits>>(index*8U));
#if defined(BOF_COMMAND_SHA1)
    digest_words=5U;
#else
    digest_words=8U;
#endif
#endif
    hash_block(hash, hash->block);
    for(index=0U;index<digest_words;index++) {
#if defined(BOF_COMMAND_MD5)
        bof_store_le32(digest+index*4U,hash->state[index]);
#else
        bof_store_be32(digest+index*4U,hash->state[index]);
#endif
    }
}

static void run_command(char *buffer, int length) {
    char *path = bof_argument(buffer, length, (int *)0);
    bof_u8 input[4096], digest[32];
    bof_hash hash;
    bof_sptr amount;
    int descriptor;
    bof_uptr digest_length;
    bof_writer writer;
    if (path == (char *)0 || *path == '\0') { bof_error("a file path is required"); return; }
    descriptor = open(path, BOF_O_RDONLY);
    if (descriptor < 0) { bof_error("unable to open file"); return; }
    hash_init(&hash);
    while ((amount = read(descriptor, input, sizeof(input))) > 0) hash_update(&hash, input, (bof_uptr)amount);
    (void)close(descriptor);
    if (amount < 0) { bof_error("unable to read file"); return; }
    hash_final(&hash, digest);
#if defined(BOF_COMMAND_MD5)
    digest_length = 16U;
#elif defined(BOF_COMMAND_SHA1)
    digest_length = 20U;
#else
    digest_length = 32U;
#endif
    bof_writer_init(&writer, CALLBACK_OUTPUT);
    bof_put_hex(&writer, digest, digest_length);
    bof_puts(&writer, "  "); bof_puts(&writer, path); bof_putc(&writer, '\n'); bof_flush(&writer);
}

#else
#error "one BOF_COMMAND_* macro is required"
#endif

void go(char *buffer, bof_u32 length) {
    run_command(buffer, (int)length);
}
