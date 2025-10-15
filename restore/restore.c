// Snapshot restore service for /snapshot/<sanitized>_<timestamp> sessions.
// Matches the on-disk format written by your kernel module:
//   blocks.map: repeated records { u64 sector; u32 size; u64 offset } (packed)
//   blocks.dat: raw block payloads appended; 'offset' indexes into this file.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef NAME_MAX
#define NAME_MAX 255
#endif

#define SNAPSHOT_ROOT "/snapshot"
#define SECTOR_SIZE   512ULL

// Must match kernel struct layout (packed, little-endian on x86)
#pragma pack(push, 1)
typedef struct {
    uint64_t sector;  // key in sectors (512B)
    uint32_t size;    // bytes
    uint64_t offset;  // offset inside blocks.dat
} snapshot_rec_t;
#pragma pack(pop)

typedef struct {
    char dirname[NAME_MAX+1];     // e.g., "loop21_1696512345"
    unsigned long long ts;        // parsed timestamp
} session_t;

static void extract_name_of_image(const char *raw, char *out, size_t outlen) {
    const char *base = strrchr(raw, '/');
    base = base ? base + 1 : raw;
    size_t i = 0;
    for (; base[i] && i < outlen - 1; i++) {
        char c = base[i];
        if (!(isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.'))
            c = '_';
        out[i] = c;
    }
    out[i] = '\0';
    if (out[0] == '\0' || (out[0]=='.' && (!out[1] || (out[1]=='.' && !out[2]))))
        strncpy(out, "dev", outlen);
}

static int cmp_sessions_desc(const void *a, const void *b) {
    const session_t *sa = (const session_t *)a;
    const session_t *sb = (const session_t *)b;
    if (sa->ts < sb->ts) return 1;
    if (sa->ts > sb->ts) return -1;
    return strcmp(sa->dirname, sb->dirname);
}

static int list_sessions_for_dev(const char *devname, session_t **out_list, size_t *out_n) {
    char sanitized[NAME_MAX+1];
    extract_name_of_image(devname, sanitized, sizeof(sanitized));
    char prefix[NAME_MAX+2];
    snprintf(prefix, sizeof(prefix), "%s_", sanitized);

    DIR *dir = opendir(SNAPSHOT_ROOT);
    if (!dir) {
        perror("opendir(/snapshot)");
        return -1;
    }

    size_t cap = 16, n = 0;
    session_t *arr = (session_t *)calloc(cap, sizeof(session_t));
    if (!arr) { closedir(dir); return -1; }

    struct dirent *de;
    while ((de = readdir(dir))) {
        if (de->d_type != DT_DIR && de->d_type != DT_UNKNOWN) continue; 
        const char *name = de->d_name;
        if (name[0] == '.') continue;
        if (strncmp(name, prefix, strlen(prefix)) != 0) continue;

        // parse timestamp after prefix
        const char *ts_str = name + strlen(prefix);
        char *endp = NULL;
        errno = 0;
        unsigned long long ts = strtoull(ts_str, &endp, 10);
        if (errno || !endp || *endp != '\0') continue; 

        if (n == cap) {
            cap *= 2;
            session_t *tmp = (session_t *)realloc(arr, cap * sizeof(session_t));
            if (!tmp) { free(arr); closedir(dir); return -1; }
            arr = tmp;
        }
        strncpy(arr[n].dirname, name, NAME_MAX);
        arr[n].dirname[NAME_MAX] = '\0';
        arr[n].ts = ts;
        n++;
    }
    closedir(dir);

    qsort(arr, n, sizeof(session_t), cmp_sessions_desc);
    *out_list = arr;
    *out_n = n;
    return 0;
}

static void print_table(const session_t *list, size_t n) {
    puts("\nAvailable snapshots:");
    puts("  # | Directory Name            | Timestamp (UTC)        ");
    puts("----+---------------------------+------------------------");
    for (size_t i = 0; i < n; i++) {
        char when[64] = {0};
        time_t t = (time_t)list[i].ts;
        struct tm tm;
        gmtime_r(&t, &tm);
        strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", &tm);
        printf("%3zu | %-25s | %s\n", i+1, list[i].dirname, when);
    }
}
// Check if a regular file is the backing file for any active loop device
static bool is_loop_backing_file_in_use(const char *filepath) {
    DIR *dir = opendir("/sys/block");
    if (!dir) return false;

    bool in_use = false;
    struct dirent *de;
    
    while ((de = readdir(dir))) {
        // Look for loopN directories
        if (strncmp(de->d_name, "loop", 4) != 0) continue;

        char backing_file_path[PATH_MAX];
        snprintf(backing_file_path, sizeof(backing_file_path),
                 "/sys/block/%s/loop/backing_file", de->d_name);

        FILE *fp = fopen(backing_file_path, "r");
        if (!fp) continue;

        char backing[PATH_MAX];
        if (fgets(backing, sizeof(backing), fp)) {
            // Remove trailing newline
            size_t len = strlen(backing);
            if (len > 0 && backing[len-1] == '\n') {
                backing[len-1] = '\0';
            }

            // Compare paths
            if (strcmp(backing, filepath) == 0) {
                in_use = true;
                fclose(fp);
                break;
            }
        }
        fclose(fp);
    }

    closedir(dir);
    return in_use;
}

static bool is_device_mounted(const char *devname) {
    struct stat target_st;
    if (stat(devname, &target_st) != 0) {
        perror("stat(devname)");
        return false; // If we can't stat it, allow restore attempt
    }

    bool is_block = S_ISBLK(target_st.st_mode);
    bool is_regular = S_ISREG(target_st.st_mode);

    if (!is_block && !is_regular) {
        fprintf(stderr, "Warning: '%s' is neither a block device nor regular file\n", devname);
        return false;
    }

    FILE *fp = fopen("/proc/mounts", "r");
    if (!fp) {
        perror("fopen(/proc/mounts)");
        return false;
    }

    char line[PATH_MAX * 2];
    char real_devname[PATH_MAX];
    bool mounted = false;

    // Resolve symlinks for target
    if (realpath(devname, real_devname) == NULL) {
        strncpy(real_devname, devname, sizeof(real_devname) - 1);
        real_devname[PATH_MAX - 1] = '\0';
    }

    while (fgets(line, sizeof(line), fp)) {
        char mount_dev[PATH_MAX];
        if (sscanf(line, "%s", mount_dev) != 1) continue;

        // For block devices: compare device numbers
        if (is_block) {
            struct stat mount_st;
            if (stat(mount_dev, &mount_st) == 0 && S_ISBLK(mount_st.st_mode)) {
                if (mount_st.st_rdev == target_st.st_rdev) {
                    mounted = true;
                    break;
                }
            }
        }

        // For regular files (loop backing files): compare resolved paths
        if (is_regular) {
            char real_mount[PATH_MAX];
            if (realpath(mount_dev, real_mount) != NULL) {
                if (strcmp(real_mount, real_devname) == 0) {
                    mounted = true;
                    break;
                }
            }
        }
    }

    fclose(fp);

    // Additional check for regular files: check if used by any loop device
    if (!mounted && is_regular) {
        mounted = is_loop_backing_file_in_use(real_devname);
    }

    return mounted;
}


static int restore_from_dir(const char *devname, const char *session_dir) {
    char path_map[PATH_MAX], path_dat[PATH_MAX];
    snprintf(path_map, sizeof(path_map), "%s/%s/blocks.map", SNAPSHOT_ROOT, session_dir);
    snprintf(path_dat, sizeof(path_dat), "%s/%s/blocks.dat", SNAPSHOT_ROOT, session_dir);

    int fd_map = open(path_map, O_RDONLY);
    if (fd_map < 0) { perror("open blocks.map"); return -1; }
    int fd_dat = open(path_dat, O_RDONLY);
    if (fd_dat < 0) { perror("open blocks.dat"); close(fd_map); return -1; }

    int fd_target = -1;
    if (strncmp(devname, "/dev/", 5) == 0) {
        //Real block device
        fd_target = open(devname, O_RDWR | O_SYNC);
    } else {
        //Regular files mounted as loop device
        fd_target = open(devname, O_WRONLY | O_SYNC);
    }
    if (fd_target < 0) {
        perror("open target");
        close(fd_map); close(fd_dat);
        return -1;
    }

    printf("\nRestoring from '%s' to '%s'...\n", session_dir, devname);
    fflush(stdout);

    size_t count = 0;
    for (;;) {
        snapshot_rec_t rec;
        ssize_t r = read(fd_map, &rec, sizeof(rec));
        if (r == 0) break;               // EOF
        if (r < 0) { perror("read(map)"); goto fail; }
        if ((size_t)r != sizeof(rec)) { fprintf(stderr, "Corrupt map record size\n"); goto fail; }

        if (rec.size == 0 || rec.size > (64u<<20)) { // sanity: max 64 MiB per record
            fprintf(stderr, "Invalid block size %u in map\n", rec.size);
            goto fail;
        }

        // fetch payload
        void *buf = malloc(rec.size);
        if (!buf) { perror("malloc"); goto fail; }
        if (lseek(fd_dat, (off_t)rec.offset, SEEK_SET) < 0) { perror("lseek(dat)"); free(buf); goto fail; }
        ssize_t r2 = read(fd_dat, buf, rec.size);
        if (r2 != (ssize_t)rec.size) { perror("read(dat)"); free(buf); goto fail; }

        // write back to target at byte offset sector*512
        off_t off = (off_t)(rec.sector * SECTOR_SIZE);
        ssize_t w = pwrite(fd_target, buf, rec.size, off);
        free(buf);
        if (w != (ssize_t)rec.size) { perror("pwrite(target)"); goto fail; }

        count++;
        if ((count % 1024) == 0) {
            printf("  ... %zu blocks restored\r", count);
            fflush(stdout);
        }
    }

    if (fsync(fd_target) != 0) perror("fsync(target)");
    printf("Restore complete: %zu blocks written.\n", count);

    close(fd_target);
    close(fd_dat);
    close(fd_map);
    return 0;

fail:
    close(fd_target);
    close(fd_dat);
    close(fd_map);
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <devname-or-backing-file>\n", argv[0]);
        return 2;
    }
    const char *devname = argv[1];

    if (geteuid() != 0) {
        fprintf(stderr, "Error: this program must run as root.\n");
        return 1;
    }

    // Basic existence check of /snapshot
    struct stat st;
    if (stat(SNAPSHOT_ROOT, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: '%s' not found \n", SNAPSHOT_ROOT);
        return 1;
    }
    bool mounted = is_device_mounted(devname);
    if (mounted) {
        fprintf(stderr, "Refusing to restore: device appears mounted (%s).\n", devname);
        fprintf(stderr, "Please unmount it first.\n");
        return 1;
    }

    session_t *list = NULL;
    size_t n = 0;
    if (list_sessions_for_dev(devname, &list, &n) != 0) {
        fprintf(stderr, "Failed to scan snapshots.\n");
        return 1;
    }
    if (n == 0) {
        printf("No snapshots found in %s for '%s'.\n", SNAPSHOT_ROOT, devname);
        free(list);
        return 0;
    }

    print_table(list, n);

    // Choose
    printf("\nSelect snapshot to restore [1-%zu] (0 to exit): ", n);
    fflush(stdout);
    char line[64];
    if (!fgets(line, sizeof(line), stdin)) {
        free(list);
        return 1;
    }
    char *endp = NULL;
    long choice = strtol(line, &endp, 10);
    if (choice == 0) { free(list); return 0; }
    if (choice < 1 || (size_t)choice > n) {
        fprintf(stderr, "Invalid choice.\n");
        free(list);
        return 1;
    }

    // Final confirmation
    printf("You selected '%s'. This will overwrite data on '%s'.\n", list[choice-1].dirname, devname);
    printf("Type'Y' to proceed: ");
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin)) { free(list); return 1; }
    if (strcmp(line, "Y\n") != 0 && strcmp(line, "Y") != 0) {
        printf("Aborted.\n");
        free(list);
        return 0;
    }

    int rc = restore_from_dir(devname, list[choice-1].dirname);
    free(list);
    return (rc == 0) ? 0 : 1;
}
