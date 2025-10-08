#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

// Theese are retrived from the usctm module
#ifndef SNAP_ACTIVATE_NR
#define SNAP_ACTIVATE_NR   156L
#endif

#ifndef SNAP_DEACTIVATE_NR
#define SNAP_DEACTIVATE_NR 174L
#endif

static long call_snapshot_syscall(long nr, const char *devname, const char *passwd) {
    long ret = syscall(nr, devname, passwd);
    if (ret == -1) {
        fprintf(stderr, " Failed syscall %ld : ", nr);
        perror(NULL); 
    }
    return ret;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr,
            "Use: %s <activate|deactivate> <devname> <password>\n"
            "Example:\n"
            "  %s activate path/to/image \"V3ryStr0ngPwd\"\n",
            argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    const char *cmd  = argv[1];
    const char *dev  = argv[2];
    const char *pass = argv[3];

    long nr;
    if (strcmp(cmd, "activate") == 0) {
        nr = SNAP_ACTIVATE_NR;
    } else if (strcmp(cmd, "deactivate") == 0) {
        nr = SNAP_DEACTIVATE_NR;
    } else {
        fprintf(stderr, "Not a valid command: '%s' (use 'activate' o 'deactivate')\n", cmd);
        return EXIT_FAILURE;
    }

    long ret = call_snapshot_syscall(nr, dev, pass);
    if (ret == -1) {
        return EXIT_FAILURE;
    }

    printf("Run command '%s': syscall %ld returned %ld\n", cmd, nr, ret);
    return EXIT_SUCCESS;
}
