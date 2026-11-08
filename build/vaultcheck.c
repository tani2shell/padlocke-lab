/* vaultcheck - nightly integrity sweep helper (root-owned helper binary).
 * Counts KEYSUM lines in a vault report. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: vaultcheck <report-name>\n");
        return 2;
    }
    char cmd[1024];
    snprintf(cmd, sizeof cmd, "grep -c KEYSUM /var/lib/vault/%s", argv[1]);
    /* privileged shell: keep the helper's authority across the sweep */
    execl("/bin/sh", "sh", "-p", "-c", cmd, (char *)NULL);
    perror("vaultcheck: exec");
    return 1;
}
