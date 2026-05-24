#define _POSIX_C_SOURCE 200809L 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

void handle_sigusr1(int sig) {
    const char *msg = "[MSG] Notification received: A new report has been added!\n";
    write(STDOUT_FILENO, msg, strlen(msg));
}

void handle_sigint(int sig) {
    const char *msg = "[MSG] Monitor process ending. Cleaning up...\n";
    write(STDOUT_FILENO, msg, strlen(msg));
    unlink(".monitor_pid"); 
    exit(0);
}

int main() {
    int check_fd = open(".monitor_pid", O_RDONLY);
    if (check_fd >= 0) {
        char pid_buf[16];
        ssize_t bytes = read(check_fd, pid_buf, sizeof(pid_buf) - 1);
        close(check_fd);
        if (bytes > 0) {
            pid_buf[bytes] = '\0';
            pid_t existing_pid = atoi(pid_buf);
            
            if (kill(existing_pid, 0) == 0 || errno != ESRCH) {
                printf("[ERR] ALREADY_RUNNING:%d\n", existing_pid);
                fflush(stdout);
                exit(1); 
            }
        }
    }

    int fd = open(".monitor_pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        dprintf(fd, "%d", getpid());
        close(fd);
    }

    struct sigaction sa_usr1, sa_int;
    
    sa_usr1.sa_handler = handle_sigusr1;
    sigemptyset(&sa_usr1.sa_mask);
    sa_usr1.sa_flags = 0;
    sigaction(SIGUSR1, &sa_usr1, NULL);

    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);

    printf("[OK] STARTED:%d\n", getpid());
    fflush(stdout);

    while(1) {
        pause(); 
    }
    return 0;
}