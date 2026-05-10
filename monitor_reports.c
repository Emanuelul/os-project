#define _POSIX_C_SOURCE 200809L 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>


void handle_sigusr1(int sig);
void handle_sigint(int sig);

void handle_sigusr1(int sig) {

    const char *msg = "Notification received: A new report has been added!\n";
    write(STDOUT_FILENO, msg, strlen(msg));
}

void handle_sigint(int sig) {

    const char *msg = "\nMonitor process ending. Cleaning up...\n";
    write(STDOUT_FILENO, msg, strlen(msg));
    unlink(".monitor_pid"); 
    exit(0);
}

int main() {
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

    printf("Monitor started (PID: %d). Waiting for signals...\n", getpid());

    while(1) {
        pause();
    }
    return 0;
}