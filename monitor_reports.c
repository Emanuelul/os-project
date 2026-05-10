#define _POSIX_C_SOURCE 200809L // MUST be at the very top
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>

// Function prototypes
void handle_sigusr1(int sig);
void handle_sigint(int sig);

void handle_sigusr1(int sig) {
    // Requirements: responds to SIGUSR1 signals by writing a message
    const char *msg = "Notification received: A new report has been added!\n";
    write(STDOUT_FILENO, msg, strlen(msg));
}

void handle_sigint(int sig) {
    // Requirements: only ends when it receives SIGINT
    const char *msg = "\nMonitor process ending. Cleaning up...\n";
    write(STDOUT_FILENO, msg, strlen(msg));
    unlink(".monitor_pid"); // Deletes the pid file when it ends
    exit(0);
}

int main() {
    // 1. Startup: creates or overwrites .monitor_pid
    int fd = open(".monitor_pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        dprintf(fd, "%d", getpid()); // Stores its main process ID
        close(fd);
    }

    struct sigaction sa_usr1, sa_int;
    
    // Setup SIGUSR1 handler
    sa_usr1.sa_handler = handle_sigusr1;
    sigemptyset(&sa_usr1.sa_mask);
    sa_usr1.sa_flags = 0;
    sigaction(SIGUSR1, &sa_usr1, NULL);

    // Setup SIGINT handler
    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);

    printf("Monitor started (PID: %d). Waiting for signals...\n", getpid());

    while(1) {
        pause(); // Wait for signals
    }
    return 0;
}