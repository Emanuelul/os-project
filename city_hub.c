#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

void read_line_from_pipe(int fd, char *buffer, size_t max_len) {
    size_t index = 0;
    char ch;
    while (index < max_len - 1) {
        ssize_t n = read(fd, &ch, 1);
        if (n <= 0) break; 
        if (ch == '\n') break;
        buffer[index++] = ch;
    }
    buffer[index] = '\0';
}

void start_monitor() {
    int p_fds[2];
    if (pipe(p_fds) < 0) {
        perror("Hub Failed to initialize unnamed pipeline");
        return;
    }

    pid_t hub_mon_pid = fork();
    if (hub_mon_pid == 0) { // Child Process: hub_mon
        close(p_fds[0]); // hub_mon does not read from its own monitor pipe

        // Redirect child standard output stream directly to pipe input
        dup2(p_fds[1], STDOUT_FILENO);
        close(p_fds[1]);

        // Fork standalone monitor engine binary
        pid_t mon_exec_pid = fork();
        if (mon_exec_pid == 0) {
            char *args[] = {"./monitor_reports", NULL};
            execvp(args[0], args);
            perror("Execution of monitor target executable failed");
            exit(1);
        } else if (mon_exec_pid > 0) {
            int status;
            waitpid(mon_exec_pid, &status, 0);
            exit(0); 
        }
        exit(1);
    }

    // Parent Thread Context (The Interactive Hub Core Interface)
    close(p_fds[1]); 

    char stream_buffer[256];
    printf("[Hub System] Launching automated background monitor layer...\n");

    // Read initialization transmission lines across pipeline frame
    read_line_from_pipe(p_fds[0], stream_buffer, sizeof(stream_buffer));

    if (strncmp(stream_buffer, "[ERR]", 5) == 0) {
        char *pid_part = strchr(stream_buffer, ':');
        if (pid_part) {
            printf("\033[1;31m[Hub Error]\033[0m Instantiation Blocked: Monitor already running at PID %s.\n", pid_part + 1);
        } else {
            printf("[Hub Error] Background monitor structural check crashed.\n");
        }
        close(p_fds[0]);
        waitpid(hub_mon_pid, NULL, 0);
    } else if (strncmp(stream_buffer, "[OK]", 4) == 0) {
        char *pid_part = strchr(stream_buffer, ':');
        printf("\033[1;32m[Hub Success]\033[0m Monitor sub-thread attached securely at engine PID: %s\n", pid_part ? pid_part + 1 : "Unknown");
        
        // Fork an asynchronous monitoring engine loop to stream background messages in real time
        if (fork() == 0) {
            while (1) {
                char update_buffer[256];
                memset(update_buffer, 0, sizeof(update_buffer));
                read_line_from_pipe(p_fds[0], update_buffer, sizeof(update_buffer));
                if (strlen(update_buffer) == 0) {
                    printf("\n\033[1;33m[Hub Alert]\033[0m Monitored stream connection lost. Engine pipeline terminated.\nHub Engine > ");
                    fflush(stdout);
                    break;
                }
                printf("\n\033[1;36m[Async Monitor Stream]\033[0m %s\nHub Engine > ", update_buffer);
                fflush(stdout);
            }
            close(p_fds[0]);
            exit(0);
        }
        close(p_fds[0]);
    }
}

void calculate_scores(char *args_str) {
    char *districts[50];
    int count = 0;
    
    char *tok = strtok(args_str, " \t");
    while (tok != NULL && count < 50) {
        districts[count++] = tok;
        tok = strtok(NULL, " \t");
    }

    if (count == 0) {
        printf("Error: Command requires at least one district target input variable.\n");
        return;
    }

    printf("\n=== Compiling Consolidated Hub Workload Matrix ===\n");
    for (int i = 0; i < count; i++) {
        int p_fds[2];
        if (pipe(p_fds) < 0) { perror("Pipe generation failed"); continue; }

        pid_t pid = fork();
        if (pid == 0) { // Child scorer runner
            close(p_fds[0]); 
            dup2(p_fds[1], STDOUT_FILENO); // Bind output channel directly to pipeline
            close(p_fds[1]);

            char *exec_args[] = {"./scorer", districts[i], NULL};
            execvp(exec_args[0], exec_args);
            perror("Execution context mismatch on scoring binary tool");
            exit(1);
        }

        // Parent parsing channel context
        close(p_fds[1]);
        
        char line_in[256];
        while (1) {
            memset(line_in, 0, sizeof(line_in));
            read_line_from_pipe(p_fds[0], line_in, sizeof(line_in));
            if (strlen(line_in) == 0) break;
            printf("%s\n", line_in);
        }
        close(p_fds[0]);
        waitpid(pid, NULL, 0);
    }
    printf("===================================================\n");
}

int main() {
    char user_input[512];
    printf("===================================================\n");
    printf("       CITY SYSTEM CONSOLE MANAGEMENT HUB          \n");
    printf("       Supported operations: start_monitor         \n");
    printf("                 calculate_scores <d1> <d2>...     \n");
    printf("                 exit                              \n");
    printf("===================================================\n");

    while (1) {
        printf("Hub Engine > ");
        fflush(stdout);

        if (!fgets(user_input, sizeof(user_input), stdin)) break;
        user_input[strcspn(user_input, "\n")] = '\0';

        if (strlen(user_input) == 0) continue;

        if (strcmp(user_input, "exit") == 0) {
            printf("Exiting management console pipeline space cleanly.\n");
            break;
        } else if (strcmp(user_input, "start_monitor") == 0) {
            start_monitor();
            sleep(1); // Small delay to let async outputs format cleanly
        } else if (strncmp(user_input, "calculate_scores", 16) == 0) {
            char *args_ptr = user_input + 16;
            calculate_scores(args_ptr);
        } else {
            printf("Command identity validation failed. Please check instruction usage.\n");
        }
    }
    return 0;
}