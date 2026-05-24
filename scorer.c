#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#define MAX_NAME 40
#define MAX_CAT 20
#define MAX_DESC 106

typedef struct {
    int report_id;
    char inspector_name[MAX_NAME];
    double latitude;
    double longitude;
    char category[MAX_CAT];
    int severity;
    time_t timestamp;
    char description[MAX_DESC];
} REPORT;

typedef struct {
    char name[MAX_NAME];
    int score;
} INSPECTOR_SCORE;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <district_id>\n", argv[0]);
        return 1;
    }

    char file_path[256];
    snprintf(file_path, sizeof(file_path), "./%s/reports.dat", argv[1]);

    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        printf("District [%s]: No reports data found.\n", argv[1]);
        return 0;
    }

    INSPECTOR_SCORE roster[100];
    int roster_size = 0;
    memset(roster, 0, sizeof(roster));

    REPORT r;
    while (read(fd, &r, sizeof(REPORT)) == sizeof(REPORT)) {
        int found = 0;
        for (int i = 0; i < roster_size; i++) {
            if (strcmp(roster[i].name, r.inspector_name) == 0) {
                roster[i].score += r.severity;
                found = 1;
                break;
            }
        }
        if (!found && roster_size < 100) {
            strncpy(roster[roster_size].name, r.inspector_name, MAX_NAME);
            roster[roster_size].score = r.severity;
            roster_size++;
        }
    }
    close(fd);

    printf("--- District Workload Evaluation: %s ---\n", argv[1]);
    if (roster_size == 0) {
        printf("  No tracked inspector entries.\n");
    } else {
        for (int i = 0; i < roster_size; i++) {
            printf("  Inspector: %-15s | Aggregated Workload Score: %d\n", roster[i].name, roster[i].score);
        }
    }
    return 0;
}