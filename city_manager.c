#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_NAME 40
#define MAX_CAT 20
#define MAX_DESC 106

typedef struct
{
	int report_id;
	char inspector_name[MAX_NAME];
	double latitude;
	double longitude;
	char category[MAX_CAT];
	int severity;
	time_t timestamp;
	char description[MAX_DESC];
} REPORT;


int check_permission(const char *path, const char *role, char access_type) {
    struct stat st;
    if (stat(path, &st) != 0) {
        perror("Stat failed");
        return 0;
    }

    if (strcmp(role, "manager") == 0) {
        if (access_type == 'r' && (st.st_mode & S_IRUSR)) {
            return 1;
        }
        if (access_type == 'w' && (st.st_mode & S_IWUSR)) {
            return 1;
        }
    } else if (strcmp(role, "inspector") == 0) {
        if (access_type == 'r' && (st.st_mode & S_IRGRP)) {
            return 1;
        }
        if (access_type == 'w' && (st.st_mode & S_IWGRP)) {
            return 1;
        }
    }

    return 0;
}

void add_report(const char *district_id, const char *role, const char *user) {
    char dir_path[256], file_path[256], log_path[256], cfg_path[256];


    snprintf(dir_path, sizeof(dir_path), "./%s", district_id);
    snprintf(file_path, sizeof(file_path), "%s/reports.dat", dir_path);
    snprintf(log_path, sizeof(log_path), "%s/logged_district", dir_path);
    snprintf(cfg_path, sizeof(cfg_path), "%s/district.cfg", dir_path);

    mkdir(dir_path, 0750);
    chmod(dir_path, 0750);

    if (access(cfg_path, F_OK) == -1) {
        int cfg_fd = open(cfg_path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
        if (cfg_fd >= 0)
        {
            close(cfg_fd);
            chmod(cfg_path, 0640);
        }
    } 

    int fd = open(file_path, O_WRONLY | O_APPEND | O_CREAT, 0664);
    if (fd < 0) {
        perror("Error opening reports.dat");
        return;
    }
    chmod(file_path, 0664);

    REPORT new_report;
    memset(&new_report, 0, sizeof(REPORT));

    struct stat st;
    stat(file_path, &st);
    new_report.report_id = st.st_size / sizeof(REPORT);

    strncpy(new_report.inspector_name, user, MAX_NAME);
    new_report.timestamp = time(NULL);

    printf("X: ");
    scanf("%lf", &new_report.latitude);
    printf("Y: ");
    scanf("%lf", &new_report.longitude);
    printf("Category (road/lighting/flooding/other): ");
    scanf("%s", new_report.category);
    printf("Severity level (1/2/3): ");
    scanf("%d", &new_report.severity);
    getchar();
    printf("Description: ");
    fgets(new_report.description, MAX_DESC, stdin);
    new_report.description[strcspn(new_report.description, "\n")] = 0;

    write(fd, &new_report, sizeof(REPORT));
    close(fd);

    if (strcmp(role, "manager") == 0) {
        int log_fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (log_fd >= 0) {
            dprintf(log_fd, "%ld %s %s add\n", new_report.timestamp, user, role);
            close(log_fd);
        }
    }

    char sym_link[256];
    snprintf(sym_link, sizeof(sym_link), "active_reports-%s", district_id);
    unlink(sym_link);
    symlink(file_path, sym_link);

    printf("Report #%d added successfully to %s.\n", new_report.report_id, district_id);
}

void get_permissions_string(mode_t mode, char *str) {
    str[0] = (mode & S_IRUSR) ? 'r' : '-';
    str[1] = (mode & S_IWUSR) ? 'w' : '-';
    str[2] = (mode & S_IXUSR) ? 'x' : '-';
    str[3] = (mode & S_IRGRP) ? 'r' : '-';
    str[4] = (mode & S_IWGRP) ? 'w' : '-';
    str[5] = (mode & S_IXGRP) ? 'x' : '-';
    str[6] = (mode & S_IROTH) ? 'r' : '-';
    str[7] = (mode & S_IWOTH) ? 'w' : '-';
    str[8] = (mode & S_IXOTH) ? 'x' : '-';
    str[9] = '\0';
}

void list_reports(const char *district_id) {
    char file_path[256];
    snprintf(file_path, sizeof(file_path), "./%s/reports.dat", district_id);

    struct stat st;
    if (stat(file_path, &st) == -1) {
        perror("Error accessing reports.dat");
        return;
    }

    char perm_str[11];
    get_permissions_string(st.st_mode, perm_str);
    printf("File: %s\n", file_path);
    printf("Permissions: %s | Size: %ld bytes | Last Modified: %s", perm_str, (long)st.st_size, ctime(&st.st_mtime));

    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        perror("Could not open file");
        return;
    }

    REPORT r;
    printf("\nID  |  Inspector   |  Category  | Sev |   Timestamp\n");
    printf("---------------------------------------------------------\n");

    while (read(fd, &r, sizeof(REPORT)) == sizeof(REPORT)) {
        char *tm_str = ctime(&r.timestamp);
        tm_str[strlen(tm_str) - 1] = '\0';

        printf("%-3d | %-12s | %-10s | %-3d | %s\n", 
               r.report_id, r.inspector_name, r.category, r.severity, tm_str);
    }

    close(fd);
}


int main(int argc, char * argv[]) {
	if (argc < 4) {
		printf("Invalid usage!");
		exit(1);
	}

	char role[MAX_NAME];
	char user[MAX_NAME];

	if (strcmp(argv[1], "--role") == 0) {
		strcpy(role, argv[2]);
	}

	if (strcmp(argv[3], "--user") == 0) {
		strcpy(user, argv[4]);
	}

	if (strcmp(argv[5], "--add") == 0) {
        if (argc < 7) {
            printf("Usage: city_manager --role <role> --user <user> --add <district_id>\n");
        }
        else {
            add_report(argv[6], role, user);
        }
	}
	else if (strcmp(argv[5], "--list") == 0) {
        if (argc < 7) {
            printf("Usage: city_manager --role <role> --user <user> --list <district_id>\n");
        }
        else {
            list_reports(argv[6]);
        }
    }
	else if (strcmp(argv[5], "--view") == 0) {
	}
	else if (strcmp(argv[5], "--remove-report") == 0) {
	}
	else if (strcmp(argv[5], "--update-threshold") == 0) {
	}
	else {
		printf("Error: Invalid operation!\n");
	}

	return 0;
}