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

int check_permission(const char *path, const char *role, char access_type)
{
    struct stat st;
    if (stat(path, &st) != 0)
    {
        return -1; 
    }

    if (strcmp(role, "manager") == 0)
    {
        if (access_type == 'r') return (st.st_mode & S_IRUSR);
        if (access_type == 'w') return (st.st_mode & S_IWUSR);
    }
    else if (strcmp(role, "inspector") == 0)
    {
        if (access_type == 'r') return (st.st_mode & S_IRGRP);
        if (access_type == 'w') return (st.st_mode & S_IWGRP);
    }

    return 0;
}

void log_action(const char *district_id, const char *role, const char *user, const char *action_details)
{
    char log_path[256];
    snprintf(log_path, sizeof(log_path), "./%s/logged_district", district_id);

    if (access(log_path, F_OK) == 0)
    {
        if (!check_permission(log_path, role, 'w'))
        {
            fprintf(stderr, "Log Security: Role '%s' denied write access to %s (Permissions enforced).\n", role, log_path);
            return;
        }
    }

    int fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd >= 0)
    {
        dprintf(fd, "%ld %s %s %s\n", (long)time(NULL), user, role, action_details);
        close(fd);
    }
    else
    {
        perror("System Error: Could not open log file");
    }
}

void add_report(const char *district_id, const char *role, const char *user)
{
    char dir_path[256], file_path[256], cfg_path[256];

    snprintf(dir_path, sizeof(dir_path), "./%s", district_id);
    snprintf(file_path, sizeof(file_path), "%s/reports.dat", dir_path);
    snprintf(cfg_path, sizeof(cfg_path), "%s/district.cfg", dir_path);

    mkdir(dir_path, 0750);
    chmod(dir_path, 0750);

    if (access(cfg_path, F_OK) == -1)
    {
        int cfg_fd = open(cfg_path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
        if (cfg_fd >= 0)
        {
            close(cfg_fd);
            chmod(cfg_path, 0640);
        }
    }

    int fd = open(file_path, O_WRONLY | O_APPEND | O_CREAT, 0664);
    if (fd < 0)
    {
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
    scanf("%19s", new_report.category);
    printf("Severity level (1/2/3): ");
    scanf("%d", &new_report.severity);
    getchar();
    printf("Description: ");
    fgets(new_report.description, MAX_DESC, stdin);
    new_report.description[strcspn(new_report.description, "\n")] = 0;

    write(fd, &new_report, sizeof(REPORT));
    close(fd);

    log_action(district_id, role, user, "add");

    char sym_link[256];
    snprintf(sym_link, sizeof(sym_link), "active_reports-%s", district_id);
    unlink(sym_link);
    symlink(file_path, sym_link);

    printf("Report #%d added successfully to %s.\n", new_report.report_id, district_id);
}

void get_permissions_string(mode_t mode, char *str)
{
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

void list_reports(const char *district_id, const char *role, const char *user)
{
    char file_path[256];
    snprintf(file_path, sizeof(file_path), "./%s/reports.dat", district_id);

    struct stat st;
    if (stat(file_path, &st) == -1)
    {
        perror("Error: Could not find reports.dat for this district");
        return;
    }

    char perm_str[10];
    get_permissions_string(st.st_mode, perm_str);

    printf("\n==========================================\n");
    printf("DISTRICT: %s\n", district_id);
    printf("FILE PERMISSIONS: %s\n", perm_str);
    printf("FILE SIZE: %ld bytes\n", (long)st.st_size);

    char *mod_time = ctime(&st.st_mtime);
    printf("LAST MODIFIED: %s", mod_time);
    printf("==========================================\n");

    int fd = open(file_path, O_RDONLY);
    if (fd < 0)
    {
        perror("Error opening file");
        return;
    }

    REPORT r;
    printf("%-3s | %-12s | %-10s | %-3s | %s\n", "ID", "Inspector", "Category", "Sev", "Timestamp");
    printf("----------------------------------------------------------------------\n");

    while (read(fd, &r, sizeof(REPORT)) == sizeof(REPORT))
    {
        char *report_time = ctime(&r.timestamp);
        report_time[strcspn(report_time, "\n")] = 0;

        printf("%-3d | %-12s | %-10s | %-3d | %s\n",
               r.report_id, r.inspector_name, r.category, r.severity, report_time);
    }
    close(fd);

    log_action(district_id, role, user, "list");
}

void view_report(const char *district_id, int target_id, const char *role, const char *user)
{
    char file_path[256];
    snprintf(file_path, sizeof(file_path), "./%s/reports.dat", district_id);

    struct stat st;
    if (stat(file_path, &st) == -1)
    {
        perror("Error: District not found");
        return;
    }

    long max_reports = st.st_size / sizeof(REPORT);
    if (target_id < 0 || target_id >= max_reports)
    {
        printf("Error: Report ID %d does not exist. (Total reports: %ld)\n", target_id, max_reports);
        return;
    }

    int fd = open(file_path, O_RDONLY);
    if (fd < 0)
    {
        perror("Error opening reports.dat");
        return;
    }

    off_t offset = target_id * sizeof(REPORT);
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1)
    {
        perror("Error seeking in file");
        close(fd);
        return;
    }

    REPORT r;
    if (read(fd, &r, sizeof(REPORT)) != sizeof(REPORT))
    {
        printf("Error: Could not read report data.\n");
    }
    else
    {
        printf("\n--- Report Details [ID: %d] ---\n", r.report_id);
        printf("Inspector:   %s\n", r.inspector_name);
        printf("Location:    (%.4f, %.4f)\n", r.latitude, r.longitude);
        printf("Category:    %s\n", r.category);
        printf("Severity:    %d\n", r.severity);
        printf("Timestamp:   %s", ctime(&r.timestamp));
        printf("Description: %s\n", r.description);
        printf("------------------------------\n");
    }
    close(fd);

    char details[64];
    snprintf(details, sizeof(details), "view %d", target_id);
    log_action(district_id, role, user, details);
}

void remove_report(const char *district_id, int target_id, const char *role, const char *user)
{
    if (strcmp(role, "manager") != 0)
    {
        printf("Access Denied: Only managers can remove reports.\n");
        return;
    }

    char file_path[256];
    snprintf(file_path, sizeof(file_path), "./%s/reports.dat", district_id);

    int fd = open(file_path, O_RDWR);
    if (fd < 0)
    {
        perror("Error opening reports.dat");
        return;
    }

    struct stat st;
    fstat(fd, &st);
    long total_records = st.st_size / sizeof(REPORT);

    if (target_id < 0 || target_id >= total_records)
    {
        printf("Error: Report ID %d does not exist.\n", target_id);
        close(fd);
        return;
    }

    REPORT temp;
    for (int i = target_id + 1; i < total_records; i++)
    {
        lseek(fd, i * sizeof(REPORT), SEEK_SET);
        read(fd, &temp, sizeof(REPORT));

        temp.report_id = i - 1;

        lseek(fd, (i - 1) * sizeof(REPORT), SEEK_SET);
        write(fd, &temp, sizeof(REPORT));
    }

    if (ftruncate(fd, (total_records - 1) * sizeof(REPORT)) == -1)
    {
        perror("Error truncating file");
    }

    close(fd);

    char details[64];
    snprintf(details, sizeof(details), "remove_report %d", target_id);
    log_action(district_id, role, user, details);

    printf("Report #%d removed and IDs updated.\n", target_id);
}

void update_threshold(const char *district_id, const char *new_threshold, const char *role, const char *user) {
    if (strcmp(role, "manager") != 0) {
        printf("Access Denied: Only managers can update the district threshold.\n");
        return;
    }

    char cfg_path[256];
    snprintf(cfg_path, sizeof(cfg_path), "./%s/district.cfg", district_id);

    struct stat st;
    if (stat(cfg_path, &st) == 0) {
        if ((st.st_mode & 0777) != 0640) {
            fprintf(stderr, "Security Error: Permissions for %s have been tampered with (%o)! Refusing to write.\n", 
                    cfg_path, st.st_mode & 0777);
            return;
        }
    }

    int fd = open(cfg_path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0) {
        perror("Error opening district.cfg");
        return;
    }

    if (write(fd, new_threshold, strlen(new_threshold)) == -1) {
        perror("Error writing to configuration");
    } else {
        printf("Threshold for district '%s' updated to: %s\n", district_id, new_threshold);
    }
    
    close(fd);

    char details[64];
    snprintf(details, sizeof(details), "update_threshold %s", new_threshold);
    log_action(district_id, role, user, details);
}

int parse_condition(const char *cond_str, char *field, char *op, char *value)
{
    if (sscanf(cond_str, "%[^:]:%[^:]:%s", field, op, value) == 3)
    {
        return 1;
    }
    return 0;
}

int match_condition(REPORT *r, const char *field, const char *op, const char *value)
{
    if (strcmp(field, "severity") == 0)
    {
        int val = atoi(value);
        if (strcmp(op, "==") == 0)
            return r->severity == val;
        if (strcmp(op, "!=") == 0)
            return r->severity != val;
        if (strcmp(op, ">") == 0)
            return r->severity > val;
        if (strcmp(op, "<") == 0)
            return r->severity < val;
        if (strcmp(op, ">=") == 0)
            return r->severity >= val;
        if (strcmp(op, "<=") == 0)
            return r->severity <= val;
    }
    else if (strcmp(field, "category") == 0)
    {
        if (strcmp(op, "==") == 0)
            return strcmp(r->category, value) == 0;
        if (strcmp(op, "!=") == 0)
            return strcmp(r->category, value) != 0;
    }
    else if (strcmp(field, "inspector") == 0)
    {
        if (strcmp(op, "==") == 0)
            return strcmp(r->inspector_name, value) == 0;
    }
    return 0;
}

void filter_reports(const char *district_id, const char *cond_str, const char *role, const char *user)
{
    char file_path[256];
    snprintf(file_path, sizeof(file_path), "./%s/reports.dat", district_id);

    char field[20], op[5], value[MAX_DESC];
    if (!parse_condition(cond_str, field, op, value))
    {
        printf("Error: Invalid filter format. Use 'field:op:value'\n");
        return;
    }

    int fd = open(file_path, O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        return;
    }

    REPORT r;
    printf("\n--- Filtered Results (%s) ---\n", cond_str);
    while (read(fd, &r, sizeof(REPORT)) == sizeof(REPORT))
    {
        if (match_condition(&r, field, op, value))
        {
            printf("[%d] %-10s | Sev: %d | %s\n", r.report_id, r.category, r.severity, r.description);
        }
    }
    close(fd);

    log_action(district_id, role, user, "filter");
}

int main(int argc, char *argv[])
{
    if (argc < 6)
    {
        printf("Invalid usage!");
        exit(1);
    }

    char role[MAX_NAME] = "";
    char user[MAX_NAME] = "";

    if (strcmp(argv[1], "--role") == 0)
    {
        strcpy(role, argv[2]);
    }

    if (strcmp(argv[3], "--user") == 0)
    {
        strcpy(user, argv[4]);
    }

    if (strcmp(argv[5], "--add") == 0)
    {
        if (argc < 7)
        {
            printf("Usage: city_manager --role <role> --user <user> --add <district_id>\n");
        }
        else
        {
            add_report(argv[6], role, user);
        }
    }
    else if (strcmp(argv[5], "--list") == 0)
    {
        if (argc < 7)
        {
            printf("Usage: city_manager --role <role> --user <user> --list <district_id>\n");
        }
        else
        {
            list_reports(argv[6], role, user);
        }
    }
    else if (strcmp(argv[5], "--view") == 0)
    {
        if (argc < 8)
        {
            printf("Usage: city_manager --role <role> --user <user> --view <district_id> <report_id>\n");
        }
        else
        {
            int target_id = atoi(argv[7]);
            view_report(argv[6], target_id, role, user);
        }
    }
    else if (strcmp(argv[5], "--remove_report") == 0)
    {
        if (argc < 8)
        {
            printf("Usage: city_manager --role manager --user <user> --remove_report <district> <id>\n");
        }
        else
        {
            remove_report(argv[6], atoi(argv[7]), role, user);
        }
    }
    else if (strcmp(argv[5], "--update_threshold") == 0)
    {
        if (argc < 8)
        {
            printf("Usage: city_manager --role manager --user <user> --update_threshold <district> <value>\n");
        }
        else
        {
            update_threshold(argv[6], argv[7], role, user);
        }
    }
    else if (strcmp(argv[5], "--filter") == 0)
    {
        if (argc < 8)
        {
            printf("Usage: city_manager --role <role> --user <user> --filter <district> <condition>\n");
        }
        else
        {
            filter_reports(argv[6], argv[7], role, user);
        }
    }
    else
    {
        printf("Error: Invalid operation!\n");
    }

    return 0;
}