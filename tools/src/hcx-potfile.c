#include "utils.h"
#include <linux/limits.h>
#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct PotItem {
    int num;
    char hash[128];
    char essid[256];
    char password[256];
};

struct PotArgs {
    int sort_col;
    bool passonly;
    bool nocolor;
    char* potfile_path;
};

int sort_column;

static int compare_pot_items(const void* a, const void* b)
{
    const struct PotItem* ia = (const struct PotItem*)a;
    const struct PotItem* ib = (const struct PotItem*)b;

    switch (sort_column) {
        case 0:  return ia->num - ib->num;
        case 1:  return strcmp(ia->hash, ib->hash);
        case 2:  return strcmp(ia->essid, ib->essid);
        case 3:  return strcmp(ia->password, ib->password);
        default: return 0;
    }
}

static void print_pot_table(struct PotItem* items, size_t count, bool nocolor)
{
    const char* headers[] = {"#", "HASHCAT ID", "ESSID", "PASSWORD"};
    const int num_cols = 4;

    // Initialize widths with header lengths
    size_t widths[4];
    for (int i = 0; i < num_cols; i++) {
        widths[i] = strlen(headers[i]);
    }

    // Calculate maximum width needed for each column
    for (size_t i = 0; i < count; i++) {
        char num_str[32];
        snprintf(num_str, sizeof(num_str), "%d", items[i].num);

        size_t col_widths[4] = {
            strlen(num_str),
            strlen(items[i].hash),
            utf8_display_width(items[i].essid),
            strlen(items[i].password)};

        for (int j = 0; j < num_cols; j++) {
            if (col_widths[j] > widths[j]) {
                widths[j] = col_widths[j];
            }
        }
    }

    // Print header
    for (int i = 0; i < num_cols; i++) {
        printf("%-*s", (int)widths[i], headers[i]);
        if (i < num_cols - 1) printf("  ");
    }
    printf("\n");

    // Print separator line
    for (int i = 0; i < num_cols; i++) {
        for (size_t j = 0; j < widths[i]; j++) {
            putchar('-');
        }
        if (i < num_cols - 1) printf("  ");
    }
    printf("\n");

    // Print data rows
    for (size_t i = 0; i < count; i++) {
        char num_str[16];
        snprintf(num_str, sizeof(num_str), "%d", items[i].num);

        // Column 0: number
        if (!nocolor) printf(COLOR_YELLOW);
        print_cell(num_str, widths[0]);
        if (!nocolor) printf(COLOR_RESET);
        printf("  ");

        // Column 1: hash
        if (!nocolor) printf(COLOR_GREEN);
        print_cell(items[i].hash, widths[1]);
        if (!nocolor) printf(COLOR_RESET);
        printf("  ");

        // Column 2: ESSID (UTF-8 safe)
        if (!nocolor) printf(COLOR_BLUE);
        print_cell(items[i].essid, widths[2]);
        if (!nocolor) printf(COLOR_RESET);
        printf("  ");

        // Column 3: password (UTF-8 safe)
        if (!nocolor) printf(COLOR_RED);
        print_cell(items[i].password, widths[3]);
        if (!nocolor) printf(COLOR_RESET);

        // End of row
        printf("\n");
    }
}

int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "");

    struct PotArgs args = {-1, false, false, NULL};

    // Default potfile path
    char default_path[PATH_MAX];
    const char* home = getenv("HOME");
    if (home) {
        snprintf(default_path, sizeof(default_path), "%s/.local/share/hashcat/hashcat.potfile", home);
        args.potfile_path = default_path;
    }

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--sort") == 0) {
            if (++i < argc) args.sort_col = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--passonly") == 0) {
            args.passonly = true;
        }
        else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--nocolor") == 0) {
            args.nocolor = true;
        }
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0) {
            if (++i < argc) args.potfile_path = argv[i];
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-s col] [-p] [-c] [-i potfile]\n", argv[0]);
            printf("  -s, --sort      Sort output by column number\n");
            printf("  -p, --passonly  Only print passwords from potfile\n");
            printf("  -c, --nocolor   Don't use colors when printing\n");
            printf("  -i, --input     Manually specify potfile path\n");
            return 0;
        }
    }

    if (!args.potfile_path) {
        fprintf(stderr, "Error: Could not determine potfile path\n");
        return 1;
    }

    // Open potfile
    FILE* f = fopen(args.potfile_path, "r");
    if (!f) {
        perror("fopen");
        fprintf(stderr, "Could not open: %s\n", args.potfile_path);
        return 1;
    }

    // If passonly mode, just print passwords
    if (args.passonly) {
        char line[MAX_LINE];
        while (fgets(line, sizeof(line), f)) {
            if (line[0] == '\n' || line[0] == 0) continue;

            // Split by '*'
            char* star = strchr(line, '*');
            if (!star) continue;

            // Split by ':'
            char* colon = strchr(star + 1, ':');
            if (!colon) continue;

            // Password is after the colon
            char* password = colon + 1;
            char* newline = strchr(password, '\n');
            if (newline) *newline = 0;

            printf("%s\n", password);
        }
        fclose(f);
        return 0;
    }

    // Parse full potfile for table display
    struct PotItem* items = malloc(10000 * sizeof(struct PotItem));
    size_t count = 0, capacity = 10000;
    char line[MAX_LINE];

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '\n' || line[0] == 0) continue;

        // Split by '*'
        char* star = strchr(line, '*');
        if (!star) continue;
        *star = 0;

        char* hash_part = line;
        char* rest = star + 1;

        // Split rest by ':'
        char* colon = strchr(rest, ':');
        if (!colon) continue;
        *colon = 0;

        char* essid_hex = rest;
        char* password = colon + 1;

        // Remove newline from password
        char* newline = strchr(password, '\n');
        if (newline) *newline = 0;

        // Expand array if needed
        if (count >= capacity) {
            capacity *= 2;
            items = realloc(items, capacity * sizeof(struct PotItem));
        }

        struct PotItem* item = &items[count];
        item->num = (int)count;

        strncpy(item->hash, hash_part, sizeof(item->hash) - 1);
        item->hash[sizeof(item->hash) - 1] = 0;

        hex2str(essid_hex, item->essid, sizeof(item->essid));

        strncpy(item->password, password, sizeof(item->password) - 1);
        item->password[sizeof(item->password) - 1] = 0;

        count++;
    }
    fclose(f);

    // Sort if requested
    if (args.sort_col >= 0 && args.sort_col <= 3) {
        sort_column = args.sort_col;
        qsort(items, count, sizeof(struct PotItem), compare_pot_items);
    }

    // Print table
    print_pot_table(items, count, args.nocolor);

    // Cleanup
    free(items);

    return 0;
}
