#include "utils.h"
#include <linux/limits.h>
#include <locale.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// Compare function for qsort
int (*cmp_func)(const void*, const void*);
int sort_column;

int compare_items(const void* a, const void* b)
{
    struct HashItem* ia = (struct HashItem*)a;
    struct HashItem* ib = (struct HashItem*)b;

    switch (sort_column) {
        case 0:  return ia->num - ib->num;
        case 1:  return strcmp(ia->type, ib->type);
        case 2:  return strcmp(ia->hashid, ib->hashid);
        case 3:  return strcmp(ia->bssid, ib->bssid);
        case 4:  return strcmp(ia->mac, ib->mac);
        case 5:  return strcmp(ia->essid, ib->essid);
        case 6:  return strcmp(ia->passwd, ib->passwd);
        case 7:  return strcmp(ia->vendor_ap, ib->vendor_ap);
        case 8:  return strcmp(ia->vendor_client, ib->vendor_client);
        default: return 0;
    }
}

// Print table with dynamic column widths
void print_table(struct HashItem* items, int count, bool nocolor)
{
    const char* headers[] = {"#", "TYPE", "HASH", "MAC AP", "MAC CLIENT", "ESSID", "PASSWORD", "VENDOR AP", "VENDOR CLIENT"};
    const int num_cols = 9;

    // Initialize widths with header lengths (minimum widths)
    size_t widths[9];
    for (int i = 0; i < num_cols; i++) {
        widths[i] = strlen(headers[i]);
    }

    // Calculate maximum width needed for each column
    for (int i = 0; i < count; i++) {
        char num_str[16];
        snprintf(num_str, sizeof(num_str), "%d", items[i].num);

        size_t col_widths[9] = {
            strlen(num_str),
            strlen(items[i].type),
            strlen(items[i].hashid),
            strlen(items[i].bssid),
            strlen(items[i].mac),
            utf8_display_width(items[i].essid),
            strlen(items[i].passwd),
            strlen(items[i].vendor_ap),
            strlen(items[i].vendor_client)};

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
    for (int i = 0; i < count; i++) {
        char num_str[16];
        snprintf(num_str, sizeof(num_str), "%d", items[i].num);

        if (nocolor) {
            printf("%-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s\n",
                   (int)widths[0], num_str,
                   (int)widths[1], items[i].type,
                   (int)widths[2], items[i].hashid,
                   (int)widths[3], items[i].bssid,
                   (int)widths[4], items[i].mac,
                   (int)widths[5], items[i].essid,
                   (int)widths[6], items[i].passwd,
                   (int)widths[7], items[i].vendor_ap,
                   (int)widths[8], items[i].vendor_client);
        }
        else {
            // clang-format off
            printf(COLOR_YELLOW   "%-*s"       COLOR_RESET "  "
                   COLOR_GREEN    "%-*s  %-*s" COLOR_RESET "  "
                   COLOR_MAGENTA  "%-*s"       COLOR_RESET "  "
                   COLOR_BLUE     "%-*s"       COLOR_RESET "  "
                   COLOR_RESET    "%-*s"       COLOR_RESET "  "
                   COLOR_RED      "%-*s"       COLOR_RESET "  "
                   COLOR_MAGENTA  "%-*s"       COLOR_RESET "  "
                   COLOR_BLUE     "%-*s"       COLOR_RESET "\n",
                   (int)widths[0], num_str,
                   (int)widths[1], items[i].type,
                   (int)widths[2], items[i].hashid,
                   (int)widths[3], items[i].bssid,
                   (int)widths[4], items[i].mac,
                   (int)widths[5], items[i].essid,
                   (int)widths[6], items[i].passwd,
                   (int)widths[7], items[i].vendor_ap,
                   (int)widths[8], items[i].vendor_client);
            // clang-format on
        }
    }
}
int main(int argc, char* argv[])
{
    // Set locale for proper UTF-8 handling
    setlocale(LC_ALL, "");

    struct Args args = {-1, false, false, false, NULL, NULL};

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        // clang-format off
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--sort") == 0) { if (++i < argc) args.sort_col = atoi(argv[i]); }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--vendor") == 0) { args.vendor = true; }
        else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--nohashcat") == 0) { args.nohashcat = true; }
        else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--nocolor") == 0) { args.nocolor = true; }
        else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--search") == 0) { if (++i < argc) args.search = argv[i]; }
        else if (argv[i][0] != '-') { args.filename = argv[i]; }
        // clang-format on
    }

    if (!args.filename) {
        fprintf(stderr,
                "ABOUT: Print a table for WPA-PBKDF2-PMKID+EAPOL hashes in file\n"
                "USAGE: %s [-s col] [-v] [-n] [-c] [-g search] <filename>\n"
                "\n"
                "positional arguments:\n"
                "  filename\n"
                "\n"
                "options:\n"
                "  -h, --help            show this help message and exit\n"
                "  -s, --sort <clm_num>  sort output by column\n"
                "  -v, --vendor          fetch vendor information for all MACs\n"
                "  -n, --nohashcat       dont't fetch passwords from hashcat\n"
                "  -c, --nocolor         dont't use colors when printing\n"
                "  -g, --search <match>  search hash by (ESSID, BSSID, MAC, ...) and print line\n",
                argv[0]);
        return 1;
    }

    struct VendorTable* vendors = args.vendor ? load_vendors_bin_dir() : NULL;

    // Load hashcat results
    struct HashTable* hashcat = args.nohashcat ? NULL : load_hashcat(args.filename);

    // Read hash file
    FILE* f = fopen(args.filename, "r");
    if (!f) {
        perror("fopen");
        return 1;
    }

    // use hashitem as a dynm array
    struct HashItem* items = malloc(10000 * sizeof(struct HashItem));
    int count = 0, capacity = 10000;
    char line[MAX_LINE];
    char line_original[MAX_LINE];

    while (fgets(line, sizeof(line), f)) {
        memcpy(line_original, line, sizeof(line));
        if (line[0] == '\n' || line[0] == 0) continue;

        // line buffer get's split we put null where * is
        char* parts[10];
        int np = 0;
        char* p = line;
        while (*p && np < 10) {
            parts[np++] = p;
            p = strchr(p, '*');
            if (!p) break;
            *p++ = 0;
        }

        if (np < 6) continue;

        if (count >= capacity) {
            capacity *= 2;
            items = realloc(items, capacity * sizeof(struct HashItem));
        }

        struct HashItem* item = &items[count++];
        item->num = count;

        if (strcmp(parts[1], "01") == 0)
            strcpy(item->type, "PMKID");
        else if (strcmp(parts[1], "02") == 0)
            strcpy(item->type, "EAPOL");
        else
            item->type[0] = 0;

        strncpy(item->hashid, parts[2], sizeof(item->hashid) - 1);
        strncpy(item->bssid, parts[3], sizeof(item->bssid) - 1);
        strncpy(item->mac, parts[4], sizeof(item->mac) - 1);
        hex2str(parts[5], item->essid, sizeof(item->essid), args.nocolor);

        const char* pw = hashcat ? ht_get(hashcat, parts[2]) : NULL;
        if (pw)
            strncpy(item->passwd, pw, sizeof(item->passwd) - 1);
        else
            item->passwd[0] = 0;

        if (vendors) {
            mac2ven(item->bssid, item->vendor_ap, sizeof(item->vendor_ap), vendors);
            mac2ven(item->mac, item->vendor_client, sizeof(item->vendor_client), vendors);
        }
        else {
            item->vendor_ap[0] = 0;
            item->vendor_client[0] = 0;
        }

        // Search mode
        if (args.search) {
            if (istrstr(item->type, args.search) ||
                istrstr(item->hashid, args.search) ||
                istrstr(item->bssid, args.search) ||
                istrstr(item->mac, args.search) ||
                istrstr(item->essid, args.search) ||
                istrstr(item->passwd, args.search) ||
                istrstr(item->vendor_ap, args.search) ||
                istrstr(item->vendor_client, args.search)) {
                printf("%s", line_original);
            }
        }
    }
    fclose(f);

    if (args.search) {
        free(items);
        if (hashcat) ht_free(hashcat);
        return 0;
    }

    // Sort if requested
    if (args.sort_col >= 0 && args.sort_col <= 8) {
        sort_column = args.sort_col;
        qsort(items, count, sizeof(struct HashItem), compare_items);
    }

    // Print table
    print_table(items, count, args.nocolor);

    // Cleanup
    free(items);
    if (hashcat) ht_free(hashcat);

    return 0;
}
