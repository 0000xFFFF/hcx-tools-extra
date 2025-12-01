#include "utils.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static volatile bool running = true;

// Signal handler for graceful exit
static void sigint_handler(int sig)
{
    (void)sig;
    running = false;
    printf("\nScript interrupted by user. Exiting gracefully...\n");
}

// Get total size of all .pcapng files in current directory
static long get_pcapng_total_size(void)
{
    DIR* dir = opendir(".");
    if (!dir) {
        perror("opendir");
        return 0;
    }

    long total = 0;
    struct dirent* entry;
    struct stat st;

    while ((entry = readdir(dir)) != NULL) {
        size_t len = strlen(entry->d_name);
        if (len > 7 && strcmp(entry->d_name + len - 7, ".pcapng") == 0) {
            if (stat(entry->d_name, &st) == 0) {
                total += st.st_size;
            }
        }
    }

    closedir(dir);
    return total;
}

// Create temporary file and return its name in provided buffer
static bool create_temp_file(char* buffer, size_t size)
{
    snprintf(buffer, size, "/tmp/hcx_monitor_XXXXXX.txt");
    int fd = mkstemps(buffer, 4); // 4 = length of ".txt"
    if (fd == -1) {
        perror("mkstemps");
        return false;
    }
    close(fd);
    return true;
}

// Safe file removal
static void saferm(const char* file_path)
{
    if (unlink(file_path) != 0) {
        if (errno == ENOENT) {
            printf("File not found: %s\n", file_path);
        }
        else if (errno == EACCES) {
            printf("Permission denied: %s\n", file_path);
        }
        else {
            printf("Error removing file %s: %s\n", file_path, strerror(errno));
        }
    }
}

// Process a single hash line
static int process_line(const char* line, struct HashTable* seen_bssids, int* counter, struct HashTable* hashcat, struct VendorTable* vendors)
{
    if (!line || line[0] == '\n' || line[0] == 0) { return 0; }

    // Make a copy of line to tokenize
    char line_copy[MAX_LINE];
    strncpy(line_copy, line, sizeof(line_copy) - 1);
    line_copy[sizeof(line_copy) - 1] = 0;

    // Split by '*'
    char* parts[10];
    int np = 0;
    char* p = line_copy;

    while (*p && np < 10) {
        parts[np++] = p;
        p = strchr(p, '*');
        if (!p) break;
        *p++ = 0;
    }

    if (np < 6) {
        printf("Invalid format\n");
        return 0;
    }

    // Extract fields
    const char* htype = parts[1];
    const char* hashid = parts[2];
    char* type_str = "UNKNOWN";

    if (strcmp(htype, "01") == 0) {
        type_str = "PMKID";
    }
    else if (strcmp(htype, "02") == 0) {
        type_str = "EAPOL";
    }

    char bssid[18];
    char mac[18];
    char essid[256];
    char passwd[256] = "";
    char vendor_ap[256] = "";
    char vendor_client[256] = "";

    // Convert BSSID to uppercase
    strncpy(bssid, parts[3], sizeof(bssid) - 1);
    bssid[sizeof(bssid) - 1] = 0;
    for (char* c = bssid; *c; c++) { *c = (char)toupper(*c); }

    // Convert MAC to uppercase
    strncpy(mac, parts[4], sizeof(mac) - 1);
    mac[sizeof(mac) - 1] = 0;
    for (char* c = mac; *c; c++) { *c = (char)toupper(*c); }

    // Convert hex ESSID to string
    hex2str(parts[5], essid, sizeof(essid), false);

    // Get password from hashcat if available
    if (hashcat) {
        const char* pw = ht_get(hashcat, hashid);
        if (pw) {
            strncpy(passwd, pw, sizeof(passwd) - 1);
            passwd[sizeof(passwd) - 1] = 0;
        }
    }

    // Get vendor information if available
    if (vendors) {
        mac2ven(bssid, vendor_ap, sizeof(vendor_ap), vendors);
        mac2ven(mac, vendor_client, sizeof(vendor_client), vendors);
    }

    // Check if BSSID is new using hash table
    if (!ht_get(seen_bssids, bssid)) {
        // Add to hash table (value doesn't matter, just use "1")
        ht_insert(seen_bssids, bssid, "1");
        (*counter)++;
        int num = *counter;

        // clang-format off
        printf(COLOR_YELLOW  "%d." COLOR_RESET "  "
               COLOR_GREEN   "%s"  COLOR_RESET "  "
               COLOR_GREEN   "%s"  COLOR_RESET "  "
               COLOR_MAGENTA "%s"  COLOR_RESET "  "
               COLOR_BLUE    "%s"  COLOR_RESET "  "
               COLOR_RESET   "%s"  COLOR_RESET "  "
               COLOR_RED     "%s"  COLOR_RESET "  "
               COLOR_MAGENTA "%s"  COLOR_RESET "  "
               COLOR_BLUE    "%s"  COLOR_RESET "\n",
               num, type_str, hashid, bssid, mac, essid, passwd, vendor_ap, vendor_client);
        // clang-format on
    }

    return 1;
}

int main(int argc, char* argv[])
{
    // Parse command line arguments
    bool enable_vendors = false;
    bool enable_hashcat = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--vendor") == 0) {
            enable_vendors = true;
        }
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--password") == 0) {
            enable_hashcat = true;
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {

            fprintf(stderr,
                    "ABOUT: Watches .pcapng files in cwd and if they update print unique AP hashes\n"
                    "USAGE: %s [-v] [-p]\n"
                    "  -v, --vendor    Show vendor information\n"
                    "  -p, --password  Show cracked passwords from hashcat\n"
                    "\n"
                    "\n"
                    "* requires: hcxpcapngtool\n",
                    argv[0]);
            return 0;
        }
    }

    // Set up signal handler for Ctrl+C
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    // Load vendor database if requested
    struct VendorTable* vendors = NULL;
    if (enable_vendors) { vendors = load_vendors_bin_dir(); }

    // Initialize tracking variables
    struct HashTable* seen_bssids = ht_create(HT_SIZE);
    struct HashTable* hashcat = NULL;
    int counter = 0;
    long last_size = 0;

    printf("Monitoring .pcapng files in current directory...\n");
    printf("Printing only unique BSSIDs\n");
    if (enable_hashcat) { printf("Showing cracked passwords from hashcat\n"); }
    if (enable_vendors) { printf("Showing vendor information\n"); }
    printf("Press Ctrl+C to exit.\n\n");

    while (running) {
        // Check if total size of all pcapng files changed
        long current_size = get_pcapng_total_size();

        if (current_size != last_size) {
            last_size = current_size;

            // Create temporary file
            char temp_file[256];
            if (!create_temp_file(temp_file, sizeof(temp_file))) {
                sleep(1);
                continue;
            }

            // Run hcxpcapngtool
            char cmd[4096];
            snprintf(cmd, sizeof(cmd), "hcxpcapngtool *.pcapng -o %s 2>&1", temp_file);

            FILE* pipe = popen(cmd, "r");
            if (pipe) {
                // Just consume and discard the output
                char buf[256];
                while (fgets(buf, sizeof(buf), pipe) != NULL) {
                    // Discard output
                }
                pclose(pipe);
            }

            // Load hashcat results if requested
            if (enable_hashcat) {
                if (hashcat) {
                    ht_free(hashcat);
                }
                hashcat = load_hashcat(temp_file);
            }

            // Process output file
            FILE* f = fopen(temp_file, "r");
            if (f) {
                char line[MAX_LINE];
                while (fgets(line, sizeof(line), f)) {
                    // Remove newline
                    char* nl = strchr(line, '\n');
                    if (nl) *nl = 0;

                    if (line[0] != 0) {
                        process_line(line, seen_bssids, &counter, hashcat, vendors);
                    }
                }
                fclose(f);
            }
            else {
                printf("Hash file not found: %s\n", temp_file);
            }

            // Remove temporary file
            saferm(temp_file);
        }

        sleep(1);
    }

    // Cleanup
    ht_free(seen_bssids);
    if (hashcat) {
        ht_free(hashcat);
    }
    if (vendors) {
        ht_free((struct HashTable*)vendors);
    }

    return 0;
}
