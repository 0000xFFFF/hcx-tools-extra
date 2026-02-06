#define _XOPEN_SOURCE 700 // needed for wcwidth
#include "utils.h"
#include <ctype.h>
#include <libgen.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

// Fast hash function (FNV-1a)
static inline uint32_t hash_fnv1a(const char* key)
{
    uint32_t hash = 2166136261u;
    while (*key) {
        hash ^= (uint8_t)*key++;
        hash *= 16777619u;
    }
    return hash;
}

// Create hash table
struct HashTable* ht_create(size_t size)
{
    struct HashTable* ht = malloc(sizeof(struct HashTable));
    ht->size = size;
    ht->count = 0;
    ht->buckets = calloc(size, sizeof(struct HTNode*));
    return ht;
}

// Insert into hash table
void ht_insert(struct HashTable* ht, const char* key, const char* value)
{
    uint32_t idx = (uint32_t)(hash_fnv1a(key) % ht->size);
    struct HTNode* node = malloc(sizeof(struct HTNode));
    node->key = strdup(key);
    node->value = strdup(value);
    node->next = ht->buckets[idx];
    ht->buckets[idx] = node;
    ht->count++;
}

// Get from hash table
const char* ht_get(struct HashTable* ht, const char* key)
{
    uint32_t idx = (uint32_t)(hash_fnv1a(key) % ht->size);
    struct HTNode* node = ht->buckets[idx];
    while (node) {
        if (strcmp(node->key, key) == 0) return node->value;
        node = node->next;
    }
    return NULL;
}

// Free hash table
void ht_free(struct HashTable* ht)
{
    for (size_t i = 0; i < ht->size; i++) {
        struct HTNode* node = ht->buckets[i];
        while (node) {
            struct HTNode* tmp = node;
            node = node->next;
            free(tmp->key);
            free(tmp->value);
            free(tmp);
        }
    }
    free(ht->buckets);
    free(ht);
}

// Convert hex to string
void hex2str(const char* hex, char* out, size_t outsz, bool nocolor)
{
    size_t len = strlen(hex) / 2;
    if (len >= outsz)
        len = outsz - 1;

    for (size_t i = 0; i < len; ++i) {
        unsigned int b;
        sscanf(hex + 2 * i, "%2x", &b);
        out[i] = (char)b;
    }

    out[len] = '\0';
}

// Load vendor database
struct VendorTable* load_vendors(const char* ieee_oui)
{
    struct VendorTable* vt = malloc(sizeof(struct VendorTable));
    vt->size = HT_SIZE;
    vt->buckets = calloc(HT_SIZE, sizeof(struct HTNode*));

    FILE* f = fopen(ieee_oui, "r");
    if (!f) return vt;

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        char* tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = 0;
        char* vendor = tab + 1;
        char* nl = strchr(vendor, '\n');
        if (nl) *nl = 0;

        uint32_t idx = (uint32_t)(hash_fnv1a(line) % vt->size);
        struct HTNode* node = malloc(sizeof(struct HTNode));
        node->key = strdup(line);
        node->value = strdup(vendor);
        node->next = vt->buckets[idx];
        vt->buckets[idx] = node;
    }
    fclose(f);
    return vt;
}

// Load vendor database from binary's directory path, look for "mac2ven.lst"
struct VendorTable* load_vendors_bin_dir()
{
    char bin_dir[PATH_MAX - 32];
    binary_directory(bin_dir, sizeof(bin_dir));
    char mac2ven_list_path[PATH_MAX];
    snprintf(mac2ven_list_path, sizeof(mac2ven_list_path), "%s/mac2ven.lst", bin_dir);
    return load_vendors(mac2ven_list_path);
}

// MAC to vendor lookup
void mac2ven(const char* mac, char* out, size_t out_size, struct VendorTable* vt)
{
    if (!vt) {
        out[0] = 0;
        return;
    }

    char prefix[7];
    int j = 0;
    for (int i = 0; mac[i] && j < 6; i++) {
        if (mac[i] != ':' && mac[i] != '-') {
            prefix[j++] = (char)toupper(mac[i]);
        }
    }
    prefix[j] = 0;

    uint32_t idx = (uint32_t)(hash_fnv1a(prefix) % vt->size);
    struct HTNode* node = vt->buckets[idx];
    while (node) {
        if (strcmp(node->key, prefix) == 0) {
            strncpy(out, node->value, out_size - 1);
            out[out_size - 1] = 0;
            return;
        }
        node = node->next;
    }
    out[0] = 0;
}

// Load hashcat results
struct HashTable* load_hashcat(const char* filename)
{
    struct HashTable* ht = ht_create(HT_SIZE);

    char cmd[PATH_MAX + 64];
    snprintf(cmd, sizeof(cmd), "hashcat -m 22000 --show %s 2>/dev/null", filename);

    FILE* fp = popen(cmd, "r");
    if (!fp) return ht;

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp)) {
        char* saveptr;
        char* parts[5];
        int i = 0;
        char* token = strtok_r(line, ":", &saveptr);
        while (token && i < 5) {
            parts[i++] = token;
            token = strtok_r(NULL, ":", &saveptr);
        }
        if (i >= 5) {
            char* nl = strchr(parts[4], '\n');
            if (nl) *nl = 0;
            ht_insert(ht, parts[0], parts[4]);
        }
    }
    pclose(fp);

    return ht;
}

// Case-insensitive substring search
const char* istrstr(const char* haystack, const char* needle)
{
    if (!*needle) return (const char*)haystack;

    for (; *haystack; haystack++) {
        const char* h = haystack;
        const char* n = needle;

        while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            h++;
            n++;
        }

        if (!*n)
            return (const char*)haystack;
    }
    return NULL;
}

// Calculate display width for a string (visible characters only, ignoring ANSI codes)
size_t utf8_display_width(const char* s)
{
    mbstate_t ps = {0};
    wchar_t wc;
    size_t width = 0;

    const char* p = s;

    while (*p) {
        // skip ANSI escape sequences (e.g., "\033[31m")
        if (*p == '\033') {
            if (*(p + 1) == '[') {
                p += 2;
                while (*p && (*p < '@' || *p > '~')) // skip until letter ending sequence
                    p++;
                if (*p) p++; // skip final letter
                continue;
            }
        }

        // convert next multibyte character
        size_t n = mbrtowc(&wc, p, MB_CUR_MAX, &ps);
        if (n == (size_t)-1 || n == (size_t)-2) {
            // invalid UTF-8, skip a byte
            p++;
            continue;
        }
        else if (n == 0) {
            break;
        }

        int w = wcwidth(wc);
        if (w > 0) width += (size_t)w;
        p += n;
    }

    return width;
}

char* binary_directory(char* path, size_t size)
{
    ssize_t len = readlink("/proc/self/exe", path, size - 1);

    if (len == -1) {
        perror("readlink failed");
        return NULL;
    }

    path[len] = '\0';     // Null-terminate the string
    return dirname(path); // Extract directory part
}
