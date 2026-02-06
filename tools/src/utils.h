#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_LINE       2048
#define MAX_ESSID      256
#define MAX_VENDOR     128
#define HT_SIZE        65536
#define HT_LOAD_FACTOR 0.75

// ANSI color codes
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"

// Hash table node
struct HTNode {
    char* key;
    char* value;
    struct HTNode* next;
};

// Hash table for hashcat passwords
struct HashTable {
    struct HTNode** buckets;
    size_t size;
    size_t count;
};

// Hash table for MAC vendor lookup
struct VendorTable {
    struct HTNode** buckets;
    size_t size;
};

// Hash item structure
struct HashItem {
    int num;
    char type[8];
    char hashid[64];
    char bssid[18];
    char mac[18];
    char essid[MAX_ESSID];
    char passwd[128];
    char vendor_ap[MAX_VENDOR];
    char vendor_client[MAX_VENDOR];
};

// Command line arguments
struct Args {
    int sort_col;
    bool vendor;
    bool nohashcat;
    bool nocolor;
    char* search;
    char* filename;
};


extern struct HashTable* ht_create(size_t size);
extern void ht_insert(struct HashTable* ht, const char* key, const char* value);
extern const char* ht_get(struct HashTable* ht, const char* key);
extern void ht_free(struct HashTable* ht);
extern void hex2str(const char* hex, char* out, size_t out_size, bool nocolor);
extern struct VendorTable* load_vendors(const char* prog_path);
extern struct VendorTable* load_vendors_bin_dir();
extern void mac2ven(const char* mac, char* out, size_t out_size, struct VendorTable* vt);
extern struct HashTable* load_hashcat(const char* filename);
extern const char* istrstr(const char* haystack, const char* needle);
extern int compare_items(const void* a, const void* b);
extern size_t utf8_display_width(const char* s);
extern char* binary_directory(char* path, size_t size);
extern void print_pad(int n);
extern void print_cell(const char* s, int width);
