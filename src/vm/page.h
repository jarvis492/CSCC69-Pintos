#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include <hash.h>
#include "filesys/off_t.h"
#include "threads/thread.h"

// The different locations/types of data the spt_entrys are keeping track of
enum page_location { SPT_MEMORY, SPT_SWAP, SPT_FILE, SPT_STACK, SPT_MMAP };

// Entry to keep track of supplemental info about user addresses
struct spt_entry {
    void *upage;               // User virtual address (page-aligned)
    enum page_location location;  // Where the data is coming from

    bool mmapped;              // If the page is memory mapped
    struct file *file;         // File that backs this page, if any
    off_t offset;              // Offset in the file where the page's data begins
    size_t read_bytes;         // Number of bytes to read from the file
    size_t zero_bytes;         // Number of bytes to zero after reading data
    bool writable;             // Whether the page is writable

    size_t swap_index;         // Index in swap if the page is swapped out
    bool in_swap;              // If the page is swapped out

    struct hash_elem hash_elem; // Element for the hash table
};

void spt_init(struct hash *spt);
bool spt_insert(struct hash *spt, struct spt_entry *spte);
struct spt_entry *spt_lookup(struct hash *spt, void *upage);
void spt_remove(struct hash *spt, void *upage);
void spt_destroy(struct hash *spt);
struct spt_entry *spt_alloc(void *upage, enum page_location loc);

#endif /* VM_PAGE_H */