#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#include "threads/thread.h"

struct lock frame_lock;   // Lock for critical frame operations

// Entry to keep track of a used physical fram
struct frame_entry {
    void *kpage;            // Kernel virtual address of the frame
    struct spt_entry *spte; // Pointer to corresponding supplemental page table entry
    struct thread *owner;   // Thread that owns the frame
    struct list_elem elem;  // List element for frame table
};

void frame_table_init(void);
void *frame_alloc(enum palloc_flags flags, struct spt_entry *spte); 
void frame_free(void *kpage, bool free_page);
struct frame_entry *frame_evict(void);

#endif /* VM_FRAME_H */