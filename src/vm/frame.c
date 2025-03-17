#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

#include "threads/malloc.h"
#include "userprog/pagedir.h"


static struct list frame_table;  // Global frame table, keep track of used frames

void frame_table_init(void) {
    list_init(&frame_table);
    lock_init(&frame_lock);
}

/* Allocates a new frame, returning its kernel virtual address. If a frame
   is available, will just return that frame, otherwise frees a frame by 
   putting one into swap. */
void *frame_alloc(enum palloc_flags flags, struct spt_entry *spte) { 
    
    lock_acquire(&frame_lock);

    void *kpage = palloc_get_page(PAL_USER | flags);
    if (kpage == NULL) {
        //printf("While allocating new frame, need to swap out to alloc page at %p\n", spte->upage);
        struct frame_entry *swapped = frame_evict();
        if (!swapped) {
            PANIC("No available frames and swap is full!");
        }
        kpage = swapped->kpage;
        swapped->spte = spte;
        swapped->owner = thread_current();
        list_push_back(&frame_table, &swapped->elem);
    } else {
        struct frame_entry *fte = malloc(sizeof(struct frame_entry));
        if (fte == NULL) {
            palloc_free_page(kpage);
            PANIC("Malloc failed in frame_alloc!");
        }
        fte->kpage = kpage;
        fte->spte = spte;
        fte->owner = thread_current();
        list_push_back(&frame_table, &fte->elem);
    }

    lock_release(&frame_lock);
    return kpage;
}

void frame_free(void *kpage, bool free_page) {
    lock_acquire(&frame_lock);

    struct list_elem *e;
    for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
        struct frame_entry *fte = list_entry(e, struct frame_entry, elem);
        if (fte->kpage == kpage) {
            list_remove(e);
            if (free_page)
            {
                palloc_free_page(kpage);
            }
            free(fte);
            break;
        }
    }

    lock_release(&frame_lock);
}

/* Evicts a frame and returns it's old frame entry. You can use the returned 
   frame entry freely since the frame will be saved in swap. */
struct frame_entry *frame_evict(void) {

    struct frame_entry *swapped = NULL;
    struct list_elem *e;

    if (list_empty(&frame_table)) {
      return NULL;
    }

    /* Clock algorithm */
    for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
        struct frame_entry *fte = list_entry(e, struct frame_entry, elem);
        if (!pagedir_is_accessed(fte->owner->pagedir, fte->spte->upage)) {
            swapped = fte;
            break;
        }
        pagedir_set_accessed(fte->owner->pagedir, fte->spte->upage, false);
    }
    /* If none are good candidates, just choose the first entry */
    if (swapped == NULL) {
        swapped = list_entry(list_begin(&frame_table), struct frame_entry, elem);
    }
    //printf("chose %p for eviction, kpage = %p\n", swapped->spte->upage, swapped->kpage);
    //printf("***pagedir: %u, \n", swapped->owner->pagedir);

    /* We only need to write page to swap if its been changed, aka dirty */
    if ((swapped->spte->writable && pagedir_is_dirty(swapped->owner->pagedir, swapped->spte->upage)) ||
      swapped->spte->location == SPT_SWAP) {
      //printf("evicting %p\n", swapped->spte->upage);
      if (swapped->spte->location == SPT_MMAP){
        
        file_seek(swapped->spte->file, swapped->spte->offset);
        // Write only the meaningful bytes (spte->read_bytes).
        file_write_at(swapped->spte->file, swapped->kpage, swapped->spte->read_bytes, 0);
      }
      else {
        swapped->spte->location = SPT_SWAP;
        swapped->spte->in_swap = true;
        swapped->spte->swap_index = swap_out(swapped->kpage);
        if (swapped->spte->swap_index == (size_t)-1) {
          return NULL;
        }
      }
    }

    pagedir_clear_page(swapped->owner->pagedir, swapped->spte->upage);
    list_remove(&swapped->elem);

    return swapped;
}