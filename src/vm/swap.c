#include <bitmap.h>

#include "devices/block.h"

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

#include "vm/swap.h"

/* How many disk sectors are needed to store one page of memory */
#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

static struct block *swap_block; /* Pointer to the block device used for swap space */
static struct bitmap *swap_bitmap; /* Bitmap for keeping track of swap spaces */
static struct lock swap_lock; /* Lock for critical swap operations */

/* Initialize the swap table. */
void swap_init (void) {
  swap_block = block_get_role(BLOCK_SWAP);
  if (swap_block == NULL)
    PANIC("No swap block available!");

  /* Calculate number of swap slots (each slot is one page). */
  size_t swap_slots = block_size(swap_block) / SECTORS_PER_PAGE;
  swap_bitmap = bitmap_create(swap_slots);
  if (swap_bitmap == NULL)
    PANIC("Failed to create swap bitmap!");

  bitmap_set_all(swap_bitmap, false);
  lock_init(&swap_lock);
}

/* Write a page to swap. Returns the allocated swap slot number, or (size_t)-1 on failure. */
size_t swap_out (void *kpage) {
  lock_acquire(&swap_lock);
  size_t slot = bitmap_scan(swap_bitmap, 0, 1, false);
  if (slot == BITMAP_ERROR) {
    lock_release(&swap_lock);
    return (size_t)-1;  /* No free swap slot */
  }

  bitmap_set(swap_bitmap, slot, true);
  lock_release(&swap_lock);

  /* Write the page to the swap block. */
  for (size_t i = 0; i < SECTORS_PER_PAGE; i++) {
    block_write(swap_block, slot * SECTORS_PER_PAGE + i,
                (uint8_t *)kpage + i * BLOCK_SECTOR_SIZE);
  }
  return slot;
}

/* Read a page from swap into kpage. Returns true on success, false on failure. */
bool swap_in (size_t slot, void *kpage) {
  lock_acquire(&swap_lock);
  if (!bitmap_test(swap_bitmap, slot)) {
    lock_release(&swap_lock);
    return false; /* Slot not in use */
  }
  bitmap_set(swap_bitmap, slot, false);
  lock_release(&swap_lock);

  for (size_t i = 0; i < SECTORS_PER_PAGE; i++) {
    block_read(swap_block, slot * SECTORS_PER_PAGE + i,
               (uint8_t *)kpage + i * BLOCK_SECTOR_SIZE);
  }
  return true;
}

/* Free a swap slot. */
void swap_free_slot (size_t slot) {
  lock_acquire(&swap_lock);
  bitmap_set(swap_bitmap, slot, false);
  lock_release(&swap_lock);
}