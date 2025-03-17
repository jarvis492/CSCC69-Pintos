#include "vm/page.h"
#include "threads/malloc.h"
#include "lib/kernel/hash.h"

/* Allocates a new spt_entry. Returns the new spt_entry or null on failure */
struct spt_entry *spt_alloc(void *upage, enum page_location loc) {
  struct spt_entry *spte = malloc(sizeof(struct spt_entry));
  if (!spte) return NULL;

  spte->upage = upage;
  spte->location = loc;
  spte->writable = true;
  spte->in_swap = false;
  spte->mmapped = false;

  /* Insert the entry into the process's supplemental page table. */
  if (!spt_insert(thread_current()->spt, spte)) {
    free(spte);
    return NULL;
  }
  return spte;
}

/* Hash function that uses the user page address as the key. */
unsigned
spt_hash (const struct hash_elem *e, void *aux UNUSED) {
  struct spt_entry *spte = hash_entry(e, struct spt_entry, hash_elem);
  return hash_bytes(&spte->upage, sizeof spte->upage);
}

/* Comparator function, orders entries by upage. */
bool
spt_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  struct spt_entry *spte_a = hash_entry(a, struct spt_entry, hash_elem);
  struct spt_entry *spte_b = hash_entry(b, struct spt_entry, hash_elem);
  return spte_a->upage < spte_b->upage;
}

/* Initialize a supplemental page table. */
void
spt_init (struct hash *spt) {
  hash_init(spt, spt_hash, spt_less, NULL);
}

/* Insert an entry into the SPT. Returns true on success. */
bool
spt_insert (struct hash *spt, struct spt_entry *spte) {
  struct hash_elem *prev = hash_insert(spt, &spte->hash_elem);
  return (prev == NULL);
}

/* Look up an entry in the SPT by user page address. Returns null on failure. */
struct spt_entry *
spt_lookup (struct hash *spt, void *upage) {
  struct spt_entry tmp;
  tmp.upage = upage;
  struct hash_elem *e = hash_find(spt, &tmp.hash_elem);
  return e != NULL ? hash_entry(e, struct spt_entry, hash_elem) : NULL;
}

/* Remove an entry from the SPT and free its memory. */
void
spt_remove (struct hash *spt, void *upage) {
  struct spt_entry *spte = spt_lookup(spt, upage);
  if (spte != NULL) {
    hash_delete(spt, &spte->hash_elem);
    free(spte);
  }
}

/* Destroy the SPT, freeing all entries. */
void
spt_destroy (struct hash *spt) {
  hash_destroy(spt, NULL);
}

