void swap_init (void);

size_t swap_out (void *kpage);

bool swap_in (size_t slot, void *kpage);

void swap_free_slot (size_t slot);