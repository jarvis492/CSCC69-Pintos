#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "userprog/exception.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

#include "filesys/file.h"


/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

#define STACK_LIMIT (8 * 1024 * 1024) /* 8MB, how far below PHYS_BASE stack can grow */
/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_current()->exit_status = -1;
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Helpers for page_fault */
static bool grow_stack(void *fault_addr);

static void exit_helper();

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */
  void *esp;         /* Stack pointer */
  void *kpage;       /* Pointer to frame in kernel memory */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  /* Getting stack pointer */ 
  if (!user) {
    /* Kernel mode means stack pointer saved in thread */
    esp = thread_current()->user_esp; 
  } 
  else {
    esp = f->esp;
  }

  /* Round down to page boundary */ 
  void *page_addr = pg_round_down(fault_addr);

  // printf("***checking fault for fault_addr %p, page %p, user: %i, write: %i, not_present: %i\n", 
  //        fault_addr, page_addr, user, write, not_present);
  //printf("***esp at %p\n", esp);

  struct spt_entry *spte = spt_lookup(thread_current()->spt, page_addr);

  /* Spte does not exist */
  if (spte == NULL) {

    /* Check if the fault was caused by valid stack access */ 
    if (fault_addr >= esp - 32 && fault_addr >= PHYS_BASE - STACK_LIMIT) {
      //printf("***growing stack\n");
      if (!grow_stack(page_addr)) {
        //printf("***failed to grow stack\n");
        exit_helper();
      }
      return;
    }
    //printf("***page does not exist %p\n", page_addr);
    exit_helper();
  }

  /* Tried to write to read-only page. */
  if (!spte->writable && write) {
    //printf("***Tried to write to read-only page\n");
    exit_helper();
  }

  /* Get a new frame for the page. */
  kpage = frame_alloc(PAL_USER, spte);
  if (kpage == NULL) {
    //printf("***Failed get a frame for the page\n");
    exit_helper();
  }

  /* Frame is stored in swap */
  if (spte->location == SPT_SWAP)
  {
    //printf("found addr in swap: %p\n", page_addr);
    swap_in(spte->swap_index, kpage);
    spte->in_swap = false;
  }
  else if (spte->location == SPT_FILE || spte->location == SPT_MMAP) {
    //printf("***loading file with offset %i, page %p\n", spte->offset, page_addr);
    lock_acquire(&filesys_lock);
    file_seek(spte->file, spte->offset);
    /* Load this page. */
    if (file_read(spte->file, kpage, spte->read_bytes) != (int) spte->read_bytes) {
      lock_release(&frame_lock);
      frame_free (kpage, true);
      exit_helper();
    }
    lock_release(&filesys_lock);
    memset (kpage + spte->read_bytes, 0, spte->zero_bytes);
  }
  else if (spte->location == SPT_MEMORY) {
    /* For a lazy-allocated page */
    //printf("zeroing %p\n", page_addr);
    memset(kpage, 0, PGSIZE);
  }

  /* Point the page table entry for the faulting virtual address to the physical page */
  if (!pagedir_set_page(thread_current()->pagedir, spte->upage, kpage, spte->writable)) {
    palloc_free_page(kpage);
    exit_helper();
  }
}

static bool grow_stack(void *page_addr) {

  if (!is_user_vaddr(page_addr)) {
    return false;  // Reject kernel addresses
}
  /* Allocate new supplemental page table entry */ 
  struct spt_entry *sptes = spt_alloc(page_addr, SPT_STACK);
  if (sptes == NULL) {
    return false;
  }

  /* Get a frame for the page. */
  void *kpage = frame_alloc(PAL_USER, sptes);
  if (kpage == NULL) {
    return false;
  }
  /* Point the page table entry for the faulting virtual address to the physical page */
  if (!pagedir_set_page(thread_current()->pagedir, sptes->upage, kpage, sptes->writable)) {
    palloc_free_page(kpage);
    return false;
  }
  return true;
}

/* exit thread with exit status -1*/
static void exit_helper() {
  thread_current()->exit_status = -1;
  thread_exit (); 
}
