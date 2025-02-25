#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define CODE_SEGMENT_START 0x08048000

static void syscall_handler (struct intr_frame *);

static bool is_user_vptr(const void *ptr) 
{
  return ptr != NULL && is_user_vaddr(ptr) &&
         pagedir_get_page(thread_current()->pagedir, ptr) != NULL;

}

static bool is_user_vptr_size(const void *ptr, size_t size) {
  uint8_t *ptrc = (uint8_t *)ptr;
  int i = 0;
  while (i < size) {
    if (!is_user_vptr(ptrc)) { 
      return false;
    }
    ptrc++; 
    i++;
  }
  
  return true; 
}

static bool is_valid_string(const char *str) {
  while (is_user_vptr(str)) {
    if (*str == '\0') { 
        return true;
    }
    str++; 
  }
  
  return false; 
}

static void exit (int status)
{
  struct thread *cur = thread_current();
  cur->exit_status = status;
  thread_exit();
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
  UDST must be below PHYS_BASE.
  Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

static void 
copy_in(void *dst, const void *src, size_t size) 
{
  uint8_t *dstc = dst;
  const uint8_t *srcc = src;

  for (; size > 0; size--, dstc++, srcc++)
  {
    //printf("***%p is %d\n", srcc, is_user_vptr(srcc));
    if (!is_user_vptr(srcc)){
      exit(-1);
    }
    
    *dstc = get_user(srcc);
  }
  
}

static int exec (const char *cmd_line) 
{
  if (!is_valid_string(cmd_line))
    exit(-1);
  return process_execute(cmd_line);
}

static bool create (const char *file, unsigned initial_size)
{
  if (!is_valid_string(file))
    exit(-1);
  return filesys_create(file, (off_t)initial_size);
}

static bool remove (const char *file)
{
  if (!is_valid_string(file))
    exit(-1);
  return filesys_remove(file);
}

static int open (const char *file)
{
  if (!is_valid_string(file))
    exit(-1);
  
  struct file *f = filesys_open(file);
  if (f == NULL)
    return -1;

  int fd = allocate_fd(f);
  if (fd == -1)
  {
    file_close(f);
  }
    

  return fd;
}

static int filesize (int fd)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -1;
  return (int) file_length(file);
}

static int read (int fd, void *buffer, unsigned size)
{
  if (!is_user_vptr_size(buffer, size))
  {
    exit(-1);
  }
  /* Console. */
  if (fd == STDIN_FILENO) 
  {
    for (unsigned i = 0; i < size; i++)
    {
      ((char *)buffer)[i] = input_getc();
    }
    return size;
  }

  struct file *file = get_file(fd);
  if (file == NULL)
    return -1;

  return file_read(file, buffer, (off_t)size);
}

static int write (int fd, const void *buffer, unsigned size) 
{
  if (!is_user_vptr_size(buffer, size))
  {
    exit(-1);
  }
  /* Console. */
  if (fd == STDOUT_FILENO) 
  {
    putbuf(buffer, size);
    return size;
  }

  struct file *f = get_file(fd);
  if (f == NULL)
    return -1;

  return file_write(f, buffer, (off_t)size);
}

static void seek (int fd, unsigned position)
{
  struct file *file = get_file(fd);
  if (file != NULL)
  {
    file_seek(file, position);
  }
}

static unsigned tell(int fd) 
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -1;

  return file_tell(file);
}

static void close (int fd) 
{
  struct file *file = get_file(fd);
  if (file != NULL)
  {
    file_close(file);
    release_fd(fd);
  }
}
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  unsigned syscall_num;
  int args[3];

  if (!is_user_vptr_size(f->esp, sizeof syscall_num))
  {
    exit(-1);
  }

  //extracting syscall number
  copy_in(&syscall_num, f->esp, sizeof syscall_num);
  //printf ("***system call number: %u\n", syscall_num);

  if (syscall_num == SYS_HALT)
  {
    shutdown_power_off();
  }
  else if (syscall_num == SYS_EXIT)
  {
    copy_in(args, (uint32_t*) f->esp + 1, sizeof *args);
    exit(args[0]);
  }
  else if (syscall_num == SYS_EXEC)
  {
    copy_in(args, (uint32_t*) f->esp + 1, sizeof *args);
    f->eax = exec(args[0]);
  }
  else if (syscall_num == SYS_WAIT)
  {
    copy_in(args, (uint32_t*) f->esp + 1, sizeof *args);
    f->eax = process_wait(args[0]);
  }
  else if (syscall_num == SYS_CREATE)
  {
    copy_in(args, (uint32_t*) f->esp + 1, sizeof *args * 2);
    f->eax = create(args[0], args[1]);
  }
  else if (syscall_num == SYS_REMOVE)
  {
    copy_in(args, (uint32_t*) f->esp + 1, sizeof *args);
    f->eax = remove(args[0]);
  }
  else if (syscall_num == SYS_OPEN)
  {
    copy_in(args, (uint32_t*) f->esp + 1, sizeof *args);
    f->eax = open(args[0]);
  }
  else if (syscall_num == SYS_FILESIZE)
  {
    copy_in(args, (uint32_t*) f->esp + 1, sizeof *args);
    f->eax = filesize(args[0]);
  }
  else if (syscall_num == SYS_READ)
  {
    copy_in(args, (uint32_t*) f->esp + 1, sizeof *args * 3);
    f->eax = read(args[0], args[1], args[2]);
  }
  else if (syscall_num == SYS_WRITE)
  {
    copy_in(args, (uint32_t*) f->esp + 1, sizeof *args * 3);
    f->eax = write(args[0], args[1], args[2]);
  }
  else if (syscall_num == SYS_SEEK)
  {
    copy_in(args, (uint32_t*) f->esp + 1, sizeof *args * 2);
    seek(args[0], args[1]);
  }
  else if (syscall_num == SYS_TELL)
  {
    copy_in(args, (uint32_t*) f->esp + 1, sizeof *args);
    f->eax = tell(args[0]);
  }
  else if (syscall_num == SYS_CLOSE)
  {
    copy_in(args, (uint32_t*) f->esp + 1, sizeof *args);
    close(args[0]);
  }
  else
  {
    exit(-1);
  }
  
}
