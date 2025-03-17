#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct lock filesys_lock; /* Lock for performing filesys operations */

void syscall_init (void);

#endif /* userprog/syscall.h */
