#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

extern struct lock syscall_lock;

#endif /* userprog/syscall.h */
