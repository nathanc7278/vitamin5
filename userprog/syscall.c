#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"

static void syscall_handler(struct intr_frame *);

static struct lock syscall_lock;

void syscall_init(void) {
    lock_init(&syscall_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f UNUSED) {
    uint32_t *args = ((uint32_t *) f->esp);

    /*
     * The following print statement, if uncommented, will print out the syscall
     * number whenever a process enters a system call. You might find it useful
     * when debugging. It will cause tests to fail, however, so you should not
     * include it in your final submission.
     */

    // printf("System call number: %d\n", args[0]);

    if (args[0] == SYS_EXIT) {
        f->eax = args[1];
        printf("%s: exit(%d)\n", thread_current()->name, args[1]);
        thread_exit();
    }

    if (args[0] == SYS_INCREMENT) {
        f->eax = args[1] + 1;
    }

    if (args[0] == SYS_WRITE) {
        putbuf((char *) args[2], args[3]);
        f->eax = args[3];
    }

    if (args[0] == SYS_CREATE) {
        f->eax = filesys_create((const char *) args[1], args[2]);
    }

    if (args[0] == SYS_REMOVE) {
        f->eax = filesys_remove((const char *)args[1]);
    }

    if (args[0] == SYS_OPEN) {
        lock_acquire(&syscall_lock);
        struct file* new_file = filesys_open((const char *) args[1]);
        if (new_file == NULL) {
            lock_release(&syscall_lock);
            f->eax = -1;
        }
        int fd_index = 2;
        while (thread_current()->fd_table[fd_index] != NULL && fd_index < 128) {
            fd_index++;
        }
        if (fd_index > 127) {
            lock_release(&syscall_lock);
            f->eax = -1;
        }
        thread_current()->fd_table[fd_index] = new_file;
        lock_release(&syscall_lock);
        f->eax = fd_index;
    }

    if (args[0] == SYS_FILESIZE) {
        struct file* file_opened = thread_current()->fd_table[args[1]];
        if (file_opened == NULL) {
            f->eax = -1;
        }
        f->eax = file_length(file_opened);
    }

    if (args[0] == SYS_READ) {
        lock_acquire(&syscall_lock);
        struct file* file_opened = thread_current()->fd_table[args[1]];
        if (file_opened == NULL || args[1] == 1) {
            lock_release(&syscall_lock);
            f->eax = -1;
        }
        if (args[1] == 0) {
            uint8_t* buffer = (uint8_t*) args[2];
            for (int i = 0; i < (int) args[3]; i++) {
                uint8_t key = input_getc();
                buffer[i] = key;
            }
            lock_release(&syscall_lock);
            f->eax = args[3];
        }
        lock_release(&syscall_lock);
        f->eax = file_read(file_opened, (void *) args[2], args[3]);
    }

    if (args[0] == SYS_WRITE) {
        lock_acquire(&syscall_lock);
        struct file* file_opened = thread_current()->fd_table[args[1]];
        if (file_opened == NULL || args[1] == 0) {
            lock_release(&syscall_lock);
            f->eax = -1;
        }
        if (args[1] == 1) {
            char* buffer = (char *) args[2];
            putbuf(buffer, args[3]);
            lock_release(&syscall_lock);
            f->eax = args[3];
        }
        lock_release(&syscall_lock);
        f->eax = file_write(file_opened, (void *) args[2], args[3]);
    }

    if (args[0] == SYS_SEEK) {
        struct file* file_opened = thread_current()->fd_table[args[1]];
        if (file_opened == NULL) {
            f->eax = -1;
        }
        file_seek(file_opened, args[2]);
        f->eax = 0;
    }

    if (args[0] == SYS_TELL) {
        struct file* file_opened = thread_current()->fd_table[args[1]];
        if (file_opened == NULL) {
            f->eax = -1;
        }
        f->eax = file_tell(file_opened);
    }

    if (args[0] == SYS_CLOSE) {
        lock_acquire(&syscall_lock);
        struct file* file_opened = thread_current()->fd_table[args[1]];
        if (file_opened == NULL) {
            lock_release(&syscall_lock);
            f->eax = -1;
        }
        file_close(file_opened);
        thread_current()->fd_table[args[1]] = NULL;
        lock_release(&syscall_lock);
    }
}
