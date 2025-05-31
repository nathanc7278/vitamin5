#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"
#include "userprog/process.h"

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
        thread_current()->exit_code = args[1];
        printf("%s: exit(%d)\n", thread_current()->name, args[1]);
        thread_exit();
    }

    if (args[0] == SYS_EXEC) {
        lock_acquire(&syscall_lock);
        tid_t child = process_execute((const char *) args[1]);
        if (child == TID_ERROR) {
            f->eax = -1;
        } else {
            f->eax = child;
            struct list_elem* elem;
            struct thread* t;
            struct list* all_list = get_all_list();
            for (elem = list_begin(all_list); elem != list_end(all_list); elem = list_next(elem)) {
                t = list_entry(elem, struct thread, allelem);
                if (t->tid == child) {
                    t->parent_tid = thread_current()->tid;
                    break;
                }
            }
        }
        lock_release(&syscall_lock);
    }

    if (args[0] == SYS_WAIT) {
        
        struct list_elem* elem;
        struct thread* t;
        bool is_found = false;
        struct list* all_list = get_all_list();
        for (elem = list_begin(all_list); elem != list_end(all_list); elem = list_next(elem)) {
            t = list_entry(elem, struct thread, allelem);
            if (t->tid == (tid_t) args[1]) {
                is_found = true;
                break;
            }
        }
        if (!is_found) {
            f->eax = -1;
        } else {
            lock_acquire(&t->thread_lock);
            while (t->is_running) {
                cond_wait(&t->thread_finished, &t->thread_lock);
            }
            f->eax = t->exit_code;
            lock_release(&t->thread_lock);
        }
    }

    if (args[0] == SYS_INCREMENT) {
        f->eax = args[1] + 1;
    }

    if (args[0] == SYS_WRITE) {
        putbuf((char *) args[2], args[3]);
        f->eax = args[3];
    }

    if (args[0] == SYS_CREATE) {
        if ((const char *) args[1] == NULL || !is_user_vaddr((const char *) args[1])) {
            f->eax = -1;
        } else {
            f->eax = filesys_create((const char *) args[1], args[2]);
        }
    }

    if (args[0] == SYS_REMOVE) {
        f->eax = filesys_remove((const char *)args[1]);
    }

    if (args[0] == SYS_OPEN) {
        lock_acquire(&syscall_lock);
        struct file* new_file = filesys_open((const char *) args[1]);
        if (new_file == NULL) {
            f->eax = -1;
        } else {
            int fd_index = 2;
            while (thread_current()->fd_table[fd_index] != NULL && fd_index < 128) {
                fd_index++;
            }
            if (fd_index > 127) {
                f->eax = -1;
            }
            else {
                thread_current()->fd_table[fd_index] = new_file;
                f->eax = fd_index;
            }
        }
        lock_release(&syscall_lock);
    }

    if (args[0] == SYS_FILESIZE) {
        struct file* file_opened = thread_current()->fd_table[args[1]];
        if (file_opened == NULL) {
            f->eax = -1;
        } else {
            f->eax = file_length(file_opened);
        }
    }

    if (args[0] == SYS_READ) {
        lock_acquire(&syscall_lock);
        struct file* file_opened = thread_current()->fd_table[args[1]];
        if (file_opened == NULL || args[1] == 1) {
            lock_release(&syscall_lock);
            f->eax = -1;
        }
        else if (args[1] == 0) {
            uint8_t* buffer = (uint8_t*) args[2];
            for (int i = 0; i < (int) args[3]; i++) {
                uint8_t key = input_getc();
                buffer[i] = key;
            }
            f->eax = args[3];
        } else {
            f->eax = file_read(file_opened, (void *) args[2], args[3]);
        }
        lock_release(&syscall_lock);
    }

    if (args[0] == SYS_WRITE) {
        lock_acquire(&syscall_lock);
        struct file* file_opened = thread_current()->fd_table[args[1]];
        if (file_opened == NULL || args[1] == 0) {
            f->eax = -1;
        }
        else if (args[1] == 1) {
            char* buffer = (char *) args[2];
            putbuf(buffer, args[3]);
            f->eax = args[3];
        } else {
            f->eax = file_write(file_opened, (void *) args[2], args[3]);
        }
        lock_release(&syscall_lock);
    }

    if (args[0] == SYS_SEEK) {
        struct file* file_opened = thread_current()->fd_table[args[1]];
        if (file_opened == NULL) {
            f->eax = -1;
        } else {
            file_seek(file_opened, args[2]);
            f->eax = 0;
        }
    }

    if (args[0] == SYS_TELL) {
        struct file* file_opened = thread_current()->fd_table[args[1]];
        if (file_opened == NULL) {
            f->eax = -1;
        } else {
            f->eax = file_tell(file_opened);
        }
    }

    if (args[0] == SYS_CLOSE) {
        lock_acquire(&syscall_lock);
        struct file* file_opened = thread_current()->fd_table[args[1]];
        if (file_opened == NULL) {
            f->eax = -1;
        } else {
            file_close(file_opened);
            thread_current()->fd_table[args[1]] = NULL;
        }
        lock_release(&syscall_lock);
    }
}
