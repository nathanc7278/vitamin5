#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame *);

static struct lock syscall_lock;

void syscall_init(void) {
    lock_init(&syscall_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool validate_user_buffer(void *pointer, size_t length, bool check_writable);

bool validate_user_buffer(void *pointer, size_t length, bool check_writable)
    {

        uint8_t *start_address = (uint8_t *) pointer;
        uint8_t *end_address = start_address + length;

        for (uint8_t *address = start_address; address < end_address; address++) {
            if (!is_user_vaddr(address) || is_kernel_vaddr(address)) {
                return false;
            }

            if (pagedir_get_page(thread_current()->pagedir, address) == NULL) 
            {
                return false;
            }

        }
        return true;
    }


bool validate_user_string(const char *string);

bool validate_user_string(const char *string)
{
    if (string == NULL) {
        return false;
    }
    
    for (const char *ptr = string; ; ptr++) {
        if (!is_user_vaddr(ptr) || is_kernel_vaddr(ptr)) {
            return false;
        }
        
        if (pagedir_get_page(thread_current()->pagedir, ptr) == NULL) {
            return false;
        }
        
        if (*ptr == '\0') {
            break;
        }
    }
    
    return true;
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

    if (!validate_user_buffer(args, sizeof(uint32_t), false)) {
        printf("%s: exit(-1)\n", thread_current()->name);
        thread_exit();
    }

    if (args[0] == SYS_EXEC) {
        if (!validate_user_buffer(args, 2 * sizeof(uint32_t), false)) {
            printf("%s: exit(-1)\n", thread_current()->name);
            thread_exit();
        }
        if (!validate_user_string((const char*)args[1])) {
            printf("%s: exit(-1)\n", thread_current()->name);
            thread_exit();
        }
        f->eax = process_execute((const char*)args[1]);
    }

    if (args[0] == SYS_WAIT) {
        if (!validate_user_buffer(args, 2 * sizeof(uint32_t), false)) {
            printf("%s: exit(-1)\n", thread_current()->name);
            thread_exit();
        }
        f->eax = process_wait(args[1]);
    }

    int syscall_num = args[0];
    
    int arg_count = 0;
    switch (syscall_num) {
        case SYS_HALT:
            arg_count = 0;
            break;
        case SYS_EXIT:
        case SYS_FILESIZE:
        case SYS_TELL:
        case SYS_CLOSE:
        case SYS_REMOVE:
        case SYS_OPEN:
            arg_count = 1;
            break;
        case SYS_CREATE:
        case SYS_SEEK:
            arg_count = 2;
            break;
        case SYS_READ:
        case SYS_WRITE:
            arg_count = 3;
            break;
        default:
            printf("%s: exit(-1)\n", thread_current()->name);
            thread_exit();
    }
    
    if (!validate_user_buffer(args, (arg_count + 1) * sizeof(uint32_t), false)) {
        printf("%s: exit(-1)\n", thread_current()->name);
        thread_exit();
    }

    if (args[0] == SYS_EXIT) {
        f->eax = args[1];
        thread_current()->exit_code = args[1];
        printf("%s: exit(%d)\n", thread_current()->name, args[1]);
        thread_exit();
    }

    if (args[0] == SYS_INCREMENT) {
        f->eax = args[1] + 1;
    }

    if (args[0] == SYS_CREATE) {
        if (!validate_user_string((const char *) args[1])) {
            printf("%s: exit(-1)\n", thread_current()->name);
            thread_exit();
        }
        f->eax = filesys_create((const char *) args[1], args[2]);
    }

    if (args[0] == SYS_REMOVE) {
        f->eax = filesys_remove((const char *)args[1]);
    }

    if (args[0] == SYS_OPEN) {
        if (!validate_user_string((const char *) args[1])) {
            printf("%s: exit(-1)\n", thread_current()->name);
            thread_exit();
        }
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
        if (!validate_user_buffer((void *) args[2], args[3], true)) {
            printf("%s: exit(-1)\n", thread_current()->name);
            thread_exit();
        }
        lock_acquire(&syscall_lock);
        if (args[1] > 127) {
            f->eax = -1;
        } else if (args[1] == 1) {
            f->eax = -1;
        } else {
            struct file* file_opened = thread_current()->fd_table[args[1]];
            if (file_opened == NULL) {
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
        }
        lock_release(&syscall_lock);
    }

    if (args[0] == SYS_WRITE) {
        if (!validate_user_buffer((void*)args[2], args[3], false)) {
            printf("%s: exit(-1)\n", thread_current()->name);
            thread_exit();
        }
        lock_acquire(&syscall_lock);
        if (args[1] > 127) {
            f->eax = -1;
        } else if (args[1] == 0) {
            f->eax = -1;
        } else {
            struct file* file_opened = thread_current()->fd_table[args[1]];
            if (file_opened == NULL) {
                f->eax = -1;
            }
            else if (args[1] == 1) {
                char* buffer = (char *) args[2];
                putbuf(buffer, args[3]);
                f->eax = args[3];
            } else {
                f->eax = file_write(file_opened, (void *) args[2], args[3]);
            }
        }
        lock_release(&syscall_lock);
    }

    if (args[0] == SYS_SEEK) {
        lock_acquire(&syscall_lock);
        if (args[1] > 127) {
            f->eax = -1;
        } else {
            struct file* file_opened = thread_current()->fd_table[args[1]];
            if (file_opened == NULL) {
                f->eax = -1;
            } else {
                file_seek(file_opened, args[2]);
                f->eax = 0;
            }
        }
        lock_release(&syscall_lock);
    }

    if (args[0] == SYS_TELL) {
        lock_acquire(&syscall_lock);
        if (args[1] > 127) {
            f->eax = -1;
        } else {
            struct file* file_opened = thread_current()->fd_table[args[1]];
            if (file_opened == NULL) {
                f->eax = -1;
            } else {
                f->eax = file_tell(file_opened);
            }
        }
        lock_release(&syscall_lock);
    }

    if (args[0] == SYS_CLOSE) {
        lock_acquire(&syscall_lock);
        if (args[1] > 127 || args[1] < 2) {
            f->eax = -1;
        } else {
            struct file* file_opened = thread_current()->fd_table[args[1]];
            if (file_opened == NULL) {
                f->eax = -1;
            } else {
                file_close(file_opened);
                thread_current()->fd_table[args[1]] = NULL;
            }
        }
        lock_release(&syscall_lock);
    }

    if (args[0] == SYS_HALT) {
        shutdown_power_off();
    }
}
