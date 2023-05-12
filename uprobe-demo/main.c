#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uprobes.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#define DEBUGGEE_FILE "/home/zfane/hello/hello"
#define DEBUGGEE_FILE_OFFSET (0x1149)
static struct inode *debuggee_inode;

static int uprobe_sample_handler(struct uprobe_consumer *con,
                                 struct pt_regs *regs)
{
    printk("handler is executed\n");


    return 0;
}

static int uprobe_sample_ret_handler(struct uprobe_consumer *con,
                                     unsigned long func,
                                     struct pt_regs *regs)
{
    printk("ret_handler is executed\n");
    return 0;
}

static struct uprobe_consumer uc = {
        .handler = uprobe_sample_handler,
        .ret_handler = uprobe_sample_ret_handler
};

static int __init init_uprobe_sample(void)
{
    int ret;
    struct path path;

    ret = kern_path(DEBUGGEE_FILE, LOOKUP_FOLLOW, &path);
    if (ret) {
        return -1;
    }

    debuggee_inode = igrab(path.dentry->d_inode);
    path_put(&path);

    ret = uprobe_register(debuggee_inode,
                          DEBUGGEE_FILE_OFFSET, &uc);
    if (ret < 0) {
        return -1;
    }

    printk(KERN_INFO "insmod uprobe_sample\n");
    return 0;
}

static void __exit exit_uprobe_sample(void)
{
    uprobe_unregister(debuggee_inode,
                      DEBUGGEE_FILE_OFFSET, &uc);
    printk(KERN_INFO "rmmod uprobe_sample\n");
}

module_init(init_uprobe_sample);
module_exit(exit_uprobe_sample);

MODULE_LICENSE("GPL");