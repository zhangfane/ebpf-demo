#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kernel.h>

static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
};
static struct kprobe kp2 = {
        .symbol_name = "disassemble"
};
static int __init my_module_init(void)
{
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    typedef unsigned long (*disassemble_t)(const char *name);
    disassemble_t disassemble;
    register_kprobe(&kp2);
    disassemble = (disassemble_t) kp.addr;
    unregister_kprobe(&kp2);

    unsigned long addr = kallsyms_lookup_name("do_exit");

    long unsigned int func_size;
    long unsigned int func_offset;
    char *func_insn;
    int ret;


    // 查找函数的大小和偏移量
    ret = kallsyms_lookup_size_offset(addr, &func_size, &func_offset);
    if (ret < 0) {
        pr_err("failed to lookup function \n");
        return ret;
    }

    // 分配足够大的空间来存储汇编指令
    func_insn = kmalloc(func_size + 1, GFP_KERNEL);
    if (!func_insn) {
        pr_err("failed to allocate memory\n");
        return 0;
    }

    // 将函数的机器码转换为汇编指令
    ret = disassemble(func_insn, func_size, addr, func_offset);
    if (ret < 0) {
        pr_err("failed to disassemble function \n");
        kfree(func_insn);
        return 0;
    }

    // 打印汇编指令
    pr_info("assembly code of function :\n%s", func_insn);

    kfree(func_insn);
//    unsigned char *instr = (unsigned char *)addr;
//
//    printk(KERN_INFO "sys_write at 0x%lx\n", addr);
//    printk(KERN_INFO "instruction at 0x%lx: %02x %02x %02x %02x %02x %02x %02x %02x\n",
//            (unsigned long)instr, instr[0], instr[1], instr[2], instr[3],
//            instr[4], instr[5], instr[6], instr[7]);
//    char buf[512];
//
//    int i, ret;
//    ret = disassemble_fn(addr, buf, sizeof(buf));
//    if (ret > 0) {
//        printk("Disassembling function %p:\n", addr);
//        for (i = 0; i < ret; i++)
//            printk("%c", buf[i]);
//        printk("\n");
//    } else {
//        printk("Failed to disassemble function %p\n", addr);
//    }

    return 0;
}

static void __exit my_module_exit(void)
{
    printk(KERN_INFO "module unloaded\n");
}

module_init(my_module_init);
module_exit(my_module_exit);
MODULE_LICENSE("GPL");