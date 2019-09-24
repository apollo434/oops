#### Kernel Crash ####

##### 1. crash happened in kernel mode #####

**create a crash via "echo c > /proc/sysrq-trigge" **

```
__dabt_svc
  dabt_helper
    CPU_DABORT_HANDLER
      do_DataAbort
        do_translation_fault
          do_page_fault
            __do_kernel_fault
              show_pte and
              die
                report_bug
                __die
                  __show_regs(regs)
                  dump_mem
                  dump_backtrace
                  dump_instr
                crash_kexec
                  machine_crash_shutdown


```

```
arch/arm/kernel/entry-armv.S

__dabt_svc

    .align    5
__dabt_svc:
    svc_entry
    mov    r2, sp
    dabt_helper

    @
    @ IRQs off again before pulling preserved data off the stack
    @
    disable_irq_notrace
    svc_exit r5                @ return from exception
 UNWIND(.fnend        )
ENDPROC(__dabt_svc)

```

```
.macro    dabt_helper

    @
    @ Call the processor-specific abort handler:
    @
    @  r2 - pt_regs
    @  r4 - aborted context pc
    @  r5 - aborted context psr
    @
    @ The abort handler must return the aborted address in r0, and
    @ the fault status register in r1.  r9 must be preserved.
    @

    bl    CPU_DABORT_HANDLER
    .endm
```

```
arch/arm/include/asm/glue-df.h

#ifdef CONFIG_CPU_ABRT_EV7
# ifdef CPU_DABORT_HANDLER
#  define MULTI_DABORT 1
# else
#  define CPU_DABORT_HANDLER v7_early_abort
# endif
#endif

```
```
arch/arm/mm/abort-ev7.S

.align    5
ENTRY(v7_early_abort)
    /*
     * The effect of data aborts on on the exclusive access monitor are
     * UNPREDICTABLE. Do a CLREX to clear the state
     */
    clrex

    mrc    p15, 0, r1, c5, c0, 0        @ get FSR 【Fault Status Register (FSR)】
    mrc    p15, 0, r0, c6, c0, 0        @ get FAR 【Fault Address Register (FAR).】

    /*
     * V6 code adjusts the returned DFSR.
     * New designs should not need to patch up faults.
     */

    b    do_DataAbort
ENDPROC(v7_early_abort)

```
```
arch/arm/mm/fault.c

/*
 * Dispatch a data abort to the relevant handler.
 */
asmlinkage void __exception
do_DataAbort(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
    const struct fsr_info *inf = fsr_info + fsr_fs(fsr);
    struct siginfo info;

    if (!inf->fn(addr, fsr & ~FSR_LNX_PF, regs))
        return;

    printk(KERN_ALERT "Unhandled fault: %s (0x%03x) at 0x%08lx\n",
        inf->name, fsr, addr);

    info.si_signo = inf->sig;
    info.si_errno = 0;
    info.si_code  = inf->code;
    info.si_addr  = (void __user *)addr;
    arm_notify_die("", regs, &info, fsr, 0);
}

```
```
do_DataAbort(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
    const struct fsr_info *inf = fsr_info + fsr_fs(fsr);
    struct siginfo info;
    /*threre so many callbacks*/
    if(!addr)
        printk(KERN_ALERT "do_DataAbort: NULL index:0x%x\n",fsr_fs(fsr));
    if (!inf->fn(addr, fsr & ~FSR_LNX_PF, regs))
        return;

}

```
```
arch/arm/mm/fsr-2level.c

static struct fsr_info fsr_info[] = {
    /*
     * The following are the standard ARMv3 and ARMv4 aborts.  ARMv5
     * defines these to be "precise" aborts.
     */
    { do_bad,        SIGSEGV, 0,        "vector exception"           },
    { do_bad,        SIGBUS,     BUS_ADRALN,    "alignment exception"           },
    { do_bad,        SIGKILL, 0,        "terminal exception"           },
    { do_bad,        SIGBUS,     BUS_ADRALN,    "alignment exception"           },
    { do_bad,        SIGBUS,     0,        "external abort on linefetch"       },
    { do_translation_fault,    SIGSEGV, SEGV_MAPERR,    "section translation fault"       },
    { do_bad,        SIGBUS,     0,        "external abort on linefetch"       },
    { do_page_fault,    SIGSEGV, SEGV_MAPERR,    "page translation fault"       },
    { do_bad,        SIGBUS,     0,        "external abort on non-linefetch"  },
    { do_bad,        SIGSEGV, SEGV_ACCERR,    "section domain fault"           },
    { do_bad,        SIGBUS,     0,        "external abort on non-linefetch"  },
    { do_bad,        SIGSEGV, SEGV_ACCERR,    "page domain fault"           },
    { do_bad,        SIGBUS,     0,        "external abort on translation"       },
    { do_sect_fault,    SIGSEGV, SEGV_ACCERR,    "section permission fault"       },
    { do_bad,        SIGBUS,     0,        "external abort on translation"       },
    { do_page_fault,    SIGSEGV, SEGV_ACCERR,    "page permission fault"           },
}

```

```
arch/arm/mm/fault.c

do_translation_fault(unsigned long addr, unsigned int fsr,
             struct pt_regs *regs)
{
    unsigned int index;
    pgd_t *pgd, *pgd_k;
    pud_t *pud, *pud_k;
    pmd_t *pmd, *pmd_k;

    if (addr < TASK_SIZE)
        return do_page_fault(addr, fsr, regs);
}

do_page_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
    struct task_struct *tsk;
    struct mm_struct *mm;
    int fault, sig, code;
    int write = fsr & FSR_WRITE;
    unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE |
                (write ? FAULT_FLAG_WRITE : 0);

    /*
     * If we're in an interrupt or have no user
     * context, we must not take the fault..
     */
    if (in_atomic() || !mm){
        printk(KERN_ALERT "do_page_fault:mm_struct_1 0x%x\n", mm);
        goto no_context;
    }

    if (!down_read_trylock(&mm->mmap_sem)) {
        if (!user_mode(regs) && !search_exception_tables(regs->ARM_pc)){
            printk(KERN_ALERT "do_page_fault:mm_struct_2 0x%x\n", mm);
            goto no_context;
        }
        down_read(&mm->mmap_sem);
    }
    else{
        fault = __do_page_fault(mm, addr, fsr, flags, tsk);
        /*
         * If we are in kernel mode at this point, we
         * have no context to handle this fault with.
         */
        if (!user_mode(regs)){
            printk(KERN_ALERT "do_page_fault:mm_struct_3 0x%x\n", mm);
            goto no_context;
        }
    }
no_context:
    printk(KERN_ALERT "__do_kernel_fault: do_page_fault:index 0x%x\n", fsr_fs(fsr));
    __do_kernel_fault(mm, addr, fsr, regs);
    return 0;

}

```
