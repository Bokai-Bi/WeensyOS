#include "kernel.hh"
#include "k-apic.hh"
#include "k-vmiter.hh"
#include <atomic>

// kernel.cc
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

proc ptable[NPROC];             // array of process descriptors
                                // Note that `ptable[0]` is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static std::atomic<unsigned long> ticks; // # timer interrupts so far


// Memory state
//    Information about physical page with address `pa` is stored in
//    `pages[pa / PAGESIZE]`. In the handout code, each `pages` entry
//    holds an `refcount` member, which is 0 for free pages.
//    You can change this as you see fit.

pageinfo pages[NPAGES];


[[noreturn]] void schedule();
[[noreturn]] void run(proc* p);
void exception(regstate* regs);
uintptr_t syscall(regstate* regs);
void memshow();


// kernel(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

static void process_setup(pid_t pid, const char* program_name);

void kernel(const char* command) {
    // Initialize hardware.
    init_hardware();
    log_printf("Starting WeensyOS\n");

    // Initialize timer interrupt.
    ticks = 1;
    init_timer(HZ);

    // Clear screen.
    console_clear();

    // (re-)Initialize the kernel page table.
    for (vmiter it(kernel_pagetable); it.va() < MEMSIZE_PHYSICAL; it += PAGESIZE) {
        if (it.va() == 0) {
            // nullptr is inaccessible even to the kernel
            it.map(it.va(), 0);
            
        }
        else if (it.va() < PROC_START_ADDR && it.va() != CONSOLE_ADDR) {
            // kernel memory, inaccessible to programs
            it.map(it.va(), PTE_P | PTE_W);
        }
        else{
            it.map(it.va(), PTE_P | PTE_W | PTE_U);
        }
    }

    memset(ptable, 0, sizeof(proc) * NPROC);

    // Set up process descriptors.
    for (pid_t i = 0; i < NPROC; i++) {
        ptable[i].pid = i;
        ptable[i].state = P_FREE;
    }
    if (command && program_loader(command).present()) {
        process_setup(1, command);
    } else {
        process_setup(1, "allocator");
        process_setup(2, "allocator2");
        process_setup(3, "allocator3");
        process_setup(4, "allocator4");
    }

    // Switch to the first process using run().
    run(&ptable[1]);
}

void del_pagetable(x86_64_pagetable* new_pagetable){
    for (vmiter it(new_pagetable); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE){
        if (it.user() && (it.pa() != CONSOLE_ADDR)){
            kfree((void*)(it.pa()));
        }
    }

    for (ptiter it(new_pagetable); it.active(); it.next()) {
        kfree(it.kptr());
    }
    kfree(new_pagetable);
}


// kalloc(sz)
//    Kernel memory allocator. Allocates `sz` contiguous bytes and
//    returns a pointer to the allocated memory (the physical address of
//    the newly allocated memory), or `nullptr` on failure.
//
//    The returned memory is initialized to 0xCC, which corresponds to
//    the x86 instruction `int3` (this may help you debug). You can
//    reset it to something more useful.
//
//    On WeensyOS, `kalloc` is a page-based allocator: if `sz > PAGESIZE`
//    the allocation fails; if `sz < PAGESIZE` it allocates a whole page
//    anyway.
//
//    The stencil code returns the next allocatable free page it can find,
//    but it never reuses pages or supports freeing memory (you'll have to
//    change this at some point).

static uintptr_t next_alloc_pa;


void* kalloc(size_t sz) {
    if (sz > PAGESIZE) {
        return nullptr;
    }
    next_alloc_pa = 0;

    while (next_alloc_pa < MEMSIZE_PHYSICAL) {
        uintptr_t pa = next_alloc_pa;
        next_alloc_pa += PAGESIZE;
        //log_printf("Try allocate %p, used = %d\n", pa, pages[pa / PAGESIZE].used());

        if (allocatable_physical_address(pa)
            && !pages[pa / PAGESIZE].used()) {
            pages[pa / PAGESIZE].refcount = 1;
            //log_printf("Kalloc location: %p\n", next_alloc_pa);
            memset((void*) pa, 0xCC, PAGESIZE);
            return (void*) pa;
        }
    }
    return nullptr;
}


// kfree(kptr)
//    Frees `kptr`, which must have been previously returned by `kalloc`.
//    If `kptr == nullptr` does nothing.

void kfree(void* kptr) {
    // Placeholder code below - you will have to implement `kfree`!
    if (kptr == nullptr){
        return;
    }
    if (pages[(long)kptr / PAGESIZE].used()){
        pages[(long)kptr / PAGESIZE].refcount -= 1;
    }
}


// process_setup(pid, program_name)
//    Loads application program `program_name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.

void process_setup(pid_t pid, const char* program_name) {
    init_process(&ptable[pid], 0);

    // Initialize this process's page table. 

    // create new empty pagetable for process
    // log_printf("kalloc from init\n");
    x86_64_pagetable* proc_pagetable = (x86_64_pagetable*)kalloc(PAGESIZE);
    memset(proc_pagetable, 0, PAGESIZE);
    ///log_printf("Memory %p kalloced from process_setup-1\n", proc_pagetable);
    ptable[pid].pagetable = proc_pagetable;
    ptable[pid].state = P_RUNNABLE;

    // copy kernel addresses to new pagetable
    vmiter proc_it(proc_pagetable);
    for (vmiter it(kernel_pagetable); it.va() < PROC_START_ADDR; it += PAGESIZE){
        proc_it.map(it.pa(), it.perm());
        proc_it += PAGESIZE;
        // log_printf("Process %d: %p va -> %p pa. Perm: %d\n", pid, it.va(), proc_it.pa(), proc_it.perm());
    }


    // Initialize `program_loader`.
    // The `program_loader` is an iterator that visits segments of executables.
    program_loader loader(program_name);

    // Using the loader, we're going to start loading segments of the program binary into memory
    // (recall that an executable has code/text segment, data segment, etc).

    // First, for each segment of the program, we allocate page(s) of memory.
    for (loader.reset(); loader.present(); ++loader) {
        //log_printf("Loader VA: %p, loader size: %d", loader.va(), loader.size());
        for (uintptr_t a = round_down(loader.va(), PAGESIZE);
             a < loader.va() + loader.size();
             a += PAGESIZE) {
            // `a` is the virtual address of the current segment's page.
            // log_printf("kalloc from adding page at VA: %p\n", a);
            void* allocated_mem = kalloc(PAGESIZE);
            assert(allocated_mem != nullptr);
            ///("Memory %p kalloced from process_setup-2\n", allocated_mem);
            //assert(!pages[a / PAGESIZE].used());
            // Read the description on the `pages` array if you're confused about what it is.
            // Here, we're directly getting the page that has the same physical address as the
            // virtual address `a`, and claiming that page by incrementing its reference count
            // (you will have to change this later).
            //pages[a / PAGESIZE].refcount = 1;

            proc_it.find(a);
            proc_it.map(allocated_mem, loader.present() | ((int)loader.writable() * 2) | PTE_U);
            //proc_it.map(a, PTE_P | PTE_W | PTE_U);
            //log_printf("Process %d: %p va -> %p pa. Perm: %d\n", pid, proc_it.va(), proc_it.pa(), proc_it.perm());
        }
    }


    // We now copy instructions and data into memory that we just allocated.
    for (loader.reset(); loader.present(); ++loader) {
        //log_printf("Setting: %p, size: %d", loader.va(), loader.data_size());
        proc_it.find(loader.va());
        memset((void*) proc_it.pa(), 0, loader.size());
        memcpy((void*) proc_it.pa(), loader.data(), loader.data_size());
    }

    // Set %rip and mark the entry point of the code.
    ptable[pid].regs.reg_rip = loader.entry();

    // We also need to allocate a page for the stack.
    //uintptr_t stack_addr = PROC_START_ADDR + PROC_SIZE * pid - PAGESIZE;
    uintptr_t stack_addr = MEMSIZE_VIRTUAL - PAGESIZE;
    // log_printf("kalloc from adding stack at VA: %p\n", stack_addr);
    void* allocated_mem = kalloc(PAGESIZE);
    assert(allocated_mem != nullptr);
    ///log_printf("Memory %p kalloced from process_setup-3\n", allocated_mem);
    //assert(!pages[stack_addr / PAGESIZE].used());
    // Again, we're using the physical page that has the same address as the `stack_addr` to
    // maintain the one-to-one mapping between physical and virtual memory (you will have to change
    // this later).
    //pages[stack_addr / PAGESIZE].refcount = 1;
    proc_it.find(stack_addr);
    proc_it.map(allocated_mem, PTE_P | PTE_W | PTE_U);
    // Set %rsp to the start of the stack.
    ptable[pid].regs.reg_rsp = stack_addr + PAGESIZE;
    // assign the created pagetable to ptable[pid]
    ptable[pid].pagetable = proc_pagetable;
    // Finally, mark the process as runnable.
    ptable[pid].state = P_RUNNABLE;
}



// exception(regs)
//    Exception handler (for interrupts, traps, and faults).
//    You should *not* have to edit this function.
//
//    The register values from exception time are stored in `regs`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (see
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception(). This way, the process can be resumed right where
//    it left off before the exception. The pushed registers are popped and
//    restored before returning to the process (see k-exception.S).
//
//    Note that hardware interrupts are disabled when the kernel is running.

void exception(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: exception %d at rip %p\n",
                current->pid, regs->reg_intno, regs->reg_rip); */

    // Show the current cursor location and memory state (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if (regs->reg_intno != INT_PF || (regs->reg_errcode & PFERR_USER)) {
        memshow();
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER:
        ++ticks;
        lapicstate::get().ack();
        schedule();
        break;                  /* will not be reached */

    case INT_PF: {
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PFERR_WRITE
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PFERR_PRESENT
                ? "protection problem" : "missing page";
        
        /*for (vmiter it(ptable[current->pid].pagetable); it.va() < MEMSIZE_PHYSICAL; it += PAGESIZE){
            log_printf("Process %d: %p va -> %p pa. Perm: %d\n", current->pid, it.va(), it.pa(), it.perm());
        }*/

        if (!(regs->reg_errcode & PFERR_USER)) {
            panic("Kernel page fault for %p (%s %s, rip=%p)!\n",
                  addr, operation, problem, regs->reg_rip);
        }
        console_printf(CPOS(24, 0), 0x0C00,
                       "Process %d page fault for %p (%s %s, rip=%p)!\n",
                       current->pid, addr, operation, problem, regs->reg_rip);
        current->state = P_BROKEN;
        break;
    }

    default:
        panic("Unexpected exception %d!\n", regs->reg_intno);

    }

    // Return to the current process (or run something else).
    if (current->state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


// syscall(regs)
//    System call handler.
//
//    The register values from system call time are stored in `regs`.
//    The return value, if any, is returned to the user process in `%rax`.
//
//    Note that hardware interrupts are disabled when the kernel is running.

// Headers for helper functions used by syscall.
int syscall_page_alloc(uintptr_t addr);
pid_t syscall_fork();
void syscall_exit();

uintptr_t syscall(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: syscall %d at rip %p\n",
                  current->pid, regs->reg_rax, regs->reg_rip); */

    // Show the current cursor location and memory state (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    memshow();

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();

    // Actually handle the exception.
    switch (regs->reg_rax) {

    case SYSCALL_PANIC:
        panic(nullptr); // does not return

    case SYSCALL_GETPID:
        return current->pid;

    case SYSCALL_YIELD:
        current->regs.reg_rax = 0;
        schedule(); // does not return

    case SYSCALL_PAGE_ALLOC:
        return syscall_page_alloc(current->regs.reg_rdi);

    case SYSCALL_FORK:
        return syscall_fork();

    case SYSCALL_EXIT:
        syscall_exit();
        schedule(); // does not return

    default:
        panic("Unexpected system call %ld!\n", regs->reg_rax);

    }

    panic("Should not get here!\n");
}


// syscall_page_alloc(addr)
//    Helper function that handles the SYSCALL_PAGE_ALLOC system call.
//    This function implement the specification for `sys_page_alloc`
//    in `u-lib.hh` (but in the stencil code, it does not - you will
//    have to change this).

int syscall_page_alloc(uintptr_t addr) {
    //assert(!pages[addr / PAGESIZE].used());
    // log_printf("Received page alloc request from process %d, addr: %p", current->pid, addr);
    // Currently we're simply using the physical page that has the same address
    // as `addr` (which is a virtual address).
    if (addr < PROC_START_ADDR){
        // return -1 on trying to borrow kernel address
        return -1;
    }
    //pages[addr / PAGESIZE].refcount = 1;
    // log_printf("kalloc from syscall\n");
    void* allocated_mem = kalloc(PAGESIZE);
    if (allocated_mem == nullptr){
        return -1;
    }
    ///log_printf("Memory %p kalloced from syscall_page_alloc\n", allocated_mem);

    // add newly allocated memory entry to current pagetable
    x86_64_pagetable* current_pagetable = ptable[current->pid].pagetable;
    vmiter v(current_pagetable);
    v.find(addr);
    v.map(allocated_mem, PTE_P | PTE_W | PTE_U);
    // log_printf("Process %d: %p va -> %p pa. Perm: %d\n", current->pid, v.va(), v.pa(), v.perm());

    memset(allocated_mem, 0, PAGESIZE);
    // log_printf("Finished page alloc request from process %d, addr: %p", current->pid, addr);
    return 0;
}

// syscall_fork()
//    Handles the SYSCALL_FORK system call. This function
//    implements the specification for `sys_fork` in `u-lib.hh`.
pid_t syscall_fork() {
    // Implement for Step 5!
    //panic("Unexpected system call %ld!\n", SYSCALL_FORK);
    pid_t new_pid = -1;
    // check if there is spot in ptable
    for (int i = 1; i < NPROC; i++){
        //log_printf("Checking process index %d, pid is %d", i, ptable[i].pid);
        if (ptable[i].state == P_FREE){
            new_pid = i;
            break;
        }
    }

    if (new_pid == -1){
        // log_printf("No space\n");
        return -1;
    }

    // copy pagetable contents
    x86_64_pagetable* new_pagetable = (x86_64_pagetable*)kalloc(PAGESIZE);
    if (new_pagetable == nullptr){
        return -1;
    }
    ///log_printf("Memory %p kalloced from fork-1\n", new_pagetable);
    memset(new_pagetable, 0, PAGESIZE);
    vmiter new_it(new_pagetable);
    for (vmiter old_it(ptable[current->pid].pagetable); old_it.va() < MEMSIZE_VIRTUAL; old_it += PAGESIZE){
        if (old_it.present()){
            if (old_it.user() && old_it.va() >= PROC_START_ADDR){
                // point to same address if not writable
                if (old_it.writable()){
                    // make new copy
                    void* allocated_mem = kalloc(PAGESIZE);
                    if (allocated_mem == nullptr){
                        // TODO: free all previous allocation
                        //new_it.find(0);
                        del_pagetable(new_pagetable);
                        return -1;
                    }
                    else{
                        ///log_printf("Memory %p kalloced from fork-2\n", allocated_mem);
                        memcpy(allocated_mem, (void*)(old_it.pa()), PAGESIZE);
                        int res = new_it.try_map(allocated_mem, old_it.perm());
                        if (res == -1){
                            kfree(allocated_mem);
                            del_pagetable(new_pagetable);
                            return -1;
                        }
                    }
                }
                else{
                    // point to same address, increment ref_count
                    int res = new_it.try_map(old_it.pa(), old_it.perm());
                    if (res == -1){
                        del_pagetable(new_pagetable);
                        return -1;
                    }
                    pages[old_it.pa() / PAGESIZE].refcount += 1;
                }
                
            }
            else{
                // direct point to same
                int res = new_it.try_map(old_it.pa(), old_it.perm());
                if (res == -1){
                    del_pagetable(new_pagetable);
                    return -1;
                }
            }
        }
        new_it += PAGESIZE;
    }
    
    // TODO: fill in proc struct at ptable[new_pid]
    ptable[new_pid].pagetable = new_pagetable;
    ptable[new_pid].pid = new_pid;
    ptable[new_pid].state = P_RUNNABLE;
    memcpy(&(ptable[new_pid].regs), &(ptable[current->pid].regs), sizeof(regstate));
    ptable[new_pid].regs.reg_rax = 0;

    return new_pid;
}

// syscall_exit()
//    Handles the SYSCALL_EXIT system call. This function
//    implements the specification for `sys_exit` in `u-lib.hh`.
void syscall_exit() {
    // Implement for Step 7!
    //panic("Unexpected system call %ld!\n", SYSCALL_EXIT);

    pid_t current_pid = current->pid;
    del_pagetable(ptable[current_pid].pagetable);
    
    /*for (vmiter it(ptable[current_pid].pagetable); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE){
        if (it.user() && (it.pa() != CONSOLE_ADDR)){
            kfree((void*)(it.pa()));
        }
    }

    for (ptiter it(ptable[current_pid].pagetable); it.active(); it.next()) {
        log_printf("Freeing: %p with ref %d, used() = %d\n", it.kptr(), pages[(long)(it.kptr()) / PAGESIZE].refcount, pages[(long)(it.kptr()) / PAGESIZE].used());
        kfree(it.kptr());
        log_printf("Page at %p now has ref %d, used() = %d\n", it.kptr(), pages[(long)(it.kptr()) / PAGESIZE].refcount, pages[(long)(it.kptr()) / PAGESIZE].used());
    }
    kfree(ptable[current_pid].pagetable);
    */

    ptable[current_pid].state = P_FREE;
    //kfree(ptable[current_pid].pagetable + 1);
    //kfree(ptable[current_pid].pagetable + 2);
    //kfree(ptable[current_pid].pagetable + 3);
}

// syscall_kill(pid_t pid)
//    Exits the process at pid
void syscall_exit(pid_t pid) {
    del_pagetable(ptable[pid].pagetable);
    ptable[pid].state = P_FREE;
}

// schedule
//    Picks the next process to run and then run it.
//    If there are no runnable processes, spins forever.
//    You should *not* have to edit this function.

void schedule() {
    pid_t pid = current->pid;
    for (unsigned spins = 1; true; ++spins) {
        pid = (pid + 1) % NPROC;
        if (ptable[pid].state == P_RUNNABLE) {
            run(&ptable[pid]);
        }

        // If Control-C was typed, exit the virtual machine.
        check_keyboard();

        // If spinning forever, show the memviewer.
        if (spins % (1 << 12) == 0) {
            memshow();
            log_printf("%u\n", spins);
        }
    }
}


// run(p)
//    Runs process `p`. This involves setting `current = p` and calling
//    `exception_return` to restore its page table and registers.
//    You should *not* have to edit this function.

void run(proc* p) {
    assert(p->state == P_RUNNABLE);
    current = p;

    // Check the process's current pagetable.
    check_pagetable(p->pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(p);

    // should never get here
    while (true) {
    }
}


// memshow()
//    Draws a picture of memory (physical and virtual) on the CGA console.
//    Switches to a new process's virtual memory map every 0.25 sec.
//    Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.
//    You should *not* have to edit this function.

void memshow() {
    static unsigned last_ticks = 0;
    static int showing = 0;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        showing = (showing + 1) % NPROC;
    }

    proc* p = nullptr;
    for (int search = 0; !p && search < NPROC; ++search) {
        if (ptable[showing].state != P_FREE
            && ptable[showing].pagetable) {
            p = &ptable[showing];
        } else {
            showing = (showing + 1) % NPROC;
        }
    }

    extern void console_memviewer(proc* vmp);
    console_memviewer(p);
}
