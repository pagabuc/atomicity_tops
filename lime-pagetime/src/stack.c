#include "lime.h"
#include "timing.h"
#include <linux/pagemap.h>
#include <linux/preempt.h>

static struct page *stack_pages[MAX_PAGE_MAPPED];
static phys_addr_t stack_phys_addrs[MAX_PAGE_MAPPED];
static void *stack_kern_virt_addrs[MAX_PAGE_MAPPED];
static void *stack_user_virt_addrs[MAX_PAGE_MAPPED];
static u32 valid_pages;
static struct file *filp_stack = NULL;
static struct task_struct *target_task = NULL;

// Collect means we fill the physical stack addresses
// Not collect means we dump the actual

int is_stack_addr(phys_addr_t paddr){
    int i;
    for(i=0; i<valid_pages; i++){
        if(stack_phys_addrs[i] == paddr)
            return 1;
    }
    return 0;
}

int open_stack_file(char *path){
    mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs(get_ds());
	strcpy(reusable_str, path);
	strcat(reusable_str, ".stack");
	filp_stack = filp_open(reusable_str, O_WRONLY | O_CREAT | O_TRUNC, 0444); // O_DSYNC
    set_fs(oldfs);
	if(IS_ERR(filp)) {
		return -1;
	}
    return 0;
}

ssize_t write_stack_file(void * v, size_t is) {
    ssize_t s;
    loff_t pos;

    mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs(get_ds());

    pos = filp_stack->f_pos;
    s = vfs_write(filp_stack, v, is, &pos);
    if (s == is) {
        filp_stack->f_pos = pos;
    }
    
    set_fs(oldfs);
    return s;
}

int sample_stack_process(char *name)
{
    struct task_struct *task;
    struct mm_struct * mm;
    struct vm_area_struct *vma;
    u64 start_stack = 0, vma_start = 0, vma_end = 0;
    int i, mapped_pages = 0;
    void *v;
    phys_addr_t p;
    int found = 0;
    int ri;
    int found_zero = 0;
    
    for_each_process(task) {
        if (strcmp(task->comm, name) == 0){
            found = 1;
            break;
        }
    }    
    if(!found){
        DBG("PROCESS %s NOT FOUND!", name);
        return -1;
    }
    target_task = task;
    mm = task->mm;    
    start_stack = mm->start_stack;
    vma = mm->mmap;

    if (!vma){
        DBG("This process doesn't have any vma");
        return -1;
    }

    do{
        vma_start = vma->vm_start;
        vma_end = vma->vm_end;
        if( (vma_start <= start_stack && vma_end >= start_stack)) 
            break; // Found the stack 
        vma = vma->vm_next;
    }while(vma);

    down_read(&mm->mmap_sem);

    // vma_start points to the last page of stack, which is a guard
    // page. get_user_pages access it and this triggers the mechanism
    // which allocates a new stack page. This leads to the allocation
    // of one more stack page, so we skip this guard page.
    vma_start += 4096;
    // This fills the stack_pages array
    mapped_pages = get_user_pages_remote(NULL, mm,
                                         vma_start, MAX_PAGE_MAPPED,
                                         0, stack_pages, NULL, NULL);
    up_read(&mm->mmap_sem);
    
    if (mapped_pages != (vma_end-vma_start)/4096){
        DBG("WARNING: We should increase MAX_PAGE_MAPPED mapped: %d have: %d",
            mapped_pages, (int)(vma_end-vma_start)/4096);
        return -1;
    }


    for(i = mapped_pages-1; i >= 0; i--){
        v = kmap(stack_pages[i]);
        p = virt_to_phys(v);
        /* XXX: Figure out where this number comes from */
        if (p == 0x0000021d9000){
            if(found_zero){
                kunmap(stack_pages[i]);
                put_page(stack_pages[i]);
                kunmap(stack_pages[i+1]);
                put_page(stack_pages[i+1]);
                i+=1;
                break;
            }
            found_zero = 1;
        }
        else{
            found_zero = 0;
        }
        ri = mapped_pages-1-i;
        stack_kern_virt_addrs[ri] = v; 
        stack_user_virt_addrs[ri] = (void *)vma_end-ri*4096;
        stack_phys_addrs[ri] = p;
    }

    valid_pages = mapped_pages - i - 1;
    DBG("stackregion %s start: 0x%016llx end: 0x%016llx mapped: %d valid: %d", task->comm, vma_start, vma_end, mapped_pages, valid_pages);
    for(i=0; i<valid_pages; i++)
        DBG("user: 0x%016llx user: 0x%016llx -> phys: 0x%012llx",
            vma_end-i*4096, (u64)stack_user_virt_addrs[i], (u64)stack_phys_addrs[i]);

    return 0;
}

void snapshot_registers(struct task_struct *task)
{
    struct page *page;
    struct pt_regs *pt;
    struct pt_regs *newpt;
    void *v;
    unsigned long offset;

    if(task == NULL){
        DBG("Can not snaphost_registers because task is NULL");
        return;
    }
    pt = (struct pt_regs*)(task->thread.sp0 - sizeof(struct pt_regs));
    offset = offset_in_page(pt);
    page = vmalloc_to_page(pt);
    v = kmap(page);
    newpt = (struct pt_regs *)(v+offset);

    write_stack_file((void *)&newpt->bp, 8);
    write_stack_file((void *)&newpt->sp, 8);
    write_stack_file((void *)&newpt->ip, 8);
    DBG("rbp: 0x%016lx rsp: 0x%016lx rip: 0x%016lx", newpt->bp, newpt->sp, newpt->ip);
    kunmap(page);
}

// Format is: met_paddr|count|rbp|rsp|rip
//            stack_paddr|stack_user_vaddr|content|
//            stack_paddr|stack_user_vaddr|content..

void snapshot_stack_process(char *name, phys_addr_t paddr){

    void *vkern, *vuser;
    phys_addr_t p;
    int i;
    
    DBG("Met 0x%016llx so snapshotting stack of %s",paddr, name);
    DBG("count %d", preempt_count());
    write_stack_file((void *)&paddr, 8);
    write_stack_file((void *)&valid_pages, 4);
    snapshot_registers(target_task);
    for(i=0; i<valid_pages; i++){
        vkern = stack_kern_virt_addrs[i];
        vuser = stack_user_virt_addrs[i];
        p = stack_phys_addrs[i];
        DBG("user: 0x%016llx phys: 0x%012llx", (u64)vuser, p);
        write_stack_file(&p, 8);
        write_stack_file(&vuser, 8);
        write_stack_file(vkern, 4096);
        kunmap(stack_pages[i]);
        put_page(stack_pages[i]);          
    }

    DBG("count %d", preempt_count());
    /* memset(stack_pages, 0, valid_pages * (sizeof(struct page*))); */
    /* memset(stack_phys_addrs, 0, MAX_PAGE_MAPPED * (sizeof(phys_addr_t))); */
    /* memset(stack_kern_virt_addrs, 0, MAX_PAGE_MAPPED * (sizeof(void *))); */
    /* memset(stack_user_virt_addrs, 0, MAX_PAGE_MAPPED * (sizeof(void *))); */
    /* sample_stack_process(name); */
}

