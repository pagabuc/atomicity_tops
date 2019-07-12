#include "lime.h"
#include <linux/list.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/fdtable.h>
#include <linux/timekeeper_internal.h>

extern int write_pages(void *, int);


void dump_modules(void)
{
	struct module *m;
    struct page *page;
    void *v;
    int offset;
    struct list_head *modules = (struct list_head *) kallsyms_lookup_name("modules");
    write_pages((void *)modules, sizeof (struct list_head));
	list_for_each_entry(m, modules, list) {
        page = vmalloc_to_page(m);
        v = kmap(page);
        // Offset of this module inside the page
        offset = ((u64)m) & 0xfff;
        DBG("m: 0x%16llx v: 0x%16llx", (u64)m, (u64)v);
        write_pages(v+offset, sizeof (struct module));
        kunmap(page);
    }
}

int dump_memory_mappings(struct task_struct* task)
{
    int i, mapped_pages = 0, succ;
    u64 start_brk, brk, start_stack, vma_start, vma_end;
	void *v;
    struct vm_area_struct *vma;
	struct mm_struct * mm = task->mm;
    
	/* DBG("mm @ 0x%016llx", (u64)mm); */
	if (mm == NULL)
        return 0;

	start_brk = mm->start_brk;
	brk = mm->brk;	
	start_stack = mm->start_stack;

	//DBG("start_brk: 0x%016llx brk: 0x%016llx start_stack: 0x%016llx", (u64)start_brk, brk, start_stack);
	
	succ = write_pages((void *)mm, sizeof(struct mm_struct));
    if(!succ)
        return 0;
    
    
    vma = mm->mmap;
	while(vma){
        succ = write_pages((void *)vma, sizeof(struct vm_area_struct));
        if(!succ)
            return 0;

        write_pages((void *)vma->vm_file, sizeof(struct file));
        vma_start = vma->vm_start;
        vma_end = vma->vm_end;
        if( (vma_start <= start_brk && vma_end >= brk) ||
            (vma_start <= start_stack && vma_end >= start_stack)){
            /* DBG("STACK/HEAP start: 0x%016llx end: 0x%016llx",vma_start, vma_end); */
            while (vma_start < vma_end){

                down_read(&mm->mmap_sem);
                mapped_pages = get_user_pages_remote(task, mm,
                                                     vma_start, MAX_PAGE_MAPPED,
                                                     0, pages, NULL, NULL);
                up_read(&mm->mmap_sem);
                
                /* mapped_pages = get_user_pages_unlocked(task, mm, vma_start, */
                /*                                        MAX_PAGE_MAPPED, 0, 1, pages); */
                vma_start+=(mapped_pages*PAGE_SIZE);
                DBG("For %s mapped: %d still have: %d", task->comm, mapped_pages, (int)(vma_end-vma_start)/4096);
                
                /* if (mapped_pages != (vma_end-vma_start)/4096) */
                /*     DBG("WARNING: Increase MAX_PAGE_MAPPED mapped: %d have: %d", */
                /*         mapped_pages, (int)(vma_end-vma_start)/4096);  */
                
                for(i=0; i<mapped_pages; i++){
                    v = kmap(pages[i]);
                    write_pages(v, 4096);
                    kunmap(pages[i]);
                    put_page(pages[i]);          
                }
            }
        }
        vma = vma->vm_next;
    }
    return 1;
}


void dump_dentry(struct dentry *dentry)
{
    const unsigned char *name;
    write_pages((void *)dentry, sizeof(struct dentry));
    name = dentry->d_name.name;
    write_pages((void *)name, strlen(name));
}

int dump_open_files(struct task_struct* task)
{
    int i, max_file, succ;
    
    // Open files
    struct files_struct *files;
    struct fdtable __rcu *fdt;
    struct file __rcu **fd;
    struct path *path;

    /* struct dentry *dentry; */
    /* struct vfsmount *mnt; */
    
	files = task->files;
	succ = write_pages((void *)files, sizeof(struct files_struct));
	if (!succ)
        return 0;
        
    fdt = files->fdt;
    succ = write_pages((void *)fdt, sizeof(struct fdtable));
    if(!succ)
        return 0;
    
    fd = fdt->fd;
    max_file = fdt->max_fds;

    // Here we save the open_fds array
    write_pages((void *)fdt->open_fds, (max_file / 64) * sizeof(unsigned long));

    // Here we save the struct file * array
    write_pages((void *)fd, max_file * sizeof(struct file *));

    for(i = 0; i<max_file; i++){
        struct file *f = fd[i];
        if(!f) continue;

        succ = write_pages((void *)f, sizeof(struct file));
        if (!succ)
            continue;

        path = &(f->f_path);
        write_pages((void *)path, sizeof(struct path));
        
        /* dentry = path.dentry; */
        /* write_pages((void *)dentry, sizeof(struct dentry)); */
        
        /* mnt = path.mnt; */
        /* write_pages((void *)mnt, sizeof(struct vfsmount)); */
    }
    return 1;
}

int dump_kernel_stack(struct task_struct *task)
{
    struct page *page;
    struct pt_regs *pt;
    struct pt_regs *newpt;
    void *v;
    unsigned long offset;

    pt = (struct pt_regs*)(task->thread.sp0 - sizeof(struct pt_regs));
    offset = offset_in_page(pt);
    page = vmalloc_to_page(pt);
    v = kmap(page);
    newpt = (struct pt_regs *)(v+offset);
    DBG("sp0: 0x%16lx pt: 0x%016llx v: 0x%016llx newpt: 0x%016lx", task->thread.sp0, (u64)pt->ip, (u64)v, newpt->ip);
    write_pages((void *)newpt, sizeof (struct pt_regs));
    kunmap(page);
    return 1;
}

void walk_pte(pte_t *pte){
    write_pages(pte, 4096);    
}

void walk_pmd(pmd_t *pmd){
    int i;
    write_pages(pmd, 4096);
    for(i = 0; i < PTRS_PER_PMD; i+=1){
        if(pmd_present(*pmd) && !pmd_none(*pmd)){ // && (pmd_flags(*pmd) & _PAGE_USER) ){
            /* DBG("    pmd: 0x%016llx", *pmd); */
            if(!pmd_large(*pmd))
                walk_pte((pte_t *)pmd_page_vaddr(*pmd));
        }
        pmd++;
    }            
}

void walk_pud(pud_t *pud){
    int i;
    write_pages(pud, 4096);
    for(i = 0; i < PTRS_PER_PUD; i+=1){
        if(pud_present(*pud) && !pud_none(*pud)){// && (pud_flags(*pud) & _PAGE_USER) ){
            /* DBG("  pud: 0x%016llx", *pud); */
            if(!pud_large(*pud))
                walk_pmd((pmd_t *)pud_page_vaddr(*pud));
        }
        pud++;
    }            
}


void walk_pgd(pgd_t *pgd){
    int i;
    write_pages(pgd, 4096);
    for(i = 0; i < PTRS_PER_PGD; i+=1){
        if(pgd_present(*pgd) && !pgd_none(*pgd)){// && (pgd_flags(*pgd) & _PAGE_USER) ){
            /* DBG("pgd: 0x%016llx", *pgd); */
            if(!pgd_large(*pgd))
                walk_pud((pud_t *)pgd_page_vaddr(*pgd));
                
        }
        pgd++;
    }            
}


int dump_pagetable(struct task_struct *task){
    pgd_t *pgd;    
    if(!task->mm)
        return 0;
            
    pgd = task->mm->pgd;
    DBG("CR3: %s 0x%16llx", task->comm, pgd);
    walk_pgd(pgd);
    return 1;
}

int process_task(struct task_struct* task)
{
    int a = 0, b = 0 ,c = 0, d = 0;
    DBG("process_task @ 0x%016llx -> 0x%016llx: %s.%d \n\t parent: 0x%016llx pid: %s.%d \n\t real_parent: 0x%016llx real_parent: %s.%d",
        (u64)task, (u64) virt_to_phys((void*) task), task->comm, task->pid, task->parent, task->parent->comm, task->parent->pid, task->real_parent, task->real_parent->comm, task->real_parent->pid);
	write_pages((void *)task, sizeof(struct task_struct));
    write_pages((void *)task->cred, sizeof(struct cred));
	a = dump_memory_mappings(task);
    b = dump_kernel_stack(task);
    c = dump_open_files(task);
    d = dump_pagetable(task);
    DBG("mm: %d regs: %d of: %d pt: %d", a, b, c, d);
	return 1;
}


int dump_important_info_first(void)
{
    struct task_struct *p, *t;
    struct timekeeper *tk;
    pgd_t *init_level4_pgt;
    
    // timekeeper struct, used by linux_pslist to display start time
    tk = (struct timekeeper*) (kallsyms_lookup_name("tk_core")+8);
    write_pages((void*)tk, sizeof(struct timekeeper));
    
    // Modules list
    dump_modules();

    // Dump kernel page table
    init_level4_pgt = (pgd_t*) (kallsyms_lookup_name("init_level4_pgt"));
    walk_pgd(init_level4_pgt);
        
    // Tasks and related infos
	process_task(&init_task);
	for_each_process(p) {
        for_each_thread(p, t) {
            process_task(t);
        }
    }
        
    
	return 0;
}

