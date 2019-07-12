/*
 * LiME - Linux Memory Extractor
 * Copyright (c) 2011-2014 Joe Sylve - 504ENSICS Labs
 *
 *
 * Author:
 * Joe Sylve       - joe.sylve@gmail.com, @jtsylve
 *
 * lime-acqtime branch by:
 * Oleksii Fedorov - vsnrain.dev@gmail.com, @vsnrain
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include "lime.h"
#include "mount.h"
#include "timing.h"
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/cred.h>

// This file
static void write_range(struct resource *);

static int setup(void);
static void cleanup(void);
static int init(void);

// External
extern ssize_t write_padding(size_t);
extern ssize_t write_vaddr(void *, size_t);
extern int write_lime_header(struct resource *);
extern int write_pages(void *, int);

extern int dump_important_info_first(void);
extern int dump_memory_mappings(struct task_struct *);
extern int dump_open_files(struct task_struct*);
extern int dump_modules(void);

extern int open_stack_file(char*);
extern int sample_stack_process(char*);
extern int is_stack_addr(phys_addr_t);
extern void snapshot_stack_process(char*, phys_addr_t);

extern int setup_tcp(void);
extern void cleanup_tcp(void);
extern int setup_disk(void);
extern void cleanup_disk(void);

static char * format = 0;
int mode = 0;
char zero_page[PAGE_SIZE];
struct page *pages[MAX_PAGE_MAPPED];

char * path = 0;
int dio = 0;
int port = 0;
int localhostonly = 0;
long timeout = 1000;
int smart;
int stack;

ktime_t tp_current;

int method = 0;
char reusable_str[STRLEN];

DECLARE_BITMAP(bitmap, BITMAP_SIZE);

mm_segment_t oldfs;
int collisions;
char *proc_name = "bzip2";
extern struct resource iomem_resource;

module_param(path, charp, S_IRUGO);
module_param(dio, int, S_IRUGO);
module_param(format, charp, S_IRUGO);
module_param(localhostonly, int, S_IRUGO);
module_param(timeout, long, S_IRUGO);
module_param(smart, int, S_IRUGO);
module_param(stack, int, S_IRUGO);

int init_module (void)
{
    if(!path) {
        DBG("No path parameter specified");
        return -EINVAL;
    }
    
    if(!format) {
        DBG("No format parameter specified");
        return -EINVAL;
    }

    DBG("Parameters");
    DBG("  PATH: %s", path);
    /* DBG("  DIO: %u", dio); */
    /* DBG("  FORMAT: %s", format); */
    /* DBG("  LOCALHOSTONLY: %u", localhostonly); */
    DBG("  SMART: %u", smart);
    DBG("  STACK: %u", stack);

    memset(zero_page, 0, sizeof(zero_page));

    if (!strcmp(format, "raw")) mode = LIME_MODE_RAW;
    else if (!strcmp(format, "lime")) mode = LIME_MODE_LIME;
    else if (!strcmp(format, "padded")) mode = LIME_MODE_PADDED;
    else {
        DBG("Invalid format parameter specified.");
        return -EINVAL;
    }

    method = (sscanf(path, "tcp:%d", &port) == 1) ? LIME_METHOD_TCP : LIME_METHOD_DISK;
    return init();
}

static int init() {
    struct resource *p;
    int err = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
    resource_size_t p_last = -1;
#else
    __PTRDIFF_TYPE__ p_last = -1;
#endif

    DBG("Initializing Dump...");

    if((err = setup())) {
        DBG("Setup Error");
        cleanup();
        return err;
    }

    if(open_timing_file(path) != 0){
		DBG("[-] Failed to create timing file");
        return -1;
    }

	DBG("[+] Timing file created");
	
	init_time();
    
    if(smart){
        bitmap_zero(bitmap, BITMAP_SIZE);
        dump_important_info_first();
        // Take time at the end of the precise phase
        tp_current = get_relative_time();
        LOG("[PEND] %09lld\n", ktime_to_ns(tp_current));
    }
    
    if(stack){
        if(open_stack_file(path) != 0){
            DBG("[-] Failed to create timing file");
            return -1;
        }
        sample_stack_process(proc_name);
    }    

    for (p = iomem_resource.child; p ; p = p->sibling) {
      DBG("0x%016llx - 0x%016llx : IOMEM_RESOURCE.CHILD.NAME = %s", p->start, p->end, p->name);      

      if (strcmp(p->name, LIME_RAMSTR)) // If name != System RAM
          continue;
      
      if (mode == LIME_MODE_LIME && (err = write_lime_header(p))) {
          DBG("Error writing header 0x%lx - 0x%lx", (long) p->start, (long) p->end);
          break;
      } else if (mode == LIME_MODE_PADDED && (err = write_padding((size_t) ((p->start - 1) - p_last)))) {
          DBG("Error writing padding 0x%lx - 0x%lx", (long) p_last, (long) p->start - 1);
          break;
      }
      
      log_current_time(p->start, 0);
      write_range(p);      
      p_last = p->end;
      
    }
    
    tp_current = get_relative_time();
    LOG("[END] %09lld\n", ktime_to_ns(tp_current));

    close_timing_file();
    DBG("Memory Dump Complete...");

    cleanup();
		
    return err;
}



static void write_range(struct resource * res)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
    resource_size_t i, is;
#else
    __PTRDIFF_TYPE__ i, is;
#endif
    struct page * p;
    void * v;
    int bitmap_pos;
    ssize_t s = 0;
    ktime_t start,end;
    ktime_t tp_last = get_relative_time();
    DBG("Writing range %llx - %llx.", res->start, res->end);

    for (i = res->start; i <= res->end; i += is) {
        start = ktime_get();
        p = pfn_to_page((i) >> PAGE_SHIFT);

        is = min((size_t) PAGE_SIZE, (size_t) (res->end - i + 1));

        if (is < PAGE_SIZE) {
            // We can't map partial pages and
            // the linux kernel doesn't use them anyway
            DBG("Padding partial page: vaddr %p size: %lu", (void *) i, (unsigned long) is);
            write_padding(is);
        } else {
            v = kmap(p);
            if (stack && is_stack_addr((phys_addr_t)i)){
                preempt_disable();
                snapshot_stack_process(proc_name, (phys_addr_t)i);
                s = write_vaddr(v, is);
                preempt_enable();                
            }
            else if(smart) {
                bitmap_pos = (i >> 12);
                if(!test_bit(bitmap_pos, bitmap))
                    s = write_vaddr(v, is);                    
                /* else */
                /*     DBG("[2ND STEP] Page already acquired: 0x%016llx", (u64)i); */
            }
            else {
                s = write_vaddr(v, is);
            }
            
            tp_current = get_relative_time();
            kunmap(p);
            
            // Log timing
            if (ktime_to_ns(ktime_sub(tp_current, tp_last)) >= TP_DELTA){
                log_current_time((ptrdiff_t)i, 0);
                tp_last = tp_current;
            }

            if (s < 0) {
                DBG("Error writing page: vaddr %p ret: %zd.  Null padding.", v, s);
                write_padding(is);
            } else if (s != is) {
                DBG("Short Read %zu instead of %lu.  Null padding.", s, (unsigned long) is);
                write_padding(is - s);
            }
        }

        end = ktime_get();

        if (timeout > 0 && ktime_to_ms(ktime_sub(end, start)) > timeout) {
            DBG("Reading is too slow.  Skipping Range...");
            write_padding(res->end - i + 1 - is);
            break;
        }
    }
}


static int setup(void)
{
    return (method == LIME_METHOD_TCP) ? setup_tcp() : setup_disk();
}

static void cleanup(void)
{
    return (method == LIME_METHOD_TCP) ? cleanup_tcp() : cleanup_disk();
}

void cleanup_module(void)
{

}

MODULE_LICENSE("GPL");
