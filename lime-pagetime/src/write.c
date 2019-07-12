#include <linux/types.h>
#include "lime.h"
#include "timing.h"

extern int write_vaddr_tcp(void *, size_t);
extern int write_vaddr_disk(void *, size_t);


ssize_t write_vaddr(void * v, size_t is) {
    return RETRY_IF_INTURRUPTED(
        (method == LIME_METHOD_TCP) ? write_vaddr_tcp(v, is) : write_vaddr_disk(v, is)
    );
}

ssize_t write_padding(size_t s) {
    size_t i = 0;
    ssize_t r;

    while(s -= i) {

        i = min((size_t) PAGE_SIZE, s);
        r = write_vaddr(zero_page, i);

        if (r != i) {
            DBG("Error sending zero page: %zd", r);
            return r;
        }
    }

    return 0;
}

int write_lime_header(struct resource * res) {
    ssize_t s;

    lime_mem_range_header header;

    memset(&header, 0, sizeof(lime_mem_range_header));
    header.magic = LIME_MAGIC;
    header.version = 1;
    header.s_addr = res->start;
    header.e_addr = res->end;

    s = write_vaddr(&header, sizeof(lime_mem_range_header));

    if (s != sizeof(lime_mem_range_header)) {
        DBG("Error sending header %zd", s);
        return (int) s;
    }

    return 0;
}

int __write_pages(void * vaddr, int size, int check_bitmap)
{
    ssize_t s;
    phys_addr_t paddr;
    void *p;
    int bitmap_pos;
        
	if (vaddr == NULL){
        return 0;
	}

    p = (void *)(((u64) vaddr) & (~4096 + 1));
    
    /* Format is paddr|page|paddr|page... */
    while (p < vaddr+size){
        
        paddr = virt_to_phys(p);

        if(check_bitmap){
            bitmap_pos = (paddr >> 12);
            if(test_bit(bitmap_pos, bitmap)){
                /* DBG("Page already acquired: 0x%016llx -> 0x%012llx", (u64)p, virt_to_phys(p)); */
                p+=4096;
                continue;
            }
            __set_bit(bitmap_pos, bitmap);
        }
        
        write_vaddr(&paddr, 8);
        s = write_vaddr(p, 4096);
        log_current_time(paddr, 1);
        
        if(s != 4096)
            DBG("Error writing pages @ 0x%016llx", (u64)paddr);

        p+=4096;
	}
    
	return 1;
}

/* int write_pages_nocheck(void * vaddr, int size) */
/* { */
/*     __write_pages(vaddr, size, 0); */
/* } */

int write_pages(void * vaddr, int size)
{
    return __write_pages(vaddr, size, 1);
}
