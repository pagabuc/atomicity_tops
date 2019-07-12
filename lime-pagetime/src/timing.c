#include "lime.h"
#include "timing.h"
#include <linux/types.h>

struct file * filp = NULL;
ktime_t tp_start;

void init_time(void){
    tp_start = ktime_get();
}


int open_timing_file(char *path){
    mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs(get_ds());
	strcpy(reusable_str, path);
	strcat(reusable_str, ".times");
	filp = filp_open(reusable_str, O_WRONLY | O_CREAT | O_TRUNC, 0444);
    set_fs(oldfs);
	if(IS_ERR(filp)) {
		return -1;
	}
    return 0;
}

int close_timing_file(void){
    if(filp)
        return filp_close(filp, NULL);
    return -1;
}

ktime_t get_relative_time(void){
    return ktime_sub(ktime_get(), tp_start);
}

void log_current_time(ptrdiff_t paddr, bool precise)
{
	ktime_t tp_current = get_relative_time();
	if(precise)
        LOG("[PTIME] 0x%016llx : %09lld\n", (u64)paddr, ktime_to_ns(tp_current));
	else
        LOG("[STIME] 0x%016llx : %09lld\n", (u64)paddr, ktime_to_ns(tp_current));	

	return;
}
