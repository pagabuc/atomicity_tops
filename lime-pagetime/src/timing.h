#ifndef __TIMING_H_
#define __TIMING_H_

extern struct file * filp;

int open_timing_file(char *path);
int close_timing_file(void);
ktime_t get_relative_time(void);
void init_time(void);
void log_current_time(ptrdiff_t paddr, bool precise);

#define LOG(fmt, args...) do {                                          \
        mm_segment_t oldfs;                                             \
        oldfs = get_fs();                                               \
        set_fs(get_ds());                                               \
        snprintf(reusable_str, STRLEN, fmt, ## args);                   \
        vfs_write(filp, reusable_str, strlen(reusable_str), &filp->f_pos); \
        set_fs(oldfs);                                                  \
    } while(0)

#endif //__TIMING_H_
