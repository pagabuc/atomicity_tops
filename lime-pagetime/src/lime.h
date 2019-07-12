/*
 * LiME - Linux Memory Extractor
 * Copyright (c) 2011-2014 Joe Sylve - 504ENSICS Labs
 *
 *
 * Author:
 * Joe Sylve       - joe.sylve@gmail.com, @jtsylve
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

#ifndef __LIME_H_
#define __LIME_H_

#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/pfn.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/time.h>

#include <net/sock.h>
#include <net/tcp.h>

#include <linux/types.h>

#define LIME_RAMSTR "System RAM"
#define LIME_MAX_FILENAME_SIZE 256
#define LIME_MAGIC 0x4C694D45 //LiME

#define LIME_MODE_RAW 0
#define LIME_MODE_LIME 1
#define LIME_MODE_PADDED 2

#define LIME_METHOD_UNKNOWN 0
#define LIME_METHOD_TCP 1
#define LIME_METHOD_DISK 2

#define STRLEN 256
#define MAX_PAGE_MAPPED 2048
#define TP_DELTA 100000

// This is enough to cover ~16GB of memory. 
#define BITMAP_SIZE 4194304


#ifdef LIME_DEBUG
#define DBG(fmt, args...) do { printk("[LiME] "fmt"\n", ## args); } while (0)
#else
#define DBG(fmt, args...) do {} while(0)
#endif

//structures

typedef struct {
    unsigned int magic;
    unsigned int version;
    unsigned long long s_addr;
    unsigned long long e_addr;
    unsigned char reserved[8];
} __attribute__ ((__packed__)) lime_mem_range_header;


// variables
extern int method;
extern char reusable_str[256];
extern char zero_page[PAGE_SIZE];;
extern int collisions;
extern struct page *pages[MAX_PAGE_MAPPED];

extern DECLARE_BITMAP(bitmap, BITMAP_SIZE);
#define RETRY_IF_INTURRUPTED(f) ({ \
    ssize_t err; \
    do { err = f; } while(err == -EAGAIN || err == -EINTR); \
    err; \
})

#endif //__LIME_H_


