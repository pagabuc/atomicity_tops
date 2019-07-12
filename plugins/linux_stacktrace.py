import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import struct
import sys
import os
import hashlib
sys.path.append(".")
import volatility.plugins.linux.pagetime as Pagetime

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import bisect

target_task = "bzip2"

def mask_page(addr):
    return (addr >> 12) << 12

class linux_stacktrace(linux_common.AbstractLinuxCommand):

    # ====================== INIT ====================== #
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self.total_time = 0
        self.funcs = dict()
        self.patches = dict()
        self.task_space = None
        self.task = None
        self.stack_file_location = config.LOCATION.replace('file://', '') + '.stack'
        self.stack_patches = dict()
        self.registers = dict()
        
    def render_text(self, outfd, data):
        return

    def read_kernel(self, offset):
        return struct.unpack("<Q", self.addr_space.zread(offset, 8))[0]

    def read_task(self, offset):
        return struct.unpack("<Q", self.task_space.zread(offset, 8))[0]

    def load_elf_functions(self, econtent):
        elf = ELFFile(econtent)            
        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                self.funcs[sym['st_value']] = sym.name

    def load_stack_info(self):
        stack_file = open(self.stack_file_location, "r+")
        file_size =  os.stat(self.stack_file_location).st_size
        while stack_file.tell() != file_size:
            met_addr = struct.unpack("<Q", stack_file.read(8) )[0]
            count = struct.unpack("<I", stack_file.read(4) )[0]
            rbp = struct.unpack("<Q", stack_file.read(8) )[0]
            rsp = struct.unpack("<Q", stack_file.read(8) )[0]
            rip = struct.unpack("<Q", stack_file.read(8) )[0]
            self.stack_patches[met_addr] = list()
            self.registers[met_addr] = (rbp, rsp, rip)
            if count > 500:
                break
            for i in range(count):
                paddr = struct.unpack("<Q", stack_file.read(8) )[0]
                vaddr = struct.unpack("<Q", stack_file.read(8) )[0]
                content = stack_file.read(4096)
                self.stack_patches[met_addr].append((paddr, vaddr, content))

        # for met_addr in self.stack_patches.keys():
        #     print "0x%012x %5f" % (met_addr, self.addr_space.pagetime(met_addr) / float(1e9))
        #     for (paddr, vaddr, content) in self.stack_patches[met_addr]:
        #         print " 0x%09x 0x%016x vaddr %s" % (paddr,vaddr, hashlib.md5(content).hexdigest())

    def dump_task_stack(self):
        vaddrs = set()
        for met_addr in self.stack_patches.keys():
            for (paddr, vaddr, content) in self.stack_patches[met_addr]:
                vaddrs.add((vaddr,paddr))
        stack = []
        times = []
        for (vaddr,paddr) in sorted(list(vaddrs))[::-1]:
            print hex(vaddr), self.task_space.vtop(vaddr - 200)
            content = self.task_space.read(vaddr-4096, 4096)
            # assert(len(content) == 4096)
            if content is None:
                content = ""
            digest = hashlib.md5(content).hexdigest() 
            addr_time = self.task_space.pagetime(paddr) / float(1e9)
            print "0x%012x 0x%016x %3.5f\t%s" % (paddr, vaddr, addr_time, digest)
            stack.append((paddr, vaddr, content))
            times.append(self.task_space.vpagetime(vaddr-4096))

        print "-"*30
        print "Number of stack pages is %d" % len(times)
        print "Dumping stack pages took %5f" % ((max(times) - min(times))/float(1e9))
        print "-"*30
        return stack
    
    def apply_stack_info(self, current_stack):
        for (paddr, vaddr, content) in current_stack:
            a = self.task_space.write(vaddr - 4096, content)
        
    # XXX: min of the postive difference between x and addr
    def addr_to_function(self, addr):
        sorted_addrs = sorted(self.funcs.keys())
        i = bisect.bisect_right(sorted_addrs,addr)
        return self.funcs[sorted_addrs[i-1]]

    # Returns the function name so we know when to stop
    def print_frame_info(self, frame_beg, frame_end, ip, i, print_times):
        # if ip == 0x0000000000418772:
        #     print "FIXX"
        #     frame_end = 0x00007ffc734b9790
            
        func = self.addr_to_function(ip)
        frame_size = frame_beg - frame_end + 8
        
        frame_beg_time = self.task_space.vpagetime(frame_beg) / float(1e9)
        frame_end_time = self.task_space.vpagetime(frame_end) / float(1e9)
        frame_beg_page = self.task_space.vtop(frame_beg) or -1
        frame_end_page = self.task_space.vtop(frame_end) or -1
        warning = "<--#" if frame_beg_time != frame_end_time else ""

        # if func in ["sendMTFValues", "BZ2_blockSort"]:
        #     import IPython
        #     IPython.embed()
            
        frame_content = self.task_space.read(frame_end, frame_size)
        if frame_content:
            frame_hash = hashlib.md5(frame_content).hexdigest()
        else:
            frame_hash = "CORRUPTED"
 
        # If the frame is splitted in two pages, we calculate the hash of the two parts.            
        line = "#%3d 0x%016x in %20s size: %4d " % (i, ip, func, frame_size)
        line += "start: 0x%012x end: 0x%012x " % (frame_beg_page, frame_end_page)
        if not print_times:
            frame_beg_time = 0
            frame_end_time = 0
            
        line += "[%9f %9f] " % (frame_beg_time, frame_end_time)
        line += "0x%016x 0x%016x " % (frame_beg, frame_end)
        line += "%s " % frame_hash[:9]
        line += "%s " % warning

        if frame_hash == "CORRUPTED":
            print line
            return 0
        
        if warning:
            ptr = frame_end
            first_part_size  = 0xfff - (frame_end & 0xfff) + 1
            second_part_size = (frame_beg & 0xfff) + 8
            first_part = self.task_space.read(ptr, first_part_size)
            ptr += first_part_size
            # print "FPTR",hex(ptr)," ", first_part_size
            middle_part = ""
            if (first_part_size + second_part_size) != frame_size: # There's a full page in the middle
                middle_part = self.task_space.read(ptr, 4096)
                ptr+= 4096
                # print "MPTR",hex(ptr), " 4096"

            second_part = self.task_space.read(ptr, second_part_size)
            ptr+=second_part_size
            
            # print "SPTR",hex(ptr)," ", second_part_size
            
            assert(ptr == frame_beg + 8)
            
            first_hash = hashlib.md5(first_part).hexdigest()
            line += "%s " % (first_hash[:9])
            if middle_part:
                middle_hash = hashlib.md5(middle_part).hexdigest()
                line += "%s " % (middle_hash[:9])
            second_hash = hashlib.md5(second_part).hexdigest()
            line += "%s " % (second_hash[:9])
            
        print line
        
        return func

    def find_task(self, taskname):
        init_task_addr = self.addr_space.profile.get_symbol("init_task")
        init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)
        found = 0
        for task in init_task.tasks:
            if task.comm == taskname:
                found = 1
                break
            
        if not found:
            print "[-] Task %s not found" % target_task
            sys.exit(-1)
        return task
    
    def do_stack_trace(self, rbp=0, rsp=0, rip=0, print_times=1):
        # target_task = "stacktrace"
        elf = open("/tmp/%s" % target_task)

        self.load_elf_functions(elf)
        # self.task_space.pt.empty_timeline()

        # SP0 points to the top of the kernel stack thread stack
        # (where the register are saved, in a struct pt_regs).
        sp0_vaddr  = self.task.thread.sp0 

        if rbp == 0:
            rbp = self.read_kernel(sp0_vaddr - 136)
            rsp = self.read_kernel(sp0_vaddr - 16)
            rip = self.read_kernel(sp0_vaddr - 40)
            rbp_time = self.addr_space.vpagetime(sp0_vaddr - 136)
            print "rbp collected at %5f" % (rbp_time / float(1e9))
            print "rbp stack delta: %5f" % ((rbp_time - self.task_space.vpagetime(rbp)) / float(1e9))
        print "RBP = 0x{:016x}".format(rbp)
        print "RSP = 0x{:016x}".format(rsp)
        print "RIP = 0x{:016x}".format(rip)

        #  From 'arch/x86/include/asm/ptrace.h': rbp is not always
        #  saved in pt_regs. But in the __syscallX routines of musl:
        #  rbp is always equal to rsp, so we can use the latter.
        if "__syscall" in self.addr_to_function(rip):
            rbp = rsp
            
        i = 0        
        frame_beg = rbp + 8
        frame_end = rsp 
        func = self.print_frame_info(frame_beg, frame_end, rip, i, print_times)
        ret = 1
        i+=1
        stack_physical_pages = set()
        stack_physical_pages.add(mask_page(self.task_space.vtop(frame_beg)))
        stack_physical_pages.add(mask_page(self.task_space.vtop(frame_end)))
        if frame_beg - frame_end > 4096:
            stack_physical_pages.add(mask_page(self.task_space.vtop(frame_end + 4096)))
            
        while func != "main" and ret != 0:
            ret = self.read_task(rbp+8)
            new_rbp = self.read_task(rbp)

            frame_beg = new_rbp + 8
            frame_end = rbp + 16

            func = self.print_frame_info(frame_beg, frame_end, ret, i, print_times)
            if func == 0:
                return stack_physical_pages

            rbp = new_rbp
            i+=1
            stack_physical_pages.add(mask_page(self.task_space.vtop(frame_beg)))
            stack_physical_pages.add(mask_page(self.task_space.vtop(frame_end)))
            if frame_beg - frame_end > 4096:
                stack_physical_pages.add(mask_page(self.task_space.vtop(frame_end + 4096)))

            if i>500:
                break
        return stack_physical_pages
    
    def calculate(self):
        linux_common.set_plugin_members(self)
        self.task = self.find_task(target_task)
        self.task_space = self.task.get_process_address_space()
        self.load_stack_info()
        
        print "######## STACK STATUS FROM DUMP"
        # original_stack = self.dump_task_stack()
        # print "######## STACK TRACE FROM DUMP"
        self.task_space.pt.empty_timeline()
        stack_physical_pages = self.do_stack_trace(print_times=1)

        # print "####### STACK TRACE WITH ATOMIC KERNEL STACK ", 
        # for (p,v,c) in original_stack[::-1]:
        #     if p in stack_physical_pages:
        #         break

        # first_stack_page = p
        # print "OF PAGE 0x%12x" % first_stack_page
        # (rbp, rsp, rip) = self.registers[first_stack_page]
        # self.do_stack_trace(rbp, rsp, rip, 0)
        
        # for met_addr in stack_physical_pages:
        #     print "######## 0x%09x %5f" % (met_addr, self.addr_space.pagetime(met_addr)/float(1e9))
        #     current_stack = self.stack_patches[met_addr]
        #     self.apply_stack_info(current_stack)
        #     (rbp, rsp, rip) = self.registers[met_addr]
        #     self.do_stack_trace(rbp, rsp, rip, 0)
        #     # self.dump_task_stack()

        # # Restore the stack 
        # self.apply_stack_info(original_stack)
