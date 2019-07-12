import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.mount as linux_mount
import volatility.plugins.linux.cpuinfo as linux_cpuinfo
import json
import struct
import cProfile
import sys
import os

class linux_acqtime_collect(linux_common.AbstractLinuxCommand):

    # ====================== INIT ====================== #
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)

        json_filename = config.LOCATION.replace('file://', '') + '.json'
        self.json_file = open(json_filename, 'w')
        self.json_objects = {}
        
    def render_text(self, outfd, data):
        return

    def calculate(self):
        linux_common.set_plugin_members(self)
        self.total_time = self.addr_space.pt.total_time
        self.test()
        self.collect_vmas()
        # self.collect_vmas_for_plot()
        self.collect_tasks()
        # self.collect_files()
        # self.collect_modules()
        
        # self.check_size()
        self.json_objects['total_time'] = self.total_time
        json.dump(self.json_objects, self.json_file)

    def test(self):
        init_task_addr = self.addr_space.profile.get_symbol("init_task")
        init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)
        for task in init_task.tasks:
            continue
            # print hex(task.obj_offset)
            # for f,fd in task.lsof():
            #     continue
            # for f in task.get_proc_maps():
            #     continue
        return

    def get_task_list(self):
        init_task_addr = self.addr_space.profile.get_symbol("init_task")
        init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)
        tasks = [init_task]
        for task in init_task.tasks:
            tasks.append(task)

        # import IPython
        # IPython.embed()

        return tasks
    
        
    def collect_tasks(self):        
        print "\n[+] Task collection"
        
        tasks = self.get_task_list()
        tasks_list = []
        
        for task in tasks:
            task_vaddr = task.obj_offset
            task_paddr = self.addr_space.vtop(task_vaddr)
            time = self.addr_space.pagetime(task_paddr)
            tasks_list.append({'comm': task.comm, 'vaddr': task_vaddr, 'paddr': task_paddr, 'time': time})

        # for e in tasks_list:
        #     print "%20s 0x%016x 0x%016x %f" % (e['comm'], e['vaddr'], e['page'], e['time'])
        e = tasks_list[0]
        print "First task: {0: <16} 0x{1:016x} {2:f}".format(e['comm'], e['vaddr'], e['time'])
        e = tasks_list[-1]
        print "Last task : {0: <16} 0x{1:016x} {2:f}".format(e['comm'], e['vaddr'], e['time'])


        tasks_min = min(tasks_list, key=lambda x: x['time'])
        tasks_max = max(tasks_list, key=lambda x: x['time'])
        tasks_min_time = tasks_min['time']
        tasks_max_time = tasks_max['time']
        print '{0: <16} 0x{1:012x} {2:.2f}'.format(tasks_min['comm'], tasks_min['paddr'], (tasks_min_time / float(1e9)))
        print '{0: <16} 0x{1:012x} {2:.2f}'.format(tasks_max['comm'], tasks_max['paddr'], (tasks_max_time / float(1e9)))

        print "Task collection took: %.2f (out of %d)" % ((tasks_max_time - tasks_min_time) / float(1e9), self.total_time / float(1e9))
        self.json_objects["tasks_list"] = tasks_list            

    def collect_files(self):
        print "\n[+] File collection"
        files_list = []

        tasks = self.get_task_list()
        for task in tasks:
            # if task.comm != "test":
            #     continue
            files_vaddr = task.files.dereference().m('fd_array').obj_offset            
            files_paddr = self.addr_space.vtop(files_vaddr)
            time_files = self.addr_space.pagetime(files_paddr)

            # fdt = task.files.fdt
            # fdt_time = self.addr_space.pagetime(self.addr_space.vtop(fdt))
            # file_tmp_time = self.addr_space.pagetime(self.addr_space.vtop(task.files))
            # fd = task.files.fdt.fd
            # fd_time = self.addr_space.pagetime(self.addr_space.vtop(fd))
            # print "FILES @ 0x%016x for %10s taken @ %f" % (task.files.obj_offset, task.comm, file_tmp_time/float(1e9))
            # print "FDT @ 0x%016x for %10s taken @ %f" % (fdt.obj_offset, task.comm, fdt_time/float(1e9))
            # print "FD @ 0x%016x for %10s taken @ %f" % (fd.obj_offset, task.comm, fd_time/float(1e9))

            # rdentry = task.fs.get_root_dentry()
            # rmnt    = task.fs.get_root_mnt()
            # print "rdentry @ 0x%016x for %10s taken @ %f" % (rdentry.obj_offset, task.comm,
            #                                                  self.addr_space.pagetime(self.addr_space.vtop(rdentry))/float(1e9))

            # print "rmnt    @ 0x%016x for %10s taken @ %f" % (rmnt.obj_offset, task.comm,
            #                                               self.addr_space.pagetime(self.addr_space.vtop(rmnt))/float(1e9))


            for f, fd in task.lsof():
                # dentry  = f.dentry
                # vfsmnt  = f.vfsmnt
                # print "dentry  @ 0x%016x for %10s taken @ %f" % (dentry.obj_offset, task.comm,
                #                                                  self.addr_space.pagetime(self.addr_space.vtop(dentry))/float(1e9))
                
                # print "vfsmnt  @ 0x%016x for %10s taken @ %f" % (vfsmnt.obj_offset, task.comm,
                #                                                  self.addr_space.pagetime(self.addr_space.vtop(vfsmnt))/float(1e9))

                time_file = self.addr_space.pagetime(self.addr_space.vtop(f.obj_offset))
                # time_files is when the files_struct was collected,
                # time_file when an element of fd_array was collected
                files_list.append({'comm': task.comm, #'time_files': time_files,
                                   'fd':fd, 'time_file':time_file })
        
        # for e in files_list:
        #     print "%15s %d %f" % (e['comm'], e['fd'], e['time_file']/float(1e9))

        files_min = min(files_list, key=lambda x: abs(x['time_file']) )
        files_max = max(files_list, key=lambda x: abs(x['time_file']) )
        files_min_time = files_min['time_file']
        files_max_time = files_max['time_file']
        print '{0: <16} (fd {1:d}) {2:.2f}'.format(files_min['comm'], files_min['fd'], (files_min_time / float(1e9)))
        print '{0: <16} (fd {1:d}) {2:.2f}'.format(files_max['comm'], files_max['fd'], (files_max_time / float(1e9)))
        # print '%16s (fd %d) %f' % (files_max['comm'], files_max['fd'], (files_max_time / float(1e9)))
        # print '%16s (fd %d) %f' % (files_min['comm'], files_min['fd'], (files_min_time / float(1e9)))
        print "File collection took: %.2f (out of %d)" % ((files_max_time - files_min_time) / float(1e9), self.total_time / float(1e9))
        self.json_objects["files_list"] = files_list
    
    
    def collect_modules(self):
        print "\n[+] Module collection"
        module_list = []
        modules_addr = self.addr_space.profile.get_symbol("modules")
        modules = obj.Object("list_head", vm = self.addr_space, offset = modules_addr)
        # walk the modules list
        for module in modules.list_of_type("module", "list"):
            module_vaddr = module.obj_offset            
            module_paddr = self.addr_space.vtop(module_vaddr)
            time_module = self.addr_space.pagetime(module_paddr)
            module_list.append({'name': str(module.name), 'vaddr': module_vaddr, 'paddr': module_paddr, 'time': time_module})
            
        # for e in module_list:
        #     print "%20s 0x%016x 0x%016x %f" % (e['name'], e['vaddr'], e['paddr'], e['time']/float(1e9))

        modules_max = max(module_list, key=lambda x: abs(x['time']) )
        modules_min = min(module_list, key=lambda x: abs(x['time']) )

        modules_max_time = modules_max['time']
        modules_min_time = modules_min['time']

        print '{0: <25} 0x{1:012x} {2:.2f}'.format(modules_min['name'], modules_min['paddr'], (modules_min_time / float(1e9)))
        print '{0: <25} 0x{1:012x} {2:.2f}'.format(modules_max['name'], modules_max['paddr'], (modules_max_time / float(1e9)))
        # print '%16s 0x%016x %f' % (modules_max['name'], modules_max['paddr'], (modules_max_time / float(1e9)))
        # print '%16s 0x%016x %f' % (modules_min['name'], modules_min['paddr'], (modules_min_time / float(1e9)))
        print "Module collection took: %.2f (out of %d)" % ((modules_max_time - modules_min_time) / float(1e9), self.total_time / float(1e9))

        self.json_objects["module_list"] = module_list

    def collect_vmas(self):
        print "[+] VMAs collection"
        tasks = self.get_task_list()
        vma_list = []        
        for task in tasks:
            # if task.pid < 1300:
            #     continue
            # if task.comm != "test":
            #     continue
            
            task_space = task.get_process_address_space()
            
            for vma in task.get_proc_maps():
                vma_name = vma.info(task)[0]
                vma_start = vma.vm_start
                vma_end = vma.vm_end
                    
                vma_paddr = self.addr_space.vtop(vma.obj_offset)
                time_vma_struct = self.addr_space.pagetime(vma_paddr)
                
                vma_start_phy = task_space.vtop(vma_start + 1) or 0
                time_vma_start = task_space.pagetime(vma_start_phy)
                # time_vma_end = self.addr_space.pagetime(task_space.vtop(vma_end - 4096))
                vma_list.append({'task_pid': int(task.pid), 'task_name': task.comm, 'vma_name': vma_name,
                                 'vaddr': vma.obj_offset, 'paddr': vma_paddr, 'time': time_vma_start})
                # print 'A {0: <20} {1: <55} 0x{2:016x} 0x{3:016x} {4:.5f}'.format(task.comm, vma_name,
                #                                                                  vma_start, vma_start_phy,
                #                                                                  time_vma_start / float(1e9))

        vmas_max = max(vma_list, key=lambda x: abs(x['time']) )
        vmas_min = min(vma_list, key=lambda x: abs(x['time']) )

        vmas_max_time = vmas_max['time']
        vmas_min_time = vmas_min['time']

        print '{0: <25} {1: <25} 0x{2:012x} {3:.5f}'.format(vmas_min['task_name'], vmas_min['vma_name'],
                                                            vmas_min['paddr'], (vmas_min_time / float(1e9)))
        print '{0: <25} {1: <25} 0x{2:012x} {3:.5f}'.format(vmas_max['task_name'], vmas_max['vma_name'],
                                                            vmas_max['paddr'], (vmas_max_time / float(1e9)))
        
        print "VMAs collection took: %.2f (out of %d)" % ((vmas_max_time - vmas_min_time) / float(1e9), self.total_time / float(1e9))


            
    def collect_vmas_for_plot(self):
        print "[+] VMAs collection for plot"
        tasks = self.get_task_list()
        vma_list = []        
        for task in tasks:
            print task.comm

            # if task.comm != "firefox":
            #     continue
            
            task_space = task.get_process_address_space()

            # interesting_inodes = []
            # for vma in task.get_proc_maps():
            #     if vma.vm_flags.is_readable() and vma.vm_flags.is_executable():
            #         e_type = struct.unpack("B", task_space.zread(vma.vm_start,0x16)[0x10])[0]
            #         # print "RW: ", vma.info(task)[0], e_type
            #         if e_type == 0x2: # 0x2 == executable
            #             inode = int(vma.info(task)[3])            
            #             interesting_inodes.append(inode)
                        
            for vma in task.get_proc_maps():
                vma_vaddr = vma.obj_offset            
                vma_paddr = self.addr_space.vtop(vma_vaddr)
                time_vma = self.addr_space.pagetime(vma_paddr)

                vma_name = vma.info(task)[0]
                vma_inode = int(vma.info(task)[3])
                vma_flags = str(vma.vm_flags)
                page_vaddr = vma.vm_start 
                interesting = False               
                # if (vma.vm_flags.is_writable() or
                #     vma_inode in interesting_inodes) or vma.vm_start == 0x400000:
                #     interesting = True                    
                filename = os.path.basename(vma_name)
                if (vma_name in ["[heap]","[stack]"] or filename[:16] == task.comm):
                    interesting = True

                # print ("%15s %80s %s 0x%016x - 0x%016x [%06x] %d" %
                #        (task.get_commandline(), vma_name, vma.vm_flags,
                #         vma.vm_start, vma.vm_end, (vma.vm_end - vma.vm_start), interesting))

                if vma.vm_start == 0 or not interesting:
                    continue

                pages = []

                while page_vaddr < vma.vm_end:
                    page_paddr = task_space.vtop(page_vaddr)

                    if page_paddr:
                        page_time = task_space.pagetime(page_paddr)
                        pages.append({'page_vaddr': int(page_vaddr),
                                      'page_paddr': int(page_paddr),
                                      'page_time' : page_time })

                    page_vaddr+=4096

                print "APPENDING: %s %s %d" % (task.comm, vma_name, len(pages))
                vma_list.append({'task_pid': int(task.pid), 'task_name': task.comm, 'vma_name': vma_name,
                                 'vaddr': vma_vaddr, 'paddr': vma_paddr, 'time': time_vma,
                                 'vma_flags': vma_flags , 'pages': pages})

            # for e in vma_list:
            #     print('%5s %35s %s 0x%016x -> 0x%016x (0x%016x) %.2f %d' %
            #           (e["task_name"], e["vma_name"], e["vma_flags"],
            #            e["page_vaddr"], e["page_paddr"], e['near_page'], e['time']/float(1e9), e['interesting'] ))

        self.json_objects["vma_list"] = vma_list
        return

                    
