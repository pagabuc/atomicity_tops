import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.mount as linux_mount
import volatility.plugins.linux.cpuinfo as linux_cpuinfo
import struct
import cProfile
import sys

class linux_validate_vmas(linux_common.AbstractLinuxCommand):

    # ====================== INIT ====================== #
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        
    def render_text(self, outfd, data):
        return

    def get_task_list(self):
        init_task = obj.Object("task_struct",
                               vm = self.addr_space,
                               offset = self.addr_space.profile.get_symbol("init_task"))
        
        return [init_task] + list(init_task.tasks)

    def calculate(self):
        linux_common.set_plugin_members(self)
        # self.validate_task_list()
        self.validate_vmas()

    def validate_task_list(self):
        print "\n[+] Task list validation"

        tasks = self.get_task_list()
        for t in tasks:
            # print("Task %16s at memory 0x%016x" % (t.comm, self.addr_space.vtop(t.obj_offset)))
            if t.real_parent not in tasks:
                print "%15s %d real_parent (was %s %d) not in tasks_list" % (t.comm, t.pid,
                                                                             t.real_parent.comm, t.real_parent.pid)
            if t.parent not in tasks:
                print "%15s %d parent (was %s %d) not in tasks_list" % (t.comm, t.pid,
                                                                        t.parent.comm, t.parent.pid)
            if t.group_leader not in tasks:
                print "%15s %d group_leader (was %s %d) not in tasks_list" % (t.comm, t.pid,
                                                                              t.group_leader.comm, t.group_leader.pid)
            for child in t.children.list_of_type("task_struct", "sibling"):
                if child not in tasks:
                    child_time = self.addr_space.pagetime(self.addr_space.vtop(child.obj_offset))
                    task_time  = self.addr_space.pagetime(self.addr_space.vtop(t.obj_offset))
                    print "[-] Child of %s %d %.2f (was %s %d %.2f) not in tasks_list" % (t.comm, t.pid, task_time/float(1e9),
                                                                                          child.comm, child.pid, child_time/float(1e9))
                    
    def validate_vmas(self):
        print "\n[+] VMAs validation"

        tasks = self.get_task_list()
        for task in tasks[::-1]:
            if not task.mm:
                continue

            list_len = len(list(task.get_proc_maps()))
            rb_len = len(list(task.get_proc_maps_rb()))
            count = task.mm.m('map_count')
            
            if list_len == 0:
                continue
            if list_len != count or rb_len != count:
                print "ERR %s (%4d) vma_list = %d vma_rb = %d vma_counter = %d" % (task.comm, task.pid,
                                                                     list_len, rb_len, count)
            # else:
            #     print "OK  %15s (%5d) list = %d rb = %d counter = %d" % (task.comm, task.pid,
            #                                                             list_len, rb_len, count)                     
