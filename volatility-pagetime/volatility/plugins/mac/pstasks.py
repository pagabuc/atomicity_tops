# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""
import volatility.obj as obj
import volatility.plugins.mac.pslist as pslist
import volatility.plugins.mac.common as common

class mac_tasks(pslist.mac_pslist):
    """ List Active Tasks """
    def __init__(self, config, *args, **kwargs):
        pslist.mac_pslist.__init__(self, config, *args, **kwargs)

    def allprocs(self):
        common.set_plugin_members(self)
        tasksaddr = self.addr_space.profile.get_symbol("_tasks")
        queue_entry = obj.Object("queue_entry", offset = tasksaddr, vm = self.addr_space)

        seen = { tasksaddr : 1 }

        for task in queue_entry.walk_list(list_head = tasksaddr):
            if task.obj_offset not in seen:
                seen[task.obj_offset] = 0

                if task.bsd_info:
                    proc = task.bsd_info.dereference_as("proc") 
                    yield proc
            else:
                if seen[task.obj_offset] > 3:
                    break

                seen[task.obj_offset] = seen[task.obj_offset] + 1

