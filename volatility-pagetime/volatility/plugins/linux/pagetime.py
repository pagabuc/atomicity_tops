import bisect

class Pagetime():
    def __init__(self, filename):
        self.cache = dict()
        
        # Sampled Timings
        self.stimes = []

        # Precise Timings
        self.ptimes = dict()
        self.pbisect = []

        self.total_time = 0
        self.precise_time = 0

        self.timeline = []

        # Here we append all the timings..
        f = open(filename, 'r')
        for line in f.readlines():
            if line.startswith("[STIME]"):
                line = line[len("[STIME]"):]
                data = line.split(" : ")
                offset = long(data[0], 16)
                time = long(data[1], 10)
                # assert(offset not in self.stimes)
                self.stimes.append((offset, time))
                continue
            
            if line.startswith("[PTIME]"):
                line = line[len("[PTIME]"):]
                data = line.split(" : ")
                offset = long(data[0], 16)
                time = long(data[1], 10)
                self.ptimes[offset] = time
                continue
            
            if line.startswith("[END]"):
                line = line[len("[END]"):]
                self.total_time = long(line, 10)
                continue
            
            if line.startswith("[PEND]"):
                line = line[len("[PEND]"):]
                self.precise_time = long(line, 10)
                continue
            
        f.close()
        
        self.pbisect.sort()
        # for offset,time in self.ptimes.items():
        #     print "P: 0x%012x %f" % (offset, time/float(1e9))

        # for offset,time in self.stimes:
        #     print "S: 0x%012x %f" % (offset, time/float(1e9))

    def pagetime(self, addr):
        if addr is None:
            print "PAGETIME CALLED WITH NONE"
            return -1

        addr =  addr & (~4096+1)
        if addr in self.cache:
            return self.cache[addr]

        # If we have the precise timing, use it

        if self.precise_time != 0:
            if addr in self.ptimes:
                time = self.ptimes[addr]
                self.cache[addr] = time
                return time
            
        # Otherwise look for the closer one in stime
        e = min(self.stimes, key=lambda x:abs(x[0]-addr))
        self.cache[addr] = e[1]
        return e[1]

    def track(self, t):
        self.timeline.append(t)

    def empty_timeline(self):
        self.timeline = []

    def print_timebar(self, values, total_duration):
        step = float(total_duration)/80
        ticks = [0]*80
        for v in values:
            ticks[int(v/step)] += 1
            res = ""
            for x in range(80):
                if ticks[x]==0:
                    res+='-'
                elif ticks[x]>5:
                    res+='X'
                else:
                    res+='x'
        print '[%s]'%res
        
    def display(self):
        if len(self.timeline):
            mint = min(filter(None, self.timeline)) / float(1e9)
            maxt = max(self.timeline) / float(1e9)
        else:
            mint = 0
            maxt = 0
        tott = self.total_time  / float(1e9)
        pret = self.precise_time / float(1e9)
        status = "ATOMIC :-)" if maxt <= pret else "NON ATOMIC :-("
        below = sum(map(lambda x : x <= self.precise_time, self.timeline)) 
        above = len(self.timeline) - below
        print "min: %.4f | max: %.4f | window: %.4f | smart: %.4f | total: %.4f | status: %s" % (mint, maxt, maxt - mint, pret, tott, status)
        print "atomic: %d | not-atomic: %d | unique : %d" % (below, above, len(set(self.timeline)))
        self.print_timebar([i for i in self.timeline if i > 0], self.total_time)
