# your Python code to implement the features could be placed here
# note that you may use any language, there is no preference towards Python

import sys,os
import re
import datetime
import heapq

class Window:
    def __init__ (self, size):
       self.accesses  = [0] * size
       self.accesses_total= 0
       self.startindex = None   # current start index of window
       self.endindex = None   # current end index of window
       self.size = size
       self.window_heap = []
       self.window_heap_size= 0
       self.window_heap_smallest= None
       self.one_second= datetime.timedelta(seconds=1)

    def print_mostactive(self, hoursfile):
        for i in range(min(10,len(self.window_heap))):
            busywindow = heapq.heappop(self.window_heap)
            hoursfile.write("{} -0400,{}\n".format( busywindow[1].strftime("%d/%b/%Y:%H:%M:%S"), -busywindow[0]))

    def nextindex(self):
        return (self.endindex + 1) % self.size

    def is_full(self): #returns true if all 3600 slots have been filled
                       # once full, it styas full
        return self.nextindex() == self.startindex

    def add_to_queue(self, timestamp, access_count):
        if self.window_heap_size < 10:
            heapq.heappush(self.window_heap, (-access_count,timestamp))
            self.window_heap_size += 1
            if self.window_heap_smallest is None:
                self.window_heap_smallest= access_count
            else:
                self.window_heap_smallest= min(access_count,self.window_heap_smallest)
        else: # heap already contains 10 windows so put a new one only if it has
              # a higher accesscount than the smallest one in the heap
             if access_count <= self.window_heap_smallest:
                 return   #no need to add this to heap
             heapq.heappush(self.window_heap, (-access_count,timestamp))

    def shift(self): #if the window is full then add  to heap
                     #   and shift window start right by one second
                     #shift window end right by one second
        if self.is_full():
            self.add_to_queue(self.start_timestamp, self.accesses_total)
            self.accesses_total -= self.accesses[self.startindex]
            self.startindex = (self.startindex+1) % self.size
            self.start_timestamp += self.one_second
        self.endindex = (self.endindex+1) % self.size
        self.end_timestamp += self.one_second

    def record_access(self, timestamp):
        if self.startindex is None: #meaning this is the first valid entry in log
            self.startindex = 0
            self.start_timestamp = timestamp
            self.endindex = 0
            self.end_timestamp = timestamp
            self.accesses[self.startindex] = 1
            self.accesses_total = 1
        elif (timestamp - self.end_timestamp).total_seconds() == 0:
            # the new log entry has the same time stamp as the previous entry
            self.accesses[self.endindex] += 1 # increment access count
            self.accesses_total += 1 # increment total access count
        else: # new time stamp is later than last time stamp
            time_increment  = int((timestamp - self.end_timestamp).total_seconds())
            for increment in range(time_increment):
                self.shift()
            self.accesses[self.endindex] = 1
            self.accesses_total += 1

    def postprocess(self): # at the end push remaining windows on heap
          while self.startindex != self.endindex:
              heapq.heappush(self.window_heap, (-self.accesses_total,self.start_timestamp))
              self.accesses_total -= self.accesses[self.startindex]
              self.startindex = (self.startindex+1) % self.size
              self.start_timestamp += self.one_second
          self.add_to_queue(self.start_timestamp, self.accesses_total)


class Security:
    def __init__(self):
        self.blocked_hosts= {}  # dictionary of hosts blocked due to 3 failed logins. The value stored
                       # in the dictionary is the end of block
        self.monitored_hosts = {} # dictionary of hosts that have had 1 or 2 failed logins. The value stored is
                         # an array of timestamps. The array can have exactly one or two elements containing
                         #  and contains time of failed login + 20 seconds
    def is_blocked(self, host, timestamp):
        if not host in self.blocked_hosts:
            return False
        #if block window expired, remove block
        #otherwise print line to blocked file
        if timestamp > self.blocked_hosts[host]:
            del self.blocked_hosts[host]
        return True

    def process_login(self, host, httpcode, timestamp):
        if httpcode == '200' :   #successful login
            if host in self.blocked_hosts: #remove
                del self.blocked_hosts[host]
            elif host in self.monitored_hosts: # a
                del self.monitored_hosts[host]
        elif httpcode == '401' :   #unauthorized login
            #assuming these are the only 2 codes returned #for logins
            if host in self.monitored_hosts:
                if len(self.monitored_hosts[host])==1:  #one failed attempt
                    if timestamp >= self.monitored_hosts[host][0]:
                        self.monitored_hosts[host]= [timestamp + datetime.timedelta(seconds=20)]
                    else:
                        self.monitored_hosts[host].append(timestamp + datetime.timedelta(seconds=20))
                else: # two past failed attempts
                    if timestamp < self.monitored_hosts[host][0]: #3rd fail in 20 seconds
                        self.blocked_hosts[host] = timestamp + datetime.timedelta(minutes=30)
                        del self.monitored_hosts[host]
                    elif timestamp < self.monitored_hosts[host][1]: #2nd fail in 20 seconds
                        self.monitored_hosts[host]= [self.monitored_hosts[host][1],timestamp + datetime.timedelta(seconds=20)]
                    else: #1st fail in 20 seconds
                        self.monitored_hosts[host]= [timestamp + datetime.timedelta(seconds=20)]
            else: #add this hot to monitored_hosts
                self.monitored_hosts[host]= [timestamp + datetime.timedelta(seconds=20)]




def process_logfile(log, hostfile, resourcefile, hoursfile, blockedfile):
    requests_by_host= {}  # dictionary of number of accesses by host
    
    resources= {}
    window= Window(3600) # window size is 1 hour in seconds
    security= Security()
    for line in log:
        parsed= re.search("(\S+)[\s\-]+\[(\S+).*]\s+\"(.+)\"\s+(\d+)\s+(\d+|-)",line)
        if not parsed:
            continue
        host = parsed.group(1)
        try:
            timestamp = datetime.datetime.strptime(parsed.group(2),"%d/%b/%Y:%H:%M:%S")
        except ValueError:
            continue
        if host in requests_by_host:
            requests_by_host[host]+=1 
        else: 
            requests_by_host[host]=1
        request = parsed.group(3)
        temp = request.split()
        if(len(temp)> 1):
            resource= temp[1]
        else:
            resource= None
        httpcode = parsed.group(4)
        bytes = parsed.group(5)
        if bytes == '-':
            bytes = 0
        else: 
            bytes = int(bytes)
        if resource:
            if resource in resources:
                resources[resource]+= bytes
            else: 
                resources[resource]= bytes
        window.record_access(timestamp)
        # process failed login logic below
        if security.is_blocked(host, timestamp):
            blockedfile.write(line)
            continue
        if resource == '/login':
            security.process_login(host, httpcode, timestamp)
 
    window.postprocess()
    window.print_mostactive(hoursfile)
    requests_heap = []
    for (host, count) in requests_by_host.items():
        heapq.heappush(requests_heap, (-count,host))
    for i in range(min(10,len(requests_heap))):
        busyhost= heapq.heappop(requests_heap)
        hostfile.write("{},{}\n".format(busyhost[1], -busyhost[0]))

    resources_heap = []
    for (resource, bytes) in resources.items():
        heapq.heappush(resources_heap, (-bytes,resource))
    for i in range(min(10,len(resources_heap))):
        busyresource= heapq.heappop(resources_heap)
        resourcefile.write("{}\n".format(busyresource[1]))


# Main() starts here

if  len(sys.argv) !=  6:
    print "Usage:"
    print "process_log.py <log> <hosts> <hours> <resources> <blocked>"
    sys.exit()
else:
    print "log " + sys.argv[1]
    print "hosts " + sys.argv[2]
    print "hours " + sys.argv[3]
    print "resources " + sys.argv[4]
    print "blocked " + sys.argv[5]

try:
    log= open(sys.argv[1])
    hostfile= open(sys.argv[2],"w")
    hours= open(sys.argv[3],"w")
    resources= open(sys.argv[4],"w")
    blocked= open(sys.argv[5],"w")
except IOError:
    print "Could not open at least one of the input or output files"
    sys.exit()
process_logfile(log,hostfile,resources, hours, blocked)

