#!/usr/bin/python3

import sys, socket
from dnslib import DNSRecord
import time, signal

# Default hardcoded name and address of root NS
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.241"

def handler(signum, frame):
    raise AssertionError 


class Record:
    '''only the A type record'''
    def __init__(self, data, ttl):
        self.data = data
        self.ttl = ttl

def ask(query_name, ask_server):
    '''send a query and return the parsed response'''
    query = DNSRecord.question(query_name)
    packet = query.pack()
    if not isinstance(ask_server,str):
        ask_server = str(ask_server)
    cs.sendto(packet, (ask_server, 53))
    (response, _) = cs.recvfrom(512)
    response_parse = DNSRecord.parse(response)
    response_parse.header.set_rd(0)
    return response_parse

def add_cache(ar,name):
    records = []
    cnames = []
    if not isinstance(ar,list): # only one record, not iterable
        if ar.rtype == 1: # A type, ipv4
            records.append(Record(ar.rdata,ar.ttl))
        elif ar.rtype == 5: # cname
            cnames.append(Record(ar.rdata,ar.ttl))
    else:
        for e in ar:
            if e.rtype == 1: # A type, ipv4
                records.append(Record(e.rdata,e.ttl))
                Cache.update({str(e.rname):[Record(e.rdata,e.ttl)]})
            elif e.rtype == 5: # cname
                cnames.append(Record(e.rdata,e.ttl))

    if records:
        Cache.update({name:records})
        return None

    if not records: # not exists records of type A
        return cnames


def update_cache(t0, t1):
    delta_t = t1 - t0
    keys = []
    for k in Cache.keys():
        keys.append(k)
    for key in keys:
        if (Cache[key][0].ttl < delta_t):
            Cache.pop(key)


def receive_response(response):
    '''return the query status'''
    cnames=[]
    ns_lst=[]
    if response.header.rcode==0: # rcode = noerror
        if response.header.ar != 0: # the "additional" is not empty
            cnames = add_cache(response.ar,str(response.auth[0].rname))
        elif response.header.auth != 0:
            for e in response.auth:
                if str(e.rname) in Cache.keys():
                    ns_lst = []
                    break
                ns_lst.append(Record(e.rdata,e.ttl))

        if response.header.a !=0: # the "answer" is not empty
            cnames =add_cache(response.rr,str(response.rr[0].rname))
    return response.header.rcode, cnames, ns_lst
        
def name_cname_linker(name,cname):
    if cname in Cache.keys():
        Cache.update({name:Cache[cname]})

class Tracer:
    '''only the A type record'''
    def __init__(self, query_name):
        self.query_name = query_name
        self.previous_name = query_name
        self.current_query = query_name
        self.query_history = [query_name]
        self.skip = False
        self.is_ns = False
        self.is_cname = False 
        self.finish = False
        self.ask_server = ROOTNS_IN_ADDR
        self.results = []
        self.count = 0

    def trace(self):
        if type(self.current_query) != "str":
            self.current_query = str(self.current_query)

        self.previous_name = self.current_query
        if self.query_name in Cache.keys(): # directly return the final result
            print("Resolved name {0} to {1}".format(self.query_name, Cache[self.current_query][0].data))
            return 1

        if self.query_history[-1] != self.current_query:
            self.query_history.append(self.current_query)

        if self.is_ns and self.current_query in Cache.keys():
            self.ask_server = Cache[self.current_query][0].data
            self.current_query = self.query_history[-2]
            self.skip = True
            self.is_ns = False
            return self.trace()


        if self.is_cname and self.current_query in Cache.keys():
            name_cname_linker(self.query_history[-2],self.current_query)
            self.skip = True
            self.is_cname = False
            return self.trace()

        
        query_status = None
        if self.current_query in Cache.keys(): # directly return the final result
            if not self.is_ns:
                if self.is_cname:
                    self.finish = True
            else:
                #self.is_ns = False
                self.ask_server = Cache[self.current_query][0].data
                self.current_query = self.previous_name # ns finish, recover
            return self.trace()
                #return 0 # not finish

        known_zone_ips = None
        # add the root name server

        num = self.current_query.count(".")

        if self.skip:
            self.skip = False
            self.results.append("dig {0} +norecurse @{1}".format(self.current_query, self.ask_server))
            response = ask(self.current_query, self.ask_server)
            query_status, cnames, ns_lst = receive_response(response)
            if query_status != 0:
                print("there exist an error in {0} @{1}".format(self.query_name, self.ask_server))
                return -1 # -1:exists error, skip the next
            if cnames:
                self.is_cname = True
                if str(cnames[0].data) in Cache.keys():
                    name_cname_linker(self.current_query,cnames[0])
                    self.trace()
                self.current_query = cnames[0].data
            elif ns_lst:
                self.is_ns = True
                self.current_query = ns_lst[0].data
            
            self.trace()
        else:
            for i in range(num):
                # zone = zones[i] + "." + zone
                zone = self.current_query.split(".", i)[-1]
                if zone in Cache.keys():
                    known_zone_ips = Cache[zone]
                    break
                
            if known_zone_ips:
                for known_zone_ip in known_zone_ips:
                    self.ask_server = known_zone_ip.data
                    try:
                        signal.signal(signal.SIGALRM, handler)
                        signal.alarm(5)
                        response = ask(self.current_query, self.ask_server) # send a query and get the parsed response
                        signal.alarm(0)
                    except:
                        continue 
                    self.results.append("dig {0} +norecurse @{1}".format(self.current_query, self.ask_server))
                    query_status, cnames, ns_lst = receive_response(response)
                    if self.current_query in Cache.keys(): # directly return the final result
                            return self.trace()
                    if query_status == 0:
                        if cnames:
                            self.is_cname = True
                            if str(cnames[0].data) in Cache.keys():
                                name_cname_linker(self.query_history[-2],self.current_query)
                                self.is_cname = True
                            self.current_query = cnames[0].data
                            return self.trace()

                        elif ns_lst:
                            self.is_ns = True
                            self.current_query = ns_lst[0].data
                            return self.trace()
                        break # already got the valid response, do not need to use the next ip of the same zone
                if query_status !=0:
                    print("connection is time out, there is an error!!!")           
            else:
                self.ask_server = ROOTNS_IN_ADDR
                self.results.append("dig {0} +norecurse @{1}".format(self.current_query, self.ask_server))
                response= ask(self.current_query, self.ask_server)
                query_status, cnames, ns_lst = receive_response(response)
                if cnames:
                    self.is_cname = True
                    self.current_query = cnames[0].data
                elif ns_lst:
                    self.is_ns = True
                    self.current_query = ns_lst[0].data
                
                return self.trace()
            
                

            if query_status!=0: # the case that the rcode of response message is not noerror
                print("there exist an error in {0} @{1}".format(self.query_name, self.ask_server))
                return -1 # -1:exists error, skip the next
            if self.is_cname and self.finish:
                print("Resolved name {0} to {1}".format(self.query_name, Cache[self.current_query][0].data))
                return 1

            return self.trace()

    def print_info(self):
        for result in self.results:
            print(result)
        print("")


if __name__ == "__main__":

    # Create a client socket on which to send requests to other DNS servers
    cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Read name to be resolved from stdin
    if len(sys.argv) < 2:
        print("usage: {} [-r <DNS_root_IP_address>] <names_to_resolve>".format(sys.argv[0]))
        sys.exit()
    # support specification of custom DNS root IP address via option -r
    if sys.argv[1] == "-r":
        ROOTNS_IN_ADDR = sys.argv[2]
        name_to_resolve = sys.argv[3:]
    else:
        name_to_resolve = sys.argv[1:]
    names = name_to_resolve

    # initalize an empty cache
    Cache = {}

    t0 = time.time()    # the start time
    for name in names:
        if (name[-1] != "."):
            name += "."
        tracer = Tracer(name)
        try:
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(35)
            result = tracer.trace()
            if result!=-1:
                tracer.print_info()
            t1 = time.time()
            update_cache(t0, t1)
            signal.alarm(0)
        except:
            print("connection is time out, cannot resolve "+name)
            print("")
            continue 




    
    




