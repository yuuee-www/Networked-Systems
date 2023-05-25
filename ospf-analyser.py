#!/usr/bin/env python3

import sys
from scapy.all import *
import networkx as nx
from scapy.contrib.ospf import *


pcap_file = "cw2-stage1-trace.pcap"

if len(sys.argv) > 1:
  pcap_file = sys.argv[1]
  #print(pcap_file+"xxxxx")

class Link: # stub or transit
    def __init__(self, link_type, link_id, link_data, metric):
        self.link_type = link_type
        self.link_id = link_id
        self.link_data = link_data
        self.metric = metric
     
class LSA:
    def __init__(self, Type, LinkState_ID, AdvRoute, seq, info):
        self.Type = Type
        self.LinkState_ID = LinkState_ID
        self.AdvRoute = AdvRoute
        self.seq = seq
        if Type == 1: 
            self.links = info
        elif Type == 2:
            self.net_mask = info[0]
            self.attached_router_list = info[1]


lsa_router_lst = [] # type 1
lsa_network_lst = [] # type 2

# search all lsa in lsu，and update them to the latest
for pk in rdpcap(pcap_file):
    if pk.haslayer(OSPF_LSUpd):
        for lsa in pk[OSPF_LSUpd].lsalist:

            stored = 0
            for record in lsa_router_lst+lsa_network_lst:
                if lsa.type == record.Type and lsa.id == record.LinkState_ID and lsa.adrouter == record.AdvRoute:
                            stored = 1
                            break

            if lsa.type == 1: # LSA Type 1: OSPF Router LSA
                links = []
                for link in lsa.linklist:
                    links.append(Link(link.type,link.id,link.data,link.metric))
                if(stored == 1):
                    if lsa.seq > record.seq:
                        record.links = links
                else:
                    lsa1 = LSA(1,lsa.id,lsa.adrouter,lsa.seq,links)
                    lsa_router_lst.append(lsa1)

            elif lsa.type == 2:    # LSA Type 2: OSPF Network 
                info = [lsa.mask,lsa.routerlist]
                if(stored == 1):
                    if lsa.seq > record.seq:
                        record.net_mask, record.attached_router_list = info
                else:
                    lsa2 = LSA(2,lsa.id,lsa.adrouter,lsa.seq,info)
                    lsa_network_lst.append(lsa2)

# reconstruct the topo
tplt = "{0:<8}\t{1:<8}\t{2:<7}"
print(tplt.format("Link ID", "Metric", "Routers"))

for lsa1 in lsa_router_lst:
    for link in lsa1.links:
        if link.link_type == 2: # transit
            link_id = link.link_id # the ip of dr
            dr_id = -1
            id = lsa1.AdvRoute
            metric = link.metric

            for lsa2 in lsa_network_lst:
                # transit Only know dr's ip, don't know rid
                if link_id == lsa2.LinkState_ID: 
                    dr_id = lsa2.AdvRoute

            if(dr_id != id): # do not print when both routers are same
                print(tplt.format(str(link_id), str(metric), id+"-"+dr_id))
            
print(" ")
tplt1 = "{0:<15}\t{1:<20}\t{2:<12}\t{3:<5}"
print(tplt1.format("Stub ID", "Netmask", "Metric", "Advertising router"))
for lsa1 in lsa_router_lst:
    for link in lsa1.links:
        if link.link_type == 3: # stub
            print(tplt1.format(str(link.link_id), str(link.link_data), str(link.metric), str(lsa1.AdvRoute)))

        

