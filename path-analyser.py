from scapy.all import *
import networkx as nx
#import matplotlib.pyplot as plt

def AND(ip_address, mask):
    ip_address_binary = ''.join([bin(int(x)+256)[3:] for x in ip_address.split('.')])
    mask_binary = ''.join([bin(int(x)+256)[3:] for x in mask.split('.')])
    gateway_binary = ''.join([str(int(ip_address_binary[i]) & int(mask_binary[i])) for i in range(len(ip_address_binary))])
    gateway = '.'.join([str(int(gateway_binary[i:i+8], 2)) for i in range(0, 32, 8)])
    return gateway

def build_topo(lsdb_file):
    G = nx.Graph()
    lsdb = open(lsdb_file, "r")	
    while True:
        lsa = lsdb.readline()
        if lsa:
            lsa = lsa.split()
            if lsa == []:
                continue
            if (lsa[0] == "Link" or lsa[0] == "Stub"):
                continue

            if (len(lsa) == 3):

                #continue
                link_id = lsa[0]
                metric = int(lsa[1])
                r_id1 = "rid_" + lsa[2].split('-')[0]
                r_id2 = "rid_" + lsa[2].split('-')[1]
                if G.has_edge(r_id1, r_id2):
                    if G[r_id1][r_id2]["weight"] > metric:
                        G.add_edges_from([(r_id1, r_id2, {"weight": metric})])
                        attrs = {(r_id1, r_id2): {"Link_ID": link_id}}
                        nx.set_edge_attributes(G, attrs)
                else:
                    G.add_edges_from([(r_id1, r_id2, {"weight": metric})])
                    attrs = {(r_id1, r_id2): {"Link_ID": link_id}}
                    nx.set_edge_attributes(G, attrs)

            if (len(lsa) == 4):         # subset
                break
        else:
            break
    lsdb.close()
    return G

# Add routing information
def add_route_info(G,lsdb_file):
    lsdb = open(lsdb_file, "r")	
    lines = lsdb.readlines()
    for lsa in lines:
        if lsa:
            lsa = lsa.split()
            if (len(lsa) == 4):
                if (lsa[0] == "Link"):
                    continue
                r_id = "rid_" + lsa[3] 
                metric = int(lsa[2]) 
                subnet = lsa[0] + "/" + lsa[1]     # link id / mask
                G.add_edge(subnet, r_id, weight=metric)
    lsdb.close()
    return G


def find_paths(G, src, dst):
    if (src[0] != 'r'):
        src = "rid_" + src
    if (dst[0] != 'r'):
        dst = "rid_" + dst
    paths = []
    all_shortest_paths = nx.all_shortest_paths(G, source=src, target=dst, weight='weight')
    for path in all_shortest_paths:
        temp = []
        for r_id in path:
            temp.append(r_id.split("_")[1])
        paths.append(temp)
    return paths

def check_path(paths,path):
    if path in paths:
        return True
    else:
        return False



def traceroute(G,src_rid, dst_ip):
    end_node = 0
    # step1: check if the route for the dst_ip is available
    gateway = -1
    for node in list(G.nodes()):
        if node[0] == 'r':
            continue
        mask = node.split("/")[1]
        if(AND(dst_ip,mask) == node.split("/")[0]):
            gateway = node.split("/")[0]
            end_node = node
            break
    if (gateway == -1):
        return False
    # step2: find the shortest paths
    start_node = "rid_" + src_rid
    all_shortest_paths = nx.all_shortest_paths(G, source=start_node, target=end_node, weight='weight')
    paths = []
    for path in all_shortest_paths:
        temp = []
        for r_id in path[:-1]:
            temp.append(r_id.split("_")[1])
        temp.append(path[-1])
        paths.append(temp)
    return paths


# def find_stub(G,rid):
#     router_node = "rid_" + rid
#     for n in G.neighbors(router_node):
#         if n[0] != "r":
#             stub = n
#             return stub

        
def path2gateway(G,paths):
    paths_gateway = []
    for path in paths:
        temp = []
        for i in range(len(path)-2):
            link = G.edges["rid_"+path[i], "rid_"+path[i+1]]["Link_ID"]
            temp.append(link)
        temp.append(path[-1].split("/")[0])
        paths_gateway.append(temp)
    return paths_gateway



def check_traceroute(traceroute,IPs_lst):
    check = False
    network_mask = "255.255.255.0"
    for IPs in IPs_lst:
        if len(IPs) == len(traceroute):
            check = True
            for i in range(len(IPs)-1):
                if AND(IPs[i],network_mask) != AND(traceroute[i],network_mask):
                    check = False
    return check


# def show_graph(G):
#     pos = nx.shell_layout(G)
#     nx.draw(G, pos, node_size=100, with_labels=True, connectionstyle='arc3, rad = 0.1')
#     #edge_labels = nx.get_edge_attributes(G, 'Link_ID')
#     #nx.draw_networkx_edge_labels(G, pos, edge_labels)
#     plt.show()



def check_router_exists(path,G):
    for p in path:
        p = "rid_" + p
        if (p not in list(G.nodes)):
            return False
    return True



def check_path_file(path_file,G):
    file = open(path_file, "r")	
    lines = file.readlines()
    for line in lines:
        line = line.split()
        start = line[1]
        end = line[-1]
        if check_router_exists(line[1:],G):
            correct_path = find_paths(G, start, end)
            check = check_path(correct_path,line[1:])
            print(line[0]+" "+str.lower(str(check)))
        else:
            print(line[0]+" "+"false")

    file.close()



def check_traceroute_file(traceroute_file,G):
    file = open(traceroute_file, "r")	
    lines = file.readlines()
    trace_buffer = []
    for line in lines:
        line = line.split()
        if line:
            if line[0]=="traceroute" and line[1] != "to":
                trace_buffer = []
                trace_buffer.append(line[1])
            elif line[0]=="source":
                trace_buffer.append(line[1])
            elif line[0]=="traceroute" and line[1] == "to":
                trace_buffer.append(line[3][1:-2])
            elif line[0] != "":
                trace_buffer.append(line[1])
        elif trace_buffer!=[]:
            source = trace_buffer[1]
            dst_ip = trace_buffer[2]
            paths = traceroute(G,source,dst_ip)
            IPs_lst = path2gateway(G,paths) 
            check = check_traceroute(trace_buffer[3:],IPs_lst)
            print(trace_buffer[0]+":"+" "+str.lower(str(check)))
            trace_buffer = []

    # the last group in the buffer
    source = trace_buffer[1]
    dst_ip = trace_buffer[2]
    paths = traceroute(G,source,dst_ip)
    IPs_lst = path2gateway(G,paths) 
    check = check_traceroute(trace_buffer[3:],IPs_lst)
    print(trace_buffer[0]+":"+" "+str.lower(str(check)))
    trace_buffer = []

if __name__ == "__main__":

    ospf_lsdb_file = "cw2-lsdb-model.txt"
    path_file = "cw2-stage2-paths.txt"
    traceroute_file = "cw2-stage2-traceroutes.txt"

    if len(sys.argv) > 3:
        ospf_lsdb_file = sys.argv[1]
        path_file = sys.argv[2]
        traceroute_file = sys.argv[3]


    G = build_topo(ospf_lsdb_file)
    G = add_route_info(G,ospf_lsdb_file)
    #show_graph(G)

    check_path_file(path_file,G)
    check_traceroute_file(traceroute_file,G)



    # test
    # show_graph(G)
    # paths = find_paths(G,"1.155.0.1", "1.152.0.1")
    # print(paths)
    # print(check_path(paths,["1.155.0.1", "1.158.0.1", "1.152.0.1"]))
    # print(traceroute(G,"1.155.0.1","1.102.0.1"))
    # IPs_lst = path2gateway(G,traceroute(G,"1.155.0.1","1.102.0.1"))
    # print(IPs_lst)
    # traceroute1 = ["1.0.11.2","1.0.7.1","1.102.0.1"]
    # print(check_traceroute(traceroute1,IPs_lst))