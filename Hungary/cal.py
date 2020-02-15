from collections import defaultdict
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.controller.handler import MAIN_DISPATCHER,CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
#https://github.com/Ehsan70/RyuApps/blob/master/TopoDiscoveryInRyu.md
from ryu.topology.api import get_switch,get_all_link,get_link
import copy
import random
import sys
import queue
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib import mac
from ryu.lib import hub


# this is topo implementing dijkstra algorithm
class Topo(object):
    def __init__(self,logger):
        # adjacent map (s1,s2)->(port,weight)
        # say,we have the following topo
        # p1---s1---p2-----p3---s2---p4
        # then the adjacent map={
        #          (s1,s2):(p2,weight)
        #          (s2,s1):(p3,weight)
        # }

        self.adjacent=defaultdict(lambda s1s2:None)
        #datapathes
        self.switches=None

        # use a map to host_mac->(switch,inport)
        # host_mac_to records a piece of topology information
        # just an auxiliary map to the controller's mac_to_port
        
        # this map privide a convinient way to figure out for a specific host, which switch does it connect to, and if so,through which port.
        # if we use controller's mac_to_port
        # we have to enumerate all the content,which is much more time-consuming and error-prone.
        self.host_mac_to={}
        self.logger=logger
        self.iperf_flows = {}
        self.iperf_flows = {(1, 2):1, (1, 3):2, (1, 4):3, (1, 5):4, (1, 6):5, (1, 7):6, (1, 8):7, (1, 9):8, (1, 10):9, (1, 11):10, 
                                      (2, 1):1, (2, 3):2, (2, 4):3, (2, 5):4, (2, 6):5, (2, 7):6, (2, 8):7, (2, 9):8, (2, 10):9, (2, 11):10, 
                                      (3, 2):1, (3, 1):2, (3, 4):3, (3, 5):4, (3, 6):5, (3, 7):6, (3, 8):7, (3, 9):8, (3, 10):9, (3, 11):10, 
                                      (4, 2):1, (4, 3):2, (4, 1):3, (4, 5):4, (4, 6):5, (4, 7):6, (4, 8):7, (4, 9):8, (4, 10):9, (4, 11):10, 
                                      (5, 2):1, (5, 3):2, (5, 4):3, (5, 1):4, (5, 6):5, (5, 7):6, (5, 8):7, (5, 9):8, (5, 10):9, (5, 11):10, 
                                      (6, 2):1, (6, 3):2, (6, 4):3, (6, 5):4, (6, 1):5, (6, 7):6, (6, 8):7, (6, 9):8, (6, 10):9, (6, 11):10, 
                                      (7, 2):1, (7, 3):2, (7, 4):3, (7, 5):4, (7, 6):5, (7, 1):6, (7, 8):7, (7, 9):8, (7, 10):9, (7, 11):10, 
                                      (8, 2):1, (8, 3):2, (8, 4):3, (8, 5):4, (8, 6):5, (8, 7):6, (8, 1):7, (8, 9):8, (8, 10):9, (8, 11):10, 
                                      (9, 2):1, (9, 3):2, (9, 4):3, (9, 5):4, (9, 6):5, (9, 7):6, (9, 8):7, (9, 1):8, (9, 10):9, (9, 11):10, 
                                      (10, 2):1, (10, 3):2, (10, 4):3, (10, 5):4, (10, 6):5, (10, 7):6, (10, 8):7,(10, 9):8,(10, 1):9, (10, 11):10}
        self.match_flag = 0
        self.cal_switches = {}
    # this is a TODO 
    # not implemented
    def reset(self):
        self.adjacent=defaultdict(lambda s1s2:None)
        self.switches=None
        self.host_mac_to=None
    
    
    #helper method to fetch and modify the adjacent map
    def get_adjacent(self,s1,s2):
        return self.adjacent.get((s1,s2))
    
    def set_adjacent(self,s1,s2,port,weight):
        self.adjacent[(s1,s2)]=(port,weight)
    
    #find the switch with min distance
    def __min_dist(self,distances, Q):
        mm=float('Inf')

        m_node=None
        for v in Q:
            if distances[v]<mm:
                mm=distances[v]
                m_node=v
        return m_node
    
    #src 
    #https://en.wikipedia.org/wiki/Dijkstra%27s_algorithm
    def shortest_path(self,src_sw,dst_sw,first_port,last_port):
        if(self.match_flag == 0):
            print(self.iperf_flows)
            print(self.best_weight_match())
            self.match_flag = 1
        distance={}
        previous = {}
        flag = 0
        assert self.switches is not None
        for dpid in self.switches:
            distance[dpid]=float('Inf')
            previous[dpid]=None
        
        distance[src_sw]=0
        Q=set(self.switches)
        while len(Q) > 0:
            u=self.__min_dist(distance,Q)
            if u is not None:
                Q.remove(u)
            else:
                return [dst_sw]

            for s in self.switches:
                # get u->s port weight
                # for each neighbor s of u:   
                if self.get_adjacent(u,s) is not None:
                    _,weight=self.get_adjacent(u,s)
                    if distance[u]+weight<distance[s]:
                        distance[s]=distance[u]+weight
                        previous[s] = u
                        if (s == dst_sw):
                            flag=1
            # record path
            if (flag == 1):
                break
        record=[]
        record.append(dst_sw)
        q=previous[dst_sw]

        while q is not None:
            if q==src_sw:
                    #we find it
                record.append(q)
                break
            p=q
            record.append(p)
            q=previous[p]
        
            
        #we reverse the list 
        # src-s-s-s-s-dst

        record.reverse()

        if src_sw==dst_sw:
                path=[src_sw]
        else:
                path=record
            
        record=[]
        inport=first_port
                      
        # s1 s2; s2:s3, sn-1  sn
        for s1,s2 in zip(path[:-1],path[1:]):
            # s1--outport-->s2
            outport,_=self.get_adjacent(s1,s2)
                
            record.append((s1,inport,outport))
            inport,_=self.get_adjacent(s2,s1)
            
        record.append((dst_sw,inport,last_port))
        
        #we find a path
        # (s1,inport,outport)->(s2,inport,outport)->...->(dest_switch,inport,outport)
        print(record)
        return record

    #the dijkstra algorithm to calculate the shorest path from src to dst
    def dijkstra(self, src_sw, dst_sw):
        distance={}
        previous = {}
        flag = 0
        assert self.switches is not None
        for dpid in self.switches:
            distance[dpid]=float('Inf')
            previous[dpid]=None
        
        distance[src_sw]=0
        Q=set(self.switches)
        while len(Q) > 0:
            u=self.__min_dist(distance,Q)
            if u is not None:
                Q.remove(u)
            else:
                return [dst_sw]

            for s in self.switches:
                # get u->s port weight
                # for each neighbor s of u:   
                if self.get_adjacent(u,s) is not None:
                    _,weight=self.get_adjacent(u,s)
                    if distance[u]+weight<distance[s]:
                        distance[s]=distance[u]+weight
                        previous[s] = u
                        if (s == dst_sw):
                            flag=1
            # record path
            if (flag == 1):
                break
        record=[]
        record.append(dst_sw)
        q=previous[dst_sw]

        while q is not None:
            if q==src_sw:
                    #we find it
                record.append(q)
                break
            p=q
            record.append(p)
            q=previous[p]
        
            
        #we reverse the list 
        # src-s-s-s-s-dst

        record.reverse()

        if src_sw==dst_sw:
                path=[src_sw]
        else:
                path=record
        return path
    
    #the Hungary algorithm to return the best match
    def best_weight_match(self):
        flowtable = 5 #each switch has the calculated flowtables
        fweightmax = 0 #the max flow weight
        flags = 0
        flagf = 0
        matchswitch = dict()
        matchflow = dict()
        matchedge = dict()
        dertaswitch = dict()
        dertaflow = dict()
        ftos = dict()
        stof = dict()
        fweight = dict()
        realflow = set()
        result = dict()
        for source, destination in self.iperf_flows:
            k = self.iperf_flows[(source, destination)]
            if (source != destination):
                if (len(self.dijkstra(source, destination)) == 1):
                    continue
                realflow.add((source, destination))#record the match flow
                for j in self.dijkstra(source, destination):
                    if (source, destination) not in ftos:
                        ftos[(source, destination)] = set()#switches been matched by flows
                        dertaflow[(source, destination)] = 0#derta
                        matchflow[(source, destination)] = 0#is matched or not
                    if j not in stof:
                        for m in range(flowtable):
                            stof[(j,m)] = set()#flows been matched by switches
                            dertaswitch[(j,m)] = 0
                            matchswitch[(j, m)] = 0
                    m = 0
                    if (source, destination, j,m) not in fweight:
                        for m in range(flowtable):
                            fweight[(source, destination, j, m)] = k#record the flow weight
                            matchedge[(source, destination, j, m)] = 0
                    for m in range(flowtable):
                        ftos[(source, destination)].add((j,m))
                        stof[(j,m)].add((source, destination))
        if not realflow:
            return 0
        i = len(self.switches)+1
        m = 0
        while (len(ftos) > len(stof)):#add not enough switches
            if (m == 20):
                m = 0
                i=i+1
            stof[(i, m)] = set()
            dertaswitch[(i, m)] = 0
            matchswitch[(i,m)] = 0
            m = m + 1
        while (len(ftos) < len(stof)):
            if (m == 20):
                m = 0
                i=i+1
            ftos[(i, m)] = set()
            dertaflow[(i, m)] = 0
            matchflow[(i,m)] = 0
            m = m + 1
        for (i, j) in stof:#match the goodpath
            for (src, dst) in ftos:
                if (i, j) not in ftos[(src,dst)]:
                    ftos[(src, dst)].add((i, j))
                if (src, dst) not in stof[(i, j)]:
                    stof[(i,j)].add((src,dst))
                if (src, dst, i, j) not in fweight:
                    fweight[(src, dst, i, j)] = 0
                    matchedge[(src, dst, i, j)] = 0
                if (fweightmax < fweight[(src, dst, i, j)]):
                    fweightmax = fweight[(src, dst, i, j)]
        for (i, j) in stof:
            for (src, dst) in ftos:
                fweight[(src, dst, i, j)] = fweightmax - fweight[(src, dst, i, j)]
        while ((flags == 0) and (flagf == 0)):
            flags = 1
            flagf = 1
            m = self.modBFS(stof, ftos, fweight, dertaswitch, dertaflow, matchswitch, matchflow, matchedge)
            if (m == 2):
                print(realflow)
                print(result)
                return 2
            for (i, j) in stof:
                if (matchswitch[(i, j)] == 0):
                    flags = 0
                    break
            for (src, dst) in ftos:
                if (matchflow[(src, dst)] == 0):
                    flagf = 0
                    break
        for (i, j) in realflow:
            for (m, n) in ftos[(i, j)]:
                if ((matchedge[(i, j, m, n)] == 1)and(m <= len(self.switches))):
                    result[(i, j)] = (m, n)
        print(realflow)
        print(result)
        self.cal_switches = result #return the final record
        return 1

    def modBFS(self,stof,ftos,fweight,dertaswitch,dertaflow,matchswitch,matchflow,matchedge):
        q = queue.Queue()
        p = queue.Queue()
        start = set()
        S = set()
        NS = set()
        goodpath = 0
        previousswitch = dict()
        previousflow = dict()
        visitedswitch = dict()
        visitedflow = dict()
        rcfweight = dict()
        tsrc = 0
        tdst = 0
        for (src, dst, i, j) in fweight:#calculate the RC
            rcfweight[(src, dst, i, j)] = fweight[(src, dst, i, j)] - dertaflow[(src, dst)] - dertaswitch[(i, j)]
        for (i, j) in stof:
            if (matchswitch[(i, j)] == 0):
                start.add((i,j))
        for (a, b) in start:
            q.put((a, b))
            S.add((a, b))
            for (m, n) in stof:
                visitedswitch[(m,n)] = 0
            for (src, dst) in ftos:
                visitedflow[(src, dst)] = 0
            visitedswitch[(a, b)] = 1
            while not (q.empty() and p.empty()):
                while not q.empty():
                    i, j = q.get()
                    for (src, dst) in stof[(i, j)]:
                        if (visitedflow[(src,dst)] == 0):
                            if (rcfweight[(src, dst, i, j)] == 0):
                                if (matchedge[(src, dst, i, j)] == 0):
                                    if (matchflow[(src, dst)] == 1):  
                                        p.put((src, dst))
                                        NS.add((src, dst))
                                        visitedflow[(src,dst)] = 1
                                        previousflow[(src, dst)] = (i, j)
                                    if (matchflow[(src, dst)] == 0):
                                        visitedflow[(src,dst)] = 1
                                        previousflow[(src, dst)] = (i, j)
                                        tsrc = src
                                        tdst = dst
                                        goodpath = 1
                                        q.queue.clear
                                        p.queue.clear
                                        break
                while not p.empty():
                    src, dst = p.get()
                    for (i, j) in ftos[(src, dst)]:
                        if (visitedswitch[(i,j)] == 0):
                            if (matchedge[(src, dst, i, j)] == 1):
                                S.add((i, j))
                                q.put((i, j))
                                visitedswitch[(i, j)] = 1
                                previousswitch[(i, j)] = (src, dst)
            if (goodpath == 1):
                break
        if (goodpath == 1):
            i = tsrc
            j = tdst
            m, n = previousflow[(i, j)]
            matchedge[(i, j, m, n)] = 1
            matchflow[(i, j)] = 1
            while (matchswitch[(m, n)] == 1):
                i, j = previousswitch[(m, n)]
                matchedge[(i, j, m, n)] = 0
                m, n = previousflow[(i, j)]
                matchedge[(i, j, m, n)] = 1
            matchswitch[(m, n)] = 1
        else:
            dertamin = float('Inf')
            for (src, dst, i, j) in rcfweight:
                if (rcfweight[(src, dst, i, j)] < 0):
                    return 2
            for (c, d) in S:
                for (i, j) in stof[(c, d)]:
                    if (((fweight[(i, j, c, d)] - dertaflow[(i, j)] - dertaswitch[(c, d)])<dertamin)and((fweight[(i, j, c, d)] - dertaflow[(i, j)] - dertaswitch[(c, d)])>0)):
                        dertamin = fweight[(i, j, c, d)] - dertaflow[(i, j)] - dertaswitch[(c, d)]           
            for (c, d) in S:
                dertaswitch[(c, d)] = dertaswitch[(c, d)] + dertamin
            for (i, j) in NS:
                dertaflow[(i, j)] = dertaflow[(i, j)] - dertamin
            for (src, dst, i, j) in fweight:
                rcfweight[(src, dst, i, j)] = fweight[(src, dst, i, j)] - dertaflow[(src, dst)] - dertaswitch[(i, j)]               
        return 1

#TODO Port status monitor

class DijkstraController(app_manager.RyuApp):
    OFP_VERSIONS=[ofproto_v1_3.OFP_VERSION]

    def __init__(self,*args,**kwargs):
        super(DijkstraController,self).__init__(*args,**kwargs)
        self.mac_to_port={}
        # logical switches
        self.datapaths=[]
        #ip ->mac
        self.arp_table={}

        # revser arp table
        # mac->ip
        # this is a TODO
        # not implemented
        self.rarp_table={}

        self.topo=Topo(self.logger)
        self.flood_history={}

        self.arp_history={}
        # self.is_learning={}
        self.check_thread = hub.spawn(self._send_request)

    def _send_request(self):
        while(True):
            for datapath in self.datapaths:
                if datapath is not None:
                    parser = datapath.ofproto_parser
                    req = parser.OFPFlowStatsRequest(datapath)
                    datapath.send_msg(req)
            hub.sleep(1)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
            Save flow stats reply info into self.flow_stats.
            Calculate flow speed and Save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        for stat in sorted([flow for flow in body if flow.priority == 1000],
                           key=lambda flow: (flow.match.get('eth_src'),
                                             flow.match.get('eth_dst'))):
            key = (stat.match.get('eth_src'),  stat.match.get('eth_dst'),
                   stat.instructions[0].actions[0].port)
            value = (stat.packet_count, stat.byte_count,
                     stat.duration_sec, stat.duration_nsec)
            print("***", dpid)
            print("calculate the flow from",key[0],"to",key[1]) #TODO
            print("packet_count:", value[0], " byte_count:", value[1], " duration_sec:", value[2])
            print('')
            #print the flow table's information
    
    def _find_dp(self,dpid):
        for dp in self.datapaths:
            if dp.id==dpid:
                return dp
        return None
    
    # def _add_islearning(self,src_mac,dst_mac):
    #     self.is_learning.append((src_mac,dst_mac))
    
    # def _remove_islearning(self,src_mac,dst_mac):
    #     self.is_learning.remove((src_mac,dst_mac))
    

    #copy from example
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_best_weight_match_flow(self, dpid, eth_src, eth_dst, to_port, priority=1000):
        datapath = self._find_dp(dpid)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(to_port)]
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=eth_src,
                                eth_dst=eth_dst)
        self.add_flow(datapath, priority, match, actions)

    def configure_path(self,shortest_path:list,event,src_mac,dst_mac):
        #configure shortest path to switches
        msg=event.msg
        datapath=msg.datapath

        ofproto=datapath.ofproto

        parser=datapath.ofproto_parser

        # enumerate the calculated path
        # (s1,inport,outport)->(s2,inport,outport)->...->(dest_switch,inport,outport)
        for switch,inport,outport in shortest_path:
            match=parser.OFPMatch(in_port=inport,eth_src=src_mac,eth_dst=dst_mac)

            actions=[parser.OFPActionOutput(outport)]


            datapath=self._find_dp(int(switch))
            assert datapath is not None

            inst=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

            #idle and hardtimeout set to 0,making the entry permanent
            #reference openflow spec
            mod=datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath,
                match=match,
                idle_timeout=0,
                hard_timeout=0,
                priority=1,
                instructions=inst
            )
            datapath.send_msg(mod)

    
    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,event):

        msg=event.msg
        datapath=msg.datapath
        ofproto=datapath.ofproto
        parser=datapath.ofproto_parser

        in_port=msg.match['in_port']

        #self.logger.info("From datapath {} port {} come in a packet".format(datapath.id,in_port))

        #get src_mac and dest mac
        pkt=packet.Packet(msg.data)
        eth=pkt.get_protocols(ethernet.ethernet)[0]

        # drop lldp
        if eth.ethertype==ether_types.ETH_TYPE_LLDP:
            #self.logger.info("LLDP")
            return

        dst_mac=eth.dst

        src_mac=eth.src

        arp_pkt = pkt.get_protocol(arp.arp)

        # a map recording arp table from arp request
        # app_table={
        #     ip:mac
        # }
        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = src_mac

        dpid=datapath.id


        #mac_to_port is a two-level map, which records the mapping relation between mac address and port, for a particular switch
        #python built-in function
        #for a map,if key doesnt exsit,return the default value,which is a empty map {}
        #mac_to_port={
        #     switch:{
        #     mac:port
        #     }
        # }
        self.mac_to_port.setdefault(dpid,{})

        self.mac_to_port[dpid][src_mac]=in_port

        # flood_history helps the controller remember whether or not a particular switch has flooded a packet(identified by src and destination mac) before
        # flood_history={
        #    switch:[(src_mac,dst_mac)]
        # }

        self.flood_history.setdefault(dpid,[])
        # if this is a ipv6 broadcast packet

        if '33:33' in dst_mac[:5]:
            # the controller has not flooded this packet before
            if (src_mac,dst_mac) not in self.flood_history[dpid]:
                # we remember this packet
                self.flood_history[dpid].append((src_mac,dst_mac))
            else:
            # the controller have flooded this packet before,we do nothing and return
                return
                
        #self.logger.info("from dpid {} port {} packet in src_mac {} dst_mac{}".format(dpid,in_port,src_mac,dst_mac))



        if src_mac not in self.topo.host_mac_to.keys():
            self.topo.host_mac_to[src_mac]=(dpid,in_port)
        
        # if we have record the dest mac
        # the dst mac has registered

        # host_mac-> switch,inport
        if dst_mac in self.topo.host_mac_to.keys():
            
            final_port=self.topo.host_mac_to[dst_mac][1]
            # the first switch
            src_switch=self.topo.host_mac_to[src_mac][0]
            # the final switch
            dst_switch=self.topo.host_mac_to[dst_mac][0]
            #calculate the shortest path
            shortest_path=self.topo.shortest_path(
                src_switch,
                dst_switch,
                1,
                1)
            print(shortest_path)

            self.logger.info("The shortest path from {} to {} contains {} switches".format(src_mac,dst_mac,len(shortest_path)))
            
            assert len(shortest_path)>0
            
            #测量流表
            out_port = 0
            for key in self.topo.cal_switches:
                if key[0] == (shortest_path[0])[0] and key[1] == (shortest_path[-1])[0]:
                    for s,ip,op in shortest_path:
                        if s == (self.topo.cal_switches[key])[0]:
                            out_port = op

                    self.add_best_weight_match_flow((self.topo.cal_switches[key])[0], src_mac, dst_mac, out_port, 1000)
                    print((self.topo.cal_switches[key])[0], key[0], key[1], out_port)

            # log the shortest path
            path_str=''

            # (s1,inport,outport)->(s2,inport,outport)->...->(dest_switch,inport,outport)
            for s,ip,op in shortest_path:
                path_str=path_str+"--{}-{}-{}--".format(ip,s,op)

            self.logger.info("The shortest path from {} to {} is {}".format(src_mac,dst_mac,path_str))
            
            self.logger.info("Have calculated the shortest path from {} to {}".format(src_mac,dst_mac))

            self.logger.info("Now configuring switches of interest")

            self.configure_path(shortest_path,event,src_mac,dst_mac)

            self.logger.info("Configure done")

            # current_switch=None
            out_port=None
            for s,_,op in shortest_path:
                #print(s,dpid)
                if s==dpid:
                    out_port=op
            assert out_port is not None
        else: 
            # handle arp packet
            # in case we meet an arp packet
            if self.arp_handler(msg):  # 1:reply or drop;  0: flood
                return 
            #the dst mac has not registered
            #self.logger.info("We have not learn the mac address {},flooding...".format(dst_mac))
            out_port=ofproto.OFPP_FLOOD


        actions=[parser.OFPActionOutput(out_port)]

        data=None

        if msg.buffer_id==ofproto.OFP_NO_BUFFER:
            data=msg.data
        
        # send the packet out to avoid packet loss
        out=parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
        
    #https://vlkan.com/blog/post/2013/08/06/sdn-discovery/
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self,event):
        self.logger.info("A switch entered.Topology rediscovery...")
        self.switch_status_handler(event)
        self.logger.info('Topology rediscovery done')
    
    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self,event):
        self.logger.info("A switch leaved.Topology rediscovery...")
        self.switch_status_handler(event)
        self.logger.info('Topology rediscovery done')



    def switch_status_handler(self,event):

        #api get_switch
        #api app.send_request()
        #api switch_request_handler
        #return reply.switches
        #switch.dp.id

        # use copy to avoid unintended modification which is fatal to the network
        all_switches=copy.copy(get_switch(self,None))
       

        # get all datapathid 
        self.topo.switches=[s.dp.id for s in all_switches]

        self.logger.info("switches {}".format(self.topo.switches))

        

        self.datapaths=[s.dp for s in all_switches]

        # get link and get port
        all_links=copy.copy(get_link(self,None))
        #api link_request_handler
        #api Link
        # link port 1,port 2

        all_link_stats=[(l.src.dpid,l.dst.dpid,l.src.port_no,l.dst.port_no) for l in all_links]
        self.logger.info("Number of links {}".format(len(all_link_stats)))

        all_link_repr=''


        for s1,s2,p1,p2 in all_link_stats:
            # we would assign weight randomly
            # ignore the weight consistency
            # ie, in ryu,two links represent one physical link,
            # say s1======s2 ,in ryu we have 
            # s1------>s2,s2----->s1
            # when enumerate all the links,the later one will overwrite the previous one.
            weight=random.randint(1,10)
            # weight=1
            self.topo.set_adjacent(s1,s2,p1,weight)
            self.topo.set_adjacent(s2,s1,p2,weight)

            all_link_repr+='s{}p{}--s{}p{}\n'.format(s1,p1,s2,p2)
        self.logger.info("All links:\n "+all_link_repr)
    
    #https://github.com/osrg/ryu/pull/55/commits/8916ab85072efc75b97f987a0696ff1fe64cbf42
    # reference 
    # packet api https://ryu.readthedocs.io/en/latest/library_packet.html
    # arppacket api https://ryu.readthedocs.io/en/latest/library_packet_ref/packet_arp.html
    def arp_handler(self, msg):

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth:
            eth_dst = eth.dst
            eth_src = eth.src

        if eth_dst == mac.BROADCAST_STR and arp_pkt:
            # target ip 
            arp_dst_ip = arp_pkt.dst_ip

            # arp_history={
            # (datapath.id,eth_src,dest_ip):inport
            # }

            # we have met this particular arp request before
            if (datapath.id, eth_src, arp_dst_ip) in self.arp_history:
                #(datapath.id,eth_src,target_ip)->inport
                # however, the new arp packet did not consist with the record, it comes from another port, so may be it's a broadcasted arp request
                # we just ignore it to break the broadcast loop
                if self.arp_history[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    #datapath.send_packet_out(in_port=in_port, actions=[])
                    return True
            else:
                # we didnt met this packet before, record
                self.arp_history[(datapath.id, eth_src, arp_dst_ip)] = in_port
        
        #construct arp packet
        if arp_pkt:
            hwtype = arp_pkt.hwtype
            proto = arp_pkt.proto
            hlen = arp_pkt.hlen
            plen = arp_pkt.plen
            opcode = arp_pkt.opcode
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip

            # arp_request
            if opcode == arp.ARP_REQUEST:
                self.logger.info("ARP Request src_ip: {}".format(arp_src_ip))
                # we have learned the target ip mac mapping
                if arp_dst_ip in self.arp_table:
                    # send arp reply from in port
                    actions = [parser.OFPActionOutput(in_port)]
                    arp_reply = packet.Packet()
                    

                    arp_reply.add_protocol(ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    arp_reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    arp_reply.serialize()
                    #arp reply
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=arp_reply.data)
                    datapath.send_msg(out)
                    return True
        return False


