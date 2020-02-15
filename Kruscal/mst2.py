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
from ryu.lib.packet import arp
from ryu.lib.packet import ipv6
from ryu.lib import mac

import numpy as np

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
    
    # this is a TODO 
    # not implemented
    def reset(self):
        self.adjacent=defaultdict(lambda s1s2:None)
        self.switches=None
        self.host_mac_to=None
    
    
    #helper method to fetch and modify the adjacent map
    def get_adjacent(self,s1,s2):
        return self.adjacent.get((s1,s2))
    
    #修改图中邻接边
    def set_adjacent(self,s1,s2,port,weight):
        self.adjacent[(s1,s2)]=(port,weight)
    
    def get_graph(self):
        Matrix = np.array(np.ones((13,13))*999999)

        for (s,t) in self.adjacent.keys():
            Matrix[s-1][t-1] = random.randint(1,5)
            Matrix[t-1][s-1] = Matrix[s-1][t-1]

        return Matrix

    def get_nodenum(self,Matrix):
        return len(Matrix)

    def get_edgenum(self,Matrix):
        count = 0
        for i in range(len(Matrix)):
            for j in range(i):
                if Matrix[i][j] > 0 and Matrix[i][j] < 999999:
                    count += 1
    
        return count

    def kruskal(self, Matrix):
        nodenum = self.get_nodenum(Matrix)
        edgenum = self.get_edgenum(Matrix)

        result_list = []
        #如果点的个数是负数，或者边的数量小于点的数量-1，即不是全连通，直接返回
        if nodenum <= 0 or edgenum < nodenum - 1:
            return result_list

        #创建边集合
        edge_list = []
        #遍历节点
        for i in range(nodenum):
            #从i开始，遍历剩下的点
            for j in range(i+1, nodenum):
                #如果两个节点之间存在边
                if Matrix[i][j] < 999999:
                    #将该边加入集合，形式为[节点i,节点j,权重]
                    edge_list.append([i, j, Matrix[i][j]])

        #将边排序
        edge_list.sort(key=lambda a: a[2])

        #创建节点列表
        group = [[i] for i in range(nodenum)]
        #对于每一条边
        for edge in edge_list:
            for i in range(len(group)):
                if edge[0] in group[i]:
                    m = i
                if edge[1] in group[i]:
                    n = i
            if m != n:
                result_list.append(edge)
                group[m] = group[m] + group[n]
                group[n] = []

        return result_list

    def comput_tree(self,src,list):
        list1 = list
        links = [[] for i in range(len(list) + 1)]
        for i in range(len(list) + 1):
            for edge in list1:
                pass
                if i == edge[0]:
                    links[i].append(edge[1])
                elif i == edge[1]:
                    links[i].append(edge[0])
        return links

    def compute_links(self,src,pre_src,links):
        result = []
        if len(links[src]) < 1:
            return result

        for node in links[src]:
            if node != pre_src:
                result.append((pre_src,src,node))
                newresult = self.compute_links(node,src,links)
                result.extend(newresult)

        return result

    #收到包之后调用该函数，计算流表的转发，流表匹配源ip，向生成树上其他端口转发
    def compute_flowTables(self,src_dw,first_port):
        Matrix = self.get_graph()
        linkList1 = self.kruskal(Matrix)
        tree = self.comput_tree(src_dw-1,linkList1)
        links = self.compute_links(src_dw-1,None,tree)
        print('src:',src_dw)
        print('linkList:',linkList1)
        #print('tree:', tree)
        #print('links:',links)

        temp1 = {}
        for link in links:
            if(link[0],link[1]) not in temp1.keys():
                temp1[(link[0],link[1])] = [link[2]]
            else:
                temp1[(link[0],link[1])].append(link[2])

        #print('temp1:',temp1)

        newresult = []
        index = [key[1] for key in temp1.keys()]
        #print(index)
        for i in range(13):
            if i not in index:
                for key in temp1.keys():
                    if i in temp1[key]:
                        newresult.append((key[1],i,None))
            else:
                for key in temp1.keys():
                    if i == key[1]:
                        newresult.append((key[0],key[1],temp1[key]))
        #print('newresult:',newresult)

        result = []

        for item in newresult:
            if item[0] is not None:
                if item[2] is None:
                    inport,_ = self.get_adjacent(item[1]+1,item[0]+1)
                    outportList = [1]
                    result.append((item[1]+1,inport,outportList))
                else:
                    inport,_ = self.get_adjacent(item[1]+1,item[0]+1)
                    outportList = [1]
                    for node in item[2]:
                        op,_ = self.get_adjacent(item[1]+1,node+1)
                        outportList.append(op)
                    result.append((item[1]+1,inport,outportList))
            else:
                inport = first_port
                outportList = [1]
                for node in item[2]:
                    op,_ = self.get_adjacent(item[1]+1,node+1)
                    outportList.append(op)
                result.append((item[1]+1,inport,outportList))

        #print('result:',result)
        return result
        #result: [(s1,inport,outportList),...(sn,inport,outportList)]

    def show(self):
        print("switches: ",self.switches)

    def test(self):
        result = self.compute_flowTables(4,-1)
        print("result: ",result)


   
#控制器
class MyController(app_manager.RyuApp):
    #定义OpenFlow版本
    OFP_VERSIONS=[ofproto_v1_3.OFP_VERSION]

    def __init__(self,*args,**kwargs):
        super(MyController,self).__init__(*args,**kwargs)
        
        
        #全局的mac表,{{datapath:mac->port},...,{datapath:mac->port}}
        self.mac_to_port={}
        #存储所有datapath
        self.datapaths=[]
        #ARP表{ip->mac,...,ip->mac}
        #self.arp_table={}

        # revser arp table
        # mac->ip
        # this is a TODO
        # not implemented
        #反向ARP表{mac->ip,...,mac->ip}
        #self.rarp_table={}

        #洪泛历史表
        self.flood_history={}
        #arp历史表
        self.arp_history={}

        self.flag = False

        
        self.arp_table = {'192.168.0.1':'00:00:00:00:00:01',
                          '192.168.0.2':'00:00:00:00:00:02',
                          '192.168.0.3':'00:00:00:00:00:03',
                          '192.168.0.4':'00:00:00:00:00:04',
                          '192.168.0.5':'00:00:00:00:00:05',
                          '192.168.0.6':'00:00:00:00:00:06',
                          '192.168.0.7':'00:00:00:00:00:07',
                          '192.168.0.8':'00:00:00:00:00:08',
                          '192.168.0.9':'00:00:00:00:00:09',
                          '192.168.0.10':'00:00:00:00:00:10',
                          '192.168.0.11':'00:00:00:00:00:11',
                          '192.168.0.12':'00:00:00:00:00:12',
                          '192.168.0.255':'00:00:00:00:00:ff' 
                          }
         
        self.rarp_table = {'00:00:00:00:00:01':'192.168.0.1',
                           '00:00:00:00:00:02':'192.168.0.2',
                           '00:00:00:00:00:03':'192.168.0.3',
                           '00:00:00:00:00:04':'192.168.0.4',
                           '00:00:00:00:00:05':'192.168.0.5',
                           '00:00:00:00:00:06':'192.168.0.6',
                           '00:00:00:00:00:07':'192.168.0.7',
                           '00:00:00:00:00:08':'192.168.0.8',
                           '00:00:00:00:00:09':'192.168.0.9',
                           '00:00:00:00:00:10':'192.168.0.10',
                           '00:00:00:00:00:11':'192.168.0.11',
                           '00:00:00:00:00:12':'192.168.0.12',
                           '00:00:00:00:00:ff':'192.168.0.255' 
                           }
        
        #self.arp_table={}

        # revser arp table
        # mac->ip
        # this is a TODO
        # not implemented
        #self.rarp_table={}
        
        self.topo = Topo(self.logger)

    
    #根据dpid获取datapath实体
    def _find_dp(self,dpid):
        for dp in self.datapaths:
            if dp.id==dpid:
                return dp
        return None
    
    #配置miss-table
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


     #配流表
    def configure_path(self,path,event,src_mac,dst_mac):
        #configure shortest path to switches
        msg=event.msg
        datapath=msg.datapath

        ofproto=datapath.ofproto

        parser=datapath.ofproto_parser

        #获取选择路径经过的交换机以及转发方式，配置match和actions
        # (s1,inport,outport)->(s2,inport,outport)->...->(dest_switch,inport,outport)
        for switch,inport,outportList in path:
            match=parser.OFPMatch(in_port=inport,eth_src=src_mac,eth_dst=dst_mac)

            actions = []
            #actions是一个列表，表示流表向哪些端口转发
            for outport in outportList:
                actions.append(parser.OFPActionOutput(outport))
            

            #找到dpid对应的datapath
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
            #下发流表
            datapath.send_msg(mod)

    #监听Packet_in事件
    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,event):
        msg=event.msg
        datapath=msg.datapath
        ofproto=datapath.ofproto
        parser=datapath.ofproto_parser

        # through which port the packet comes in
        in_port=msg.match['in_port']

        #获取数据
        pkt=packet.Packet(msg.data)
        #假设为以太帧，获取帧头
        eth=pkt.get_protocols(ethernet.ethernet)[0]
        
        
        #直接下发生成树流表
        if self.flag == False:
            path = self.topo.compute_flowTables(
                4,
                1)
            
            for onepath in path:
                if onepath[0]==4:
                    onepath[2].remove(1)
            print('path:  ',path)
            #给路径中交换机下发流表
            self.configure_path(path,event,'00:00:00:00:00:04','00:00:00:00:00:03')
            print('--------------------Configure done--------------------')

            
            #下发回路
            self.configure_path([(3,1,[3]),(4,2,[1])],event,'00:00:00:00:00:03','00:00:00:00:00:04')
            print('--------------------Configure done--------------------')
            
            self.flag = True
            
        
        
        #如果是LLDP，则直接丢弃
        if eth.ethertype==ether_types.ETH_TYPE_LLDP:
            #self.logger.info("LLDP")
            return

        
        dst_mac=eth.dst

        src_mac=eth.src
        
        # check if this is an arp packet
        arp_pkt = pkt.get_protocol(arp.arp)
        # if this is an arp packet,we remember "ip---mac"
        # we learn ip---mac mapping from arp reply and request
        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = src_mac

        # dpid,an interger identify a switch uniquely
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
        # this kind of packet has some obvious charateristics.
        # Its destination mac address starts with "33:33"
        if '33:33' in dst_mac[:5]:
            # the controller has not flooded this packet before
            if (src_mac,dst_mac) not in self.flood_history[dpid]:
                # we remember this packet
                self.flood_history[dpid].append((src_mac,dst_mac))
            else:
            # the controller have flooded this packet before,we do nothing and return
                return
                
        #self.logger.info("from dpid {} port {} packet in src_mac {} dst_mac{}".format(dpid,in_port,src_mac,dst_mac))



        # use a map to host_mac->(switch,inport)
        # host_mac_to records a piece of topology information
        # just an auxiliary map to the controller's mac_to_port
        
        # this map privide a convinient way to figure out that for a specific host, which switch does it connect to, and if so,through which port.
        # if we use controller's mac_to_port
        # we have to enumerate all the content,which is much more time-consuming and error-prone.
        
        if src_mac not in self.topo.host_mac_to.keys():
            self.topo.host_mac_to[src_mac]=(dpid,in_port)
        
        # if we have record the dest mac
        # i.e the dst mac has registered, the host must have entered the topology
        # host_mac-> switch,inport
        if dst_mac in self.topo.host_mac_to.keys():

            # the topo 
            # src_host------in_port---src_switch--------many switches along the path-----dst_switch----final_port----destination_host
            # get the final port
            final_port=self.topo.host_mac_to[dst_mac][1]

            # the first switch
            src_switch=self.topo.host_mac_to[src_mac][0]

            # the final switch
            dst_switch=self.topo.host_mac_to[dst_mac][0]

            #calculate the shortest path
            shortest_path=self.topo.compute_flowTables(
                4,
                
                1
                )
            
            self.logger.info("The longest path from {} to {} contains {} switches".format(src_mac,dst_mac,len(shortest_path)))
            
            assert len(shortest_path)>0
            
            # log the shortest path
            #path_str=''

            # (s1,inport,outport)->(s2,inport,outport)->...->(dest_switch,inport,outport)
            #for s,ip,op in shortest_path:
                #path_str=path_str+"--{}-{}-{}--".format(ip,s,op)

            #self.logger.info("The longset path from {} to {} is {}".format(src_mac,dst_mac,path_str))
            
            self.logger.info("Have calculated the longest path from {} to {}".format(src_mac,dst_mac))

            self.logger.info("Now configuring switches of interest")

            self.configure_path(shortest_path,event,src_mac,dst_mac)

            self.logger.info("Configure done")

           # current_switch=None
            out_port=[]
            for s,_,op in shortest_path:
                # print(s,dpid)
                if s==dpid:
                    out_port=op
            #assert out_port is not None
        
        else: 
            # handle arp packet
            # in case we meet an arp packet

            # we return if
            # 1. broadcasted arp request
            # 2. we have sent arp reply
            if self.arp_handler(msg):  
                return 

            #the dst mac has not registered
            #self.logger.info("We have not learn the mac address {},flooding...".format(dst_mac))
            out_port=[]
            out_port.append(ofproto.OFPP_FLOOD)
        '''
        # actions= flood or some port
        print('inport:       ',in_port)
        actions=[]
        for outport in out_port:
            actions.append(parser.OFPActionOutput(out_port))
        print('actions:       ',actions)
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
        #datapath.send_msg(out)
        '''
        
        
    
    #有交换机加入网络
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
        #获取交换机的ID值
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
            weight=random.randint(1,5)

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
        
        # the destination mac address for an arp request packet is a braodcast address
        # if this is an arp request
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

                # wait a minute, how could a packet that we seen before appears inconsistent with our record ?
                # this arp_history map keeps records for the first time a switch met this packet.
                # but now it comes in from a different port!

                # So there must exists a ring in our topology so that a switch could meet this packet twice but for two different ports!
                # and there must exists a broadcast loop, we must break it. or it would take down the whole network which is intolerable.
                if self.arp_history[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    #datapath.send_packet_out(in_port=in_port, actions=[])
                    return True
            else:
                # we didnt met this packet before, record it
                self.arp_history[(datapath.id, eth_src, arp_dst_ip)] = in_port
        
        #construct arp packet
        # we get the arp header parameter to construct an arp reply.
        if arp_pkt:
            # See https://en.wikipedia.org/wiki/Address_Resolution_Protocol for more detailed explanation

            # hardware type
            hwtype = arp_pkt.hwtype
            # protocol type
            proto = arp_pkt.proto
            # hardware address length
            hlen = arp_pkt.hlen
            # protocol address length
            plen = arp_pkt.plen
            
            #specify the operation that the sender is performing:1 for request,2 for reply
            opcode = arp_pkt.opcode

            # src ip
            arp_src_ip = arp_pkt.src_ip
            # dst ip 
            arp_dst_ip = arp_pkt.dst_ip

            # arp_request
            if opcode == arp.ARP_REQUEST:
                # Note that we learn arp table from arp request and arp reply.

                # For example,say,at the very begining, the controller know nothing about ip-mac relationship.
                #  Now  wants figure out the mac address of h2
                # the switch has to broadcast the arp request to h2, but no worry for broacast storm any more.
                # Why? Because we detect the loop,break it and drop the packet. See code above.

                # h2 sends an arp reply packet with h1's mac address as dest address and h2's mac as src address and sent it back to.
                # so the controller can record h2's ip---mac mapping


                # we have learned the target ip mac mapping
                if arp_dst_ip in self.arp_table:
                    # send arp reply from in port
                    actions = [parser.OFPActionOutput(in_port)]
                    arp_reply = packet.Packet()
                    
                    # add ethernet protocol
                    # the packet is constructed according tho arp specifcation
                    # See https://en.wikipedia.org/wiki/Address_Resolution_Protocol for more details
                    # Or See https://zhuanlan.zhihu.com/p/28771785 for more details
                    
                    arp_reply.add_protocol(ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    
                    # add arp protocol
                    arp_reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))
                    
                    # serialize the packet to binary format 0101010101
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


