#!/usr/bin/python2.7
__author__ = 'anton'

from scapy.layers.inet import *
from scapy.all import *
from scapy.contrib.igmp import *
import time, threading, commands




class Querier:
    def __init__ (self, iface, qtime = 60, mrtime=10, lmrtime=1, robust_var=2):
        self.robust_var=robust_var
        self.iface=iface
        self.qtime=qtime
        self.mrtime=mrtime
        self.lmrtime=lmrtime
        self.payload = ''.join('A' for _ in xrange (1300))
        self.active_groups = {}
        self.srcMAC, self.srcIP = Querier.getsourceaddrs(self.iface)
        self.lock = threading.RLock()
        # 3 main threads
        self.threads = {}
        self.threads['sniffer'] = threading.Thread(name='sniffer',target=self.join_leave_sniffer)
        self.threads['querier'] = threading.Thread(name='querier',target=self.general_querier)
        self.threads['finalizer'] = threading.Thread(name='finalizer',target=self.finalizer)
        for i in self.threads.values():
            i.setDaemon(True)
            i.start()




    @staticmethod
    def getsourceaddrs(iface):
        mac = commands.getstatusoutput("/sbin/ifconfig %s | grep -Po '(?<=HWaddr\s)[a-f0-9:]+'" % iface)[1]
        ip = commands.getstatusoutput("/sbin/ifconfig %s | grep -Po '(?<=inet addr:)[0-9\.]+'" % iface)[1]
        return [mac,ip]

    @staticmethod
    def get_multicast_mac(ip):
        ip_octs = ip.split('.')
        mac_octs=[]
        for i in ip_octs[1:]:
            mac_octs.append(hex(int(i))[2:])
        return '01:00:5e:%s' % ':'.join(mac_octs)

    @staticmethod
    def get_integer_ip(ip):
        octets=ip.split('.')
        int_ip=0
        for i in range(4):
            int_ip+= int(octets[3-i])*256**i
        return int_ip



    def join_leave_sniffer(self):

        def generator(gaddr):
            dict = self.active_groups[gaddr]
            pkt = Ether(src=self.srcMAC,dst=Querier.get_multicast_mac(gaddr))\
                      /IP(src=self.srcIP,dst=gaddr)/UDP(sport=1234,dport=1234)/Raw(self.payload)
            while not dict['kill_it']:
                sendp(pkt,inter=0.1,iface=self.iface,verbose=0,count=10)
                time.sleep(0.09)

        def wait_joinleave(p):
            igmp = p[0].getlayer(IGMP)
            if igmp.type == 0x16: #JOIN
                with self.lock:
                    if igmp.gaddr in self.active_groups:
                        self.active_groups[igmp.gaddr]['last_join_timestamp'] = time.time()
                    else:
                        self.active_groups[igmp.gaddr] = {'last_join_timestamp':time.time()}
                        self.active_groups[igmp.gaddr]['kill_it']= False
                        self.active_groups[igmp.gaddr]['thread_id'] = \
                            threading.Thread(name='group_'+igmp.gaddr, target=generator, args=(igmp.gaddr,))
                        self.active_groups[igmp.gaddr]['thread_id'].setDaemon(True)
                        self.active_groups[igmp.gaddr]['thread_id'].start()
                    self.active_groups[igmp.gaddr]['leave_candidat'] = False
            elif igmp.type == 0x17: #LEAVE
                if igmp.gaddr in self.active_groups:
                    self.active_groups[igmp.gaddr]['leave_candidat'] = True
                    pkt = Ether(src=self.srcMAC,dst=Querier.get_multicast_mac(igmp.gaddr))\
                          /IP(src=self.srcIP,dst=igmp.gaddr,ttl=1)/IGMP(type=0x11,gaddr=igmp.gaddr,mrtime=self.lmrtime)
                    sendp (pkt,iface=self.iface,verbose=0)
                    self.active_groups[igmp.gaddr]['last_squery_timestamp'] = time.time()
                    for i in range(self.robust_var-1):
                        time.sleep(self.lmrtime)
                        sendp (pkt,iface=self.iface,verbose=0)
#            elif igmp.type==0x11: #QUERY
#                remote_ip = p[0].getlayer(IP).src
#                if Querier.get_integer_ip(remote_ip) < Querier.get_integer_ip(self.srcIP):








        sniff(iface=self.iface, lfilter=lambda p: p.src!=self.srcMAC and IGMP in p, count=0, prn=wait_joinleave, store=0)

    def general_querier(self):
        pkt = Ether(src=self.srcMAC,dst=Querier.get_multicast_mac('224.0.0.1'))\
                      /IP(src=self.srcIP,dst='224.0.0.1',ttl=1)/IGMP(type=0x11,gaddr='0.0.0.0',mrtime=self.mrtime)
        sendp (pkt,iface=self.iface,verbose=0,count=self.robust_var,inter=self.qtime/4.0)
        sendp (pkt,iface=self.iface,verbose=0,inter=self.qtime,loop=1)


    def finalizer(self):
        group_membership_interval  = self.robust_var*self.qtime+self.mrtime
        while True:
            time.sleep(0.5)
            with self.lock:
                for addr in self.active_groups.keys():
                    now = time.time()
                    if now-self.active_groups[addr]['last_join_timestamp'] > group_membership_interval\
                            or (self.active_groups[addr]['leave_candidat'] \
                                and now-self.active_groups[addr]['last_squery_timestamp'] > self.robust_var*self.lmrtime+0.5):
                        self.active_groups[addr]['kill_it'] = True
                        del self.active_groups[addr]


if __name__ == "__main__":

    q = Querier(iface='eth0')
    while True:
        time.sleep(0.5)






