# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# a simple ICMP Echo Responder

from ryu.base import app_manager
from ryu.lib import addrconv
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp

class DHCPResponder(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DHCPResponder, self).__init__(*args, **kwargs)
        self.hw_addr = '0a:e4:1c:d1:3e:44'
        self.dhcp_server = '192.168.1.1'
        self.netmask = '255.255.255.0'
        self.dns = '8.8.8.8'
        self.bin_dns = addrconv.ipv4.text_to_bin(self.dns)
        self.hostname = 'huehuehue'
        self.bin_netmask = addrconv.ipv4.text_to_bin(self.netmask)
        self.bin_server = addrconv.ipv4.text_to_bin(self.dhcp_server)
        self.ip_addr = '192.0.2.9'

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER,
                                          max_len=ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS,
                                             actions=actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=0,
                                match=parser.OFPMatch(),
                                instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        port = msg.match['in_port']
        pkt = packet.Packet(data=msg.data)

        pkt_dhcp = dhcp.dhcp.parser(pkt[3])
        if not pkt_dhcp:
            return
        else:
            self._handle_dhcp(datapath, port, pkt)
        return


    def assemble_ack(self, pkt):
        req_eth = pkt.get_protocol(ethernet.ethernet)
        req_ipv4 = pkt.get_protocol(ipv4.ipv4)
        req_udp = pkt.get_protocol(udp.udp)
        req = dhcp.dhcp.parser(pkt[3])
        req[0].options.option_list.remove(next(opt for opt in req[0].options.option_list if opt.tag == 53))
        req[0].options.option_list.insert(0, dhcp.option(tag=51, value='8640'))
        req[0].options.option_list.insert(0, dhcp.option(tag=53, value='05'.decode('hex')))

        ack_pkt = packet.Packet()
        ack_pkt.add_protocol(ethernet.ethernet(ethertype=req_eth.ethertype, dst=req_eth.src, src=self.hw_addr))
        ack_pkt.add_protocol(ipv4.ipv4(dst=req_ipv4.dst, src=self.dhcp_server, proto=req_ipv4.proto))
        ack_pkt.add_protocol(udp.udp(src_port=67,dst_port=68))
        ack_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=req_eth.src,
                                       siaddr=self.dhcp_server,
                                       boot_file=req[0].boot_file,
                                       yiaddr=self.ip_addr,
                                       xid=req[0].xid,
                                       options=req[0].options))
        self.logger.info("ASSEMBLED ACK: %s" % ack_pkt)
        return ack_pkt


    def assemble_offer(self, pkt):
        disc_eth = pkt.get_protocol(ethernet.ethernet)
        disc_ipv4 = pkt.get_protocol(ipv4.ipv4)
        disc_udp = pkt.get_protocol(udp.udp)
        disc = dhcp.dhcp.parser(pkt[3])
        disc[0].options.option_list.remove(next(opt for opt in disc[0].options.option_list if opt.tag == 55))
        disc[0].options.option_list.remove(next(opt for opt in disc[0].options.option_list if opt.tag == 53))
        disc[0].options.option_list.remove(next(opt for opt in disc[0].options.option_list if opt.tag == 12))
        disc[0].options.option_list.insert(0, dhcp.option(tag=1, value=self.bin_netmask))
        disc[0].options.option_list.insert(0, dhcp.option(tag=3, value=self.bin_server))
        disc[0].options.option_list.insert(0, dhcp.option(tag=6, value=self.bin_dns))
        disc[0].options.option_list.insert(0, dhcp.option(tag=12, value=self.hostname))
        disc[0].options.option_list.insert(0, dhcp.option(tag=53, value='02'.decode('hex')))
        disc[0].options.option_list.insert(0, dhcp.option(tag=54, value=self.bin_server))

        offer_pkt = packet.Packet()
        offer_pkt.add_protocol(ethernet.ethernet(ethertype=disc_eth.ethertype, dst=disc_eth.src, src=self.hw_addr))
        offer_pkt.add_protocol(ipv4.ipv4(dst=disc_ipv4.dst, src=self.dhcp_server, proto=disc_ipv4.proto))
        offer_pkt.add_protocol(udp.udp(src_port=67,dst_port=68))
        offer_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=disc_eth.src,
                                         siaddr=self.dhcp_server,
                                         boot_file=disc[0].boot_file,
                                         yiaddr=self.ip_addr,
                                         xid=disc[0].xid,
                                         options=disc[0].options))
        self.logger.info("ASSEMBLED OFFER: %s" % offer_pkt)
        return offer_pkt

    def get_state(self, pkt_dhcp):
        dhcp_state = ord([opt for opt in pkt_dhcp[0].options.option_list if opt.tag == 53][0].value)
        if dhcp_state == 1:
            state = 'DHCPDISCOVER'
        elif dhcp_state == 2:
            state = 'DHCPOFFER'
        elif dhcp_state == 3:
            state = 'DHCPREQUEST'
        elif dhcp_state == 5:
            state = 'DHCPACK'
        return state

    def _handle_dhcp(self, datapath, port, pkt):
        pkt_dhcp = dhcp.dhcp.parser(pkt[3])
        dhcp_state = self.get_state(pkt_dhcp)
        self.logger.info("NEW DHCP %s PACKET RECEIVED: %s" % (dhcp_state, pkt_dhcp))
        if dhcp_state == 'DHCPDISCOVER':
            self._send_packet(datapath, port, self.assemble_offer(pkt))
        elif dhcp_state == 'DHCPREQUEST':
            self._send_packet(datapath, port, self.assemble_ack(pkt))
        else:
            return

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
