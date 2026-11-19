import logging
import os
import time
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    DEAD_DISPATCHER, set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp

# ---------------- configuration ----------------
STATS_INTERVAL = 5          # seconds between reports
SYN_RATE_MAX = 20           # max new TCP connections/sec per host (tune after baselining)
BLOCK_DURATION = 60         # seconds a host stays blocked
BLOCK_PRIORITY = 100        # higher than all forwarding flows (10, 5, 1)
WHITELIST = {"10.0.0.1"}    # servers that must never be blocked
LOG_FILE = "logs/dhbs.log"


class DHBSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}                 # {dpid: {mac: port}}
        self.datapaths = {}                   # {dpid: datapath}
        self.syn_count = defaultdict(int)     # src_ip -> new TCP connections this interval
        self.blocked = {}                     # ip -> {"time", "expires", "reason"}
        self._setup_logging()
        self.monitor_thread = hub.spawn(self._monitor_loop)

    # ---------- logging ----------
    def _setup_logging(self):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s",
                                "%Y-%m-%d %H:%M:%S")
        fh = logging.FileHandler(LOG_FILE)
        fh.setFormatter(fmt)
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
        self.logger.propagate = False         # avoid duplicate console lines

    # ---------- switch connection handling ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)
        self.logger.info("Switch %s connected", dp.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    def add_flow(self, dp, priority, match, actions, idle_timeout=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                instructions=inst, idle_timeout=idle_timeout)
        dp.send_msg(mod)

    # ---------- packet handling ----------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst, src = eth.dst, eth.src
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # Count a new TCP connection = a SYN without ACK
        if ip_pkt and tcp_pkt:
            if (tcp_pkt.bits & tcp.TCP_SYN) and not (tcp_pkt.bits & tcp.TCP_ACK):
                self.syn_count[ip_pkt.src] += 1

        # Learn MAC -> port
        table = self.mac_to_port.setdefault(dp.id, {})
        table[src] = in_port
        out_port = table.get(dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow so later packets skip the controller
        if out_port != ofp.OFPP_FLOOD:
            if ip_pkt and tcp_pkt:
                # one flow per TCP connection -> every new connection reaches the controller
                match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=6,
                                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                                        tcp_src=tcp_pkt.src_port,
                                        tcp_dst=tcp_pkt.dst_port)
                self.add_flow(dp, 10, match, actions, idle_timeout=10)
            elif ip_pkt:
                # ICMP / UDP / other IP: one flow per src/dst/protocol
                match = parser.OFPMatch(in_port=in_port, eth_type=0x0800,
                                        ip_proto=ip_pkt.proto,
                                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
                self.add_flow(dp, 5, match, actions, idle_timeout=10)
            elif eth.ethertype == ether_types.ETH_TYPE_ARP:
                match = parser.OFPMatch(in_port=in_port, eth_type=0x0806,
                                        eth_dst=dst, eth_src=src)
                self.add_flow(dp, 1, match, actions, idle_timeout=10)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

    # ---------- monitoring ----------
    def _monitor_loop(self):
        while True:
            hub.sleep(STATS_INTERVAL)
            counts = self.syn_count
            self.syn_count = defaultdict(int)     # reset for the next interval
            self._report_connection_rates(counts)
            self._detect(counts)
            self._expire_blocks()
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))

    def _report_connection_rates(self, counts):
        for ip in sorted(counts):
            c = counts[ip]
            self.logger.info("[RATE] %s: %d new TCP connections in %ds (%.1f/s)",
                             ip, c, STATS_INTERVAL, c / STATS_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        pkts = defaultdict(int)
        byts = defaultdict(int)
        flows = defaultdict(int)
        for stat in ev.msg.body:
            src_ip = stat.match.get('ipv4_src')
            if src_ip is None:
                continue
            pkts[src_ip] += stat.packet_count
            byts[src_ip] += stat.byte_count
            flows[src_ip] += 1
        for ip in sorted(pkts):
            self.logger.info("[FLOWSTATS] %s: %d active flows, %d packets, %d bytes",
                             ip, flows[ip], pkts[ip], byts[ip])

    # ---------- detection ----------
    def _detect(self, counts):
        for ip, c in counts.items():
            if ip in WHITELIST or ip in self.blocked:
                continue
            rate = c / STATS_INTERVAL
            if rate > SYN_RATE_MAX:
                reason = "syn_rate=%.1f/s limit=%d/s" % (rate, SYN_RATE_MAX)
                self.logger.warning("DETECTED %s %s", ip, reason)
                self._block(ip, reason)

    # ---------- blocklist and drop rules ----------
    def _block(self, ip, reason):
        for dp in list(self.datapaths.values()):
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            # empty instruction list = drop
            mod = parser.OFPFlowMod(datapath=dp, priority=BLOCK_PRIORITY,
                                    match=match, instructions=[],
                                    hard_timeout=BLOCK_DURATION)
            dp.send_msg(mod)
        now = time.time()
        self.blocked[ip] = {"time": now, "expires": now + BLOCK_DURATION,
                            "reason": reason}
        self.logger.warning("BLOCKED %s for %ds (%s)", ip, BLOCK_DURATION, reason)

    def _unblock(self, ip):
        for dp in list(self.datapaths.values()):
            ofp = dp.ofproto
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            mod = parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                    match=match)
            dp.send_msg(mod)
        self.blocked.pop(ip, None)
        self.logger.info("UNBLOCKED %s (block duration expired)", ip)

    def _expire_blocks(self):
        now = time.time()
        for ip in [i for i, b in self.blocked.items() if now >= b["expires"]]:
            self._unblock(ip)
