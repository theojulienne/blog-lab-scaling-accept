#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import sleep
import ctypes as ct
import socket
import json, sys

bpf_source = '''
#include <net/sock.h>
#include <net/inet_sock.h>

BPF_PERF_OUTPUT(events);

static inline
struct net *safe_sock_net(const struct sock *sk)
{
#ifdef CONFIG_NET_NS
    struct net *ret;
    // was: read_pnet(&sk->sk_net)->net
    bpf_probe_read(&ret, sizeof(ret), (void *)&(sk->sk_net.net));
	return ret;
#else
    return &init_net;
#endif
}

/* generic handler */
static inline void handle_sk_potential_overflow(struct pt_regs *ctx, int syn_recv, const struct sock *sk)
{
    struct inet_sock *inet = (struct inet_sock *)sk;
    
    struct {
        u64 ts;
        u32 net_ns_id;
        u32 listen_addr;
        u16 listen_port;

        u16 syn_recv;
        u32 sk_ack_backlog;
        u32 sk_max_ack_backlog;
    } event_data = {0};
    
    bpf_probe_read(&event_data.sk_ack_backlog, sizeof(event_data.sk_ack_backlog), (void *)&sk->sk_ack_backlog);
    bpf_probe_read(&event_data.sk_max_ack_backlog, sizeof(event_data.sk_max_ack_backlog), (void *)&sk->sk_max_ack_backlog);

    /* match the conditional: sk_acceptq_is_full(sk) */
    if (event_data.sk_ack_backlog > event_data.sk_max_ack_backlog) {
        struct net *net = safe_sock_net(sk);
        bpf_probe_read(&event_data.net_ns_id, sizeof(event_data.net_ns_id), (void *)&net->ns.inum);

        /* fill out the rest of the information in the event */
        event_data.ts = bpf_ktime_get_ns();
        bpf_probe_read(&event_data.listen_addr, sizeof(event_data.listen_addr), (void *)&sk->sk_rcv_saddr);
        bpf_probe_read(&event_data.listen_port, sizeof(event_data.listen_port), (void *)&inet->inet_sport);
        event_data.syn_recv = syn_recv;

        events.perf_submit(ctx, &event_data, sizeof(event_data));
    }
}

/* when a SYN arrives */
struct tcp_request_sock_ops;
void kprobe__tcp_conn_request(struct pt_regs *ctx, struct request_sock_ops *rsk_ops,
		     const struct tcp_request_sock_ops *af_ops,
             const struct sock *sk, struct sk_buff *skb)
{
    handle_sk_potential_overflow(ctx, 0, sk);
}

/* when an ACK arrives for a SYN_RECV socket */
void kprobe__tcp_v4_syn_recv_sock(struct pt_regs *ctx, const struct sock *sk)
{
    handle_sk_potential_overflow(ctx, 1, sk);
}
'''

bpf = BPF(text=bpf_source)

class Data(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("net_ns_id", ct.c_uint),
        ("listen_addr", ct.c_byte * 4),
        ("listen_port", ct.c_ushort),

        ("syn_recv", ct.c_ushort),
        ("sk_ack_backlog", ct.c_uint),
        ("sk_max_ack_backlog", ct.c_uint),
    ]

use_json = ('--json' in sys.argv)

if not use_json:
    print("%-20s %6s %-20s %-10s %-20s %3s %6s %6s" % ('CONTAINER/HOST', 'PID', 'PROCESS', 'NETNSID', 'BIND', 'PKT', 'BL', 'MAX'))

def log_one_row(data):
    process = {}
    if len(data['processes']) > 0:
        process = data['processes'][0]
    print("%-20s %6s %-20s %-10s %-20s %3s %6d %6d" % (
        process.get('uts_host', '')[:20],
        process.get('pid', ''),
        process.get('cmdline', '')[:20],
        data['net_ns_id'],
        data['bind']['ip'] + ':' + str(data['bind']['port']),

        data['pkt_type'],
        data['sk_ack_backlog'],
        data['sk_max_ack_backlog'],
    ))

from trace_utils import *

def cb(cpu, data, size):
    assert size >= ct.sizeof(Data)
    event = ct.cast(data, ct.POINTER(Data)).contents

    data = {
        'cpu': cpu,
        'ts': float(event.ts) / 1000000,
        'bind': {
            'ip': socket.inet_ntoa(event.listen_addr),
            'port': socket.htons(event.listen_port),
        },
        'processes': [],
        'net_ns_id': event.net_ns_id,

        'sk_ack_backlog': event.sk_ack_backlog,
        'sk_max_ack_backlog': event.sk_max_ack_backlog,
    }

    if event.syn_recv:
        data['pkt_type'] = 'ACK'
    else:
        data['pkt_type'] = 'SYN'
    
    # we don't know the PID because this is on an incoming network event, so look it up
    pids = list(pids_for_sock_in_ns(event.listen_addr, event.listen_port, event.net_ns_id))
    for pid in pids:
        data['processes'].append(process_data_for_pid(pid))
    
    if use_json:
        print(json.dumps(data))
    else:
        log_one_row(data)

bpf["events"].open_perf_buffer(cb)

while 1:
    try:
        bpf.kprobe_poll()
    except KeyboardInterrupt:
        exit()
