#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import sleep
import ctypes as ct
import sys

bpf_source = '''
#define KBUILD_MODNAME ""

#include <net/sock.h>
#include <net/inet_connection_sock.h>

BPF_PERF_OUTPUT(events);

BPF_HASH(requested_backlogs, u32, u64);

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

TRACEPOINT_PROBE(syscalls, sys_enter_listen) {
    u32 pid = bpf_get_current_pid_tgid();

    u64 backlog = args->backlog;
    requested_backlogs.update(&pid, &backlog);

    return 0;
}

void kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock, int backlog)
{
    struct sock *sk = sock->sk;
    struct inet_sock *inet = (struct inet_sock *)sk;

    struct {
        u64 ts;
        u32 pid;
        u32 net_ns_id;
        u32 listen_addr;
        u16 listen_port;

        u64 requested_backlog;
        u64 netns_somaxconn;
        u64 actual_backlog;
    } event_data = {0};

    event_data.pid = bpf_get_current_pid_tgid();

    u64 *requested_backlog;
	requested_backlog = requested_backlogs.lookup(&event_data.pid);
	if (requested_backlog == NULL) {
		return;
	}

    requested_backlogs.delete(&event_data.pid);

    /* fill out the rest of the information in the event */
    event_data.ts = bpf_ktime_get_ns();
    event_data.requested_backlog = *requested_backlog;
    event_data.actual_backlog = backlog;

    bpf_probe_read(&event_data.listen_addr, sizeof(event_data.listen_addr), (void *)&sk->sk_rcv_saddr);
    bpf_probe_read(&event_data.listen_port, sizeof(event_data.listen_port), (void *)&inet->inet_sport);

    bpf_probe_read(&event_data.netns_somaxconn, sizeof(event_data.netns_somaxconn), (void *)&(safe_sock_net(sk)->core.sysctl_somaxconn));

    struct net *net = safe_sock_net(sk);
    bpf_probe_read(&event_data.net_ns_id, sizeof(event_data.net_ns_id), (void *)&net->ns.inum);

    events.perf_submit(ctx, &event_data, sizeof(event_data));
}
'''

bpf = BPF(text=bpf_source)

class Data(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("net_ns_id", ct.c_uint),
        ("listen_addr", ct.c_byte * 4),
        ("listen_port", ct.c_ushort),

        ("requested_backlog", ct.c_ulonglong),
        ("netns_somaxconn", ct.c_ulonglong),
        ("actual_backlog", ct.c_ulonglong),
    ]

use_json = ('--json' in sys.argv)

if not use_json:
    print("%-20s %6s %-20s %-10s %-20s %6s %6s %6s" % ('CONTAINER/HOST', 'PID', 'PROCESS', 'NETNSID', 'BIND', 'REQ', 'MAX', 'ACTUAL'))

def log_one_row(data):
    process = {}
    if len(data['processes']) > 0:
        process = data['processes'][0]
    status = ''
    if data['backlog_limited']:
        status = 'LIMITED'
    print("%-20s %6s %-20s %-10s %-20s %6s %6s %6s %s" % (
        process.get('uts_host', '')[:20],
        process.get('pid', ''),
        process.get('cmdline', '')[:20],
        data['net_ns_id'],
        data['bind']['ip'] + ':' + str(data['bind']['port']),
        
        data['requested_backlog'],
        data['netns_somaxconn'],
        data['actual_backlog'],
        status,
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

        'requested_backlog': event.requested_backlog,
        'netns_somaxconn': event.netns_somaxconn,
        'actual_backlog': event.actual_backlog,
        'backlog_limited': False,
    }

    # we know the PID because we're in a syscall that immediately comes from our proc
    data['processes'].append(process_data_for_pid(event.pid))

    if event.actual_backlog < event.requested_backlog:
        data['backlog_limited'] = True
    
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
