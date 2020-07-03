import glob, os, re, subprocess, socket

def inode_for_pid_sock(pid, addr, port):
    """
    Given a pid that is inside a network namespace, and the address/port of a LISTEN socket,
    find the inode of the socket regardless of which pid in the ns it's attached to.
    """

    expected_laddr = '%02X%02X%02X%02X:%04X' % (addr[3], addr[2], addr[1], addr[0], socket.htons(port))
    for line in open('/proc/{}/net/tcp'.format(pid), 'r').readlines():
        parts = re.split(r'\s+', line.strip())
        local_addr = parts[1]
        remote_addr = parts[2]
        if remote_addr != '00000000:0000': continue # not a listen socket
        if local_addr == expected_laddr:
            return int(parts[9])

def pids_for_sock_in_ns(addr, port, net_ns_id):
    """
    Finds the running PIDs in the given network namespace that hold FDs referencing a LISTEN
    socket with the given address and port.
    """

    netns_files = filter(lambda x: os.stat(x).st_ino == net_ns_id, glob.glob('/proc/*/ns/net'))
    inode = None
    for nsf in netns_files:
        _,_,pid,_,_ = nsf.split('/')
        try:
            pid = int(pid)
        except ValueError:
            continue

        # this pid is in the namespace, now look at the tcp connections in the namespace
        if inode is None:
            inode = inode_for_pid_sock(pid, addr, port)
            if inode is None:
                return
        
        if inode is not None:
            # we have our target inode, so check over the fds in this pid to see if they match
            for sock_fd in os.listdir('/proc/{}/fd'.format(pid)):
                try:
                    if os.stat('/proc/{}/fd/{}'.format(pid, sock_fd)).st_ino == inode:
                        yield pid
                except OSError:
                    continue

def uts_host_for_pid(pid):
    """
    Find the hostname in the UTS namespace of the given pid, which mostly maps to the 
    container name (when in a container) or system fqdn (otherwise).
    """
    
    try:
        return subprocess.check_output(['nsenter', '-u', '-t', str(pid), 'hostname'], stderr=subprocess.STDOUT).strip()
    except subprocess.CalledProcessError:
        return '[unknown]'

def process_data_for_pid(pid):
    try:
        return {
            'pid': pid,
            'cmdline': ' '.join(open('/proc/{}/cmdline'.format(pid), 'r').read().split('\x00')),
            'uts_host': uts_host_for_pid(pid),
        }
    except OSError:
        return {}