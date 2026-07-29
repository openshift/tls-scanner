package k8s

func (c *Client) cacheProcListenInfo(pod PodInfo, entries map[int]ProcListenEntry, inodeComm map[uint64]string) {
	c.processCacheMutex.Lock()
	defer c.processCacheMutex.Unlock()

	podKey := podOwnershipKey(pod)
	if _, ok := c.podOwnedPorts[podKey]; !ok {
		c.podOwnedPorts[podKey] = make(map[int]bool)
	}

	for _, ip := range pod.IPs {
		if _, ok := c.procListenAddrMap[ip]; !ok {
			c.procListenAddrMap[ip] = make(map[int]string)
		}
		if _, ok := c.listenInfoMap[ip]; !ok {
			c.listenInfoMap[ip] = make(map[int]ListenInfo)
		}
		if _, ok := c.processNameMap[ip]; !ok {
			c.processNameMap[ip] = make(map[int]string)
		}
		for port, entry := range entries {
			if _, exists := c.procListenAddrMap[ip][port]; !exists {
				c.procListenAddrMap[ip][port] = entry.Addr
			}
			comm := inodeComm[entry.Inode]
			if comm == "" {
				continue
			}
			c.processNameMap[ip][port] = comm
			c.listenInfoMap[ip][port] = ListenInfo{
				Port:          port,
				ListenAddress: entry.Addr,
				ProcessName:   comm,
			}
			// Ownership is scoped to THIS pod only — never merged with other
			// pods, even ones sharing the same IP (see podOwnedPorts doc).
			c.podOwnedPorts[podKey][port] = true
		}
	}
}

// podOwnershipKey uniquely identifies a pod for ownership-scoping purposes.
// Deliberately independent of IP, since hostNetwork pods share the node's IP.
func podOwnershipKey(pod PodInfo) string {
	return pod.Namespace + "/" + pod.Name
}

// GetOwnedPorts returns the set of ports whose listening process was resolved
// specifically within pod's own PID namespace (i.e. genuinely running in one
// of the pod's own containers), as observed by a prior DiscoverPortsFromProc
// call for this exact pod.
//
// This is intentionally NOT an IP-based lookup: for hostNetwork pods, many
// unrelated pods on the same node report the same IP, so keying by IP alone
// would return ports resolved by other pods entirely (see issue #85).
//
// A nil return means /proc discovery never ran (or found nothing at all) for
// this pod, i.e. cacheProcListenInfo was never invoked. A non-nil, possibly
// empty, map means discovery ran successfully but resolved zero ports to a
// process in this pod's own PID namespace — a valid outcome (e.g. every
// listening socket's inode belongs to another container's namespace), and
// callers must still treat it as ground truth for filtering rather than
// falling back as if ownership data were unavailable.
func (c *Client) GetOwnedPorts(pod PodInfo) map[int]bool {
	c.processCacheMutex.Lock()
	defer c.processCacheMutex.Unlock()

	owned, ok := c.podOwnedPorts[podOwnershipKey(pod)]
	if !ok {
		return nil
	}
	copied := make(map[int]bool, len(owned))
	for port := range owned {
		copied[port] = true
	}
	return copied
}

func (c *Client) IsLocalhostOnly(ip string, port int) (bool, string) {
	c.processCacheMutex.Lock()
	defer c.processCacheMutex.Unlock()

	if addrMap, ok := c.procListenAddrMap[ip]; ok {
		if addr, ok := addrMap[port]; ok {
			if isLocalhostAddr(addr) {
				return true, addr
			}
		}
	}

	return false, ""
}

// isLocalhostAddr reports whether addr is a loopback address.
func isLocalhostAddr(addr string) bool {
	return addr == "127.0.0.1" || addr == "::1" || addr == "localhost"
}

func (c *Client) GetListenInfo(ip string, port int) (ListenInfo, bool) {
	c.processCacheMutex.Lock()
	defer c.processCacheMutex.Unlock()

	if portMap, ok := c.listenInfoMap[ip]; ok {
		if info, ok := portMap[port]; ok {
			return info, true
		}
	}
	return ListenInfo{}, false
}

// TODO(refactor): remove — redundant with GetListenInfo().ProcessName
func (c *Client) GetProcessName(ip string, port int) (string, bool) {
	c.processCacheMutex.Lock()
	defer c.processCacheMutex.Unlock()

	if portMap, ok := c.processNameMap[ip]; ok {
		if name, ok := portMap[port]; ok {
			return name, true
		}
	}
	return "", false
}
