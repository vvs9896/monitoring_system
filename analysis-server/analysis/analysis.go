package analysis

func (e *Message) Check() string {
	if e.ParentComm == "/usr/bin/containerd-shim-runc-v2" {
		return "Critical"
	}

	m := map[string]int{
		"mknod":         1,
		"/usr/bin/gdb":  1,
		"/usr/bin/kmod": 1,
		"mount":         1,
		"curl":          1,
		"/usr/bin/curl": 1,
	}

	if e.ParentComm == "/usr/bin/bash" {
		if key, ok := m[e.Comm]
	}
}
